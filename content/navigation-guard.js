/**
 * Virus Detector — Navigation Guard (Layer 0 主动拦截)
 *
 * 在所有页面 document_start 阶段运行（MAIN world），
 * 在页面 JS 执行之前 hook window.location 和 window.open，
 * 拦截向危险文件类型（压缩包/可执行文件）的导航跳转。
 *
 * 设计目的：
 *   1. 拦截 JS 自动下载（location.href='xxx.zip'）
 *   2. 对抗 IDM 等下载器绕过（在浏览器下载 API 之前拦截）
 *   3. 零延迟：不需要等待 Content Script 采集和评分
 *
 * 性能：无 DOM 操作，无网络请求，每个导航检查 < 0.01ms
 *
 * @module navigation-guard
 */

(function () {
  'use strict';

  var AUTH_HOST_PATTERN = /^(login|logon|signin|auth|oauth|account|accounts|identity|id|sso|secure|security|verify|verification|console)\./i;
  var AUTH_PATH_PATTERN = /(?:^|[\/?#&=._-])(login|logon|logout|signin|sign-in|signout|sign-out|auth|oauth|authorize|sso|saml|2fa|mfa|otp|totp|challenge|verify|verification|webauthn|passkey|password|credential|credentials|session|callback|consent|recover|recovery|reset|device)(?:$|[\/?#&=._-])/i;
  var DISABLE_GUARD_EVENT = 'virus-detector:disable-navigation-guard';

  function isSensitiveAuthenticationUrl(url) {
    try {
      var parsed = new URL(url, window.location.href);
      if (AUTH_HOST_PATTERN.test(parsed.hostname)) return true;
      return AUTH_PATH_PATTERN.test(parsed.pathname + parsed.search + parsed.hash);
    } catch (e) {
      return false;
    }
  }

  // 登录、2FA 和控制台页面依赖原生导航对象，不在 MAIN world 中做任何 hook。
  if (isSensitiveAuthenticationUrl(window.location.href)) return;

  // ==================== 危险扩展名列表 ====================
  // 与 utils/constants.js ARCHIVE_EXTENSIONS + EXECUTABLE_EXTENSIONS 保持同步

  var ARCHIVE_EXTS = [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
    '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
    '.tar.bz2', '.tar.xz', '.zst', '.img'
  ];

  var EXECUTABLE_EXTS = [
    '.exe', '.msi', '.apk', '.dmg', '.pkg', '.appx', '.deb', '.rpm',
    '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
    '.bin', '.run', '.sh'
  ];

  /**
   * 检查 URL 是否指向危险文件类型
   * @param {string} url
   * @returns {boolean}
   */
  function isDangerousUrl(url) {
    if (!url || typeof url !== 'string') return false;

    // 跳过非 http(s) 协议
    var lower = url.toLowerCase().trim();
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      // 也检查相对路径（如 ./file.zip 或 /path/file.zip）
      if (lower.startsWith('javascript:') || lower.startsWith('data:') ||
          lower.startsWith('mailto:') || lower.startsWith('#') ||
          lower.startsWith('blob:') || lower.startsWith('file://')) {
        return false;
      }
    }

    // 提取路径部分（去掉 query 和 hash）
    var pathOnly = lower.split('?')[0].split('#')[0];

    // 检查所有危险扩展名
    for (var i = 0; i < ARCHIVE_EXTS.length; i++) {
      if (pathOnly.endsWith(ARCHIVE_EXTS[i])) return true;
    }
    for (var j = 0; j < EXECUTABLE_EXTS.length; j++) {
      if (pathOnly.endsWith(EXECUTABLE_EXTS[j])) return true;
    }

    return false;
  }

  /**
   * 对危险 URL 弹窗确认
   * @param {string} url
   * @param {string} source - 'location' | 'window.open'
   * @returns {boolean} true = 用户确认继续, false = 用户取消
   */
  function warnDangerousNavigation(url, source) {
    var fileName = '';
    try {
      var pathname = url.split('?')[0].split('#')[0];
      var parts = pathname.split('/');
      fileName = parts[parts.length - 1] || url;
    } catch (e) {
      fileName = url;
    }

    var message =
      '⚠️ Virus Detector 安全警告\n\n' +
      '页面试图导航到一个危险文件：\n\n' +
      '文件: ' + fileName + '\n' +
      '来源: ' + (source === 'location' ? '页面跳转 (location)' : '弹窗 (window.open)') + '\n\n' +
      '这可能是恶意下载。\n\n' +
      '点击「确定」继续前往（不推荐）\n' +
      '点击「取消」阻止此操作';

    // confirm() 是阻塞式的，确保在导航/下载发生之前用户看到
    return confirm(message);
  }

  // ==================== 1. Hook window.location 的 setter ====================

  // 保存原始的 location 对象引用
  var _origLocation = window.location;
  var _locationProxy = null;
  var _origLocationSetter = null;
  var _patchedLocationSetter = null;

  try {
    // 方法 A：使用 __proto__ 重写 location 对象的 href 属性
    // 这在大多数浏览器中有效

    // 创建代理对象拦截对 location 的赋值
    var _LocationProxy = function () {};

    // 拦截 location.href = 'xxx' 和 location = 'xxx'
    // 注意：直接重写 window.location 在 strict mode 下会抛异常
    // 因此我们使用 __defineSetter__ 方式

    if (window.__lookupSetter__ && window.__defineSetter__) {
      // 保存原始 setter
      _origLocationSetter = window.__lookupSetter__('location');
      if (_origLocationSetter) {
        _patchedLocationSetter = function (val) {
          if (isDangerousUrl(String(val))) {
            if (warnDangerousNavigation(String(val), 'location')) {
              _origLocationSetter.call(window, val);
            }
            // 用户取消 → 阻止跳转（不调用原始 setter）
          } else {
            _origLocationSetter.call(window, val);
          }
        };
        window.__defineSetter__('location', _patchedLocationSetter);
      }
    }
  } catch (e) {
    // __defineSetter__ 在某些环境下不可用 → 静默降级
    // injectBlockerFunc（Layer 2）会覆盖此场景
  }

  // ==================== 2. Hook window.open ====================

  var _origOpen = window.open;

  var _patchedOpen = function (url, target, features) {
    // 如果 URL 是危险文件 → 弹窗确认
    if (url && isDangerousUrl(String(url))) {
      if (!warnDangerousNavigation(String(url), 'window.open')) {
        // 用户取消 → 返回 null（阻止打开）
        return null;
      }
    }

    // 正常调用
    if (_origOpen) {
      return _origOpen.call(window, url, target, features);
    }
    return null;
  };
  window.open = _patchedOpen;

  // 保留原始 open 的引用（防止其他脚本覆盖后丢失）
  window.open.__virusDetector_original = _origOpen;

  // ==================== 3. 支持认证页动态卸载 ====================

  function disableNavigationGuard() {
    try {
      if (window.open === _patchedOpen) window.open = _origOpen;
      if (_origLocationSetter && _patchedLocationSetter && window.__lookupSetter__ &&
          window.__lookupSetter__('location') === _patchedLocationSetter) {
        window.__defineSetter__('location', _origLocationSetter);
      }
    } catch (e) { /* 恢复失败时保持静默 */ }

    document.removeEventListener(DISABLE_GUARD_EVENT, disableNavigationGuard);
    delete window.__virusDetectorNavGuard;
  }

  document.addEventListener(DISABLE_GUARD_EVENT, disableNavigationGuard);

  // ==================== 4. 标记已注入 ====================

  window.__virusDetectorNavGuard = true;

})();
