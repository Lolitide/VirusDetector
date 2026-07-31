/**
 * Virus Detector — Content Script (内容脚本)
 *
 * 注入到每个页面中，负责采集页面数据供评分引擎使用。
 * 在 document_idle 阶段运行，分两次空闲采集（600ms + 3500ms）以捕获懒加载内容。
 * 二次扫描跳过 HEAD 死链验证，避免重复网络请求和主线程压力。
 *
 * @module content-script
 *
 * 职责：
 *   1. 采集链接分析数据 (collectLinkMetrics) — 规则四 + 规则二 Phase A 数据源
 *      - 同页链接（完整 URL 精确匹配）
 *      - 死链检测（HEAD 请求验证，上限 5 个，二次扫描跳过）
 *      - 重复链接追踪（>=4 个元素指向同一链接 → 规则 A-③）
 *      - 外链下载分析（下载按钮文本 + 文件扩展名）
 *      - 压缩包链接专项采集（同域+跨域全覆盖，为 Rule 2 Phase A 提供主动扫描数据）
 *   2. 采集页面度量 (collectPageMetrics) — 规则五数据源
 *      - DOM节点数、外部资源去重总数、框架标记（HTML全文+window全局变量双重检测）、文本长度
 *   3. 扫描 ICP 备案号 (findIcpStrings) — 规则三数据源
 *      - 6 层递进扫描：footer → ICP 元素 → 底部 30% 区域 → <a> 链接 → fixed 元素 → TreeWalker
 *   4. 响应来自 Service Worker 的 REQUEST_PAGE_TEXT 重采请求（仅返回派生文本指标，不传正文）
 */

(async function () {
  'use strict';

  // ==================== 内联常量（同步自 utils/constants.js，content_scripts 不支持 ES module 导入） ====================

  // 推广/产品页面关键词 → constants.js PROMO_KEYWORDS
  const PROMO_KEYWORDS = [
    '下载', '产品', '软件', '安装', '免费', '官方', '应用', '工具',
    '版本', '最新', '破解', '注册', '激活', '绿色', '汉化', '插件',
    '专业版', '正式版', '购买', '激活码', '注册机', '补丁', '试用',
    '客户端', '安装包', '精简版', '去广告', '便携版',
    'download', 'product', 'software', 'install', 'free', 'official',
    'app', 'tool', 'version', 'latest', 'crack', 'register', 'activate',
    'pro', 'premium', 'setup', 'license', 'keygen', 'patch', 'trial',
    'portable', 'release', 'full version'
  ];

  // 下载按钮/链接关键词 → constants.js DOWNLOAD_BUTTON_KEYWORDS + DOWNLOAD_LINK_KEYWORDS 合并
  const DOWNLOAD_BUTTON_KW = [
    '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
    '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
    'download now', 'free download', 'download free',
    '立即安装', '一键安装', '安装包', 'setup', 'install', 'get started'
  ];

  // 全部文件扩展名（压缩包 + 可执行文件）→ constants.js FILE_EXTENSIONS
  const FILE_EXTENSIONS = [
    '.exe', '.msi', '.dmg', '.apk', '.appx', '.deb', '.rpm',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
    '.iso', '.cab', '.arj', '.lzh', '.z', '.zst',
    '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
    '.bin', '.run', '.sh', '.pkg'
  ];

  // 压缩包扩展名 → constants.js ARCHIVE_EXTENSIONS
  const ARCHIVE_EXTENSIONS_ALL = [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
    '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
    '.tar.bz2', '.tar.xz', '.gz2', '.zst'
  ];

  const AUTH_URL_PATTERN = /(?:^|[\/?#&=._-])(login|logon|logout|signin|sign-in|signout|sign-out|auth|oauth|authorize|sso|saml|2fa|mfa|otp|totp|challenge|verify|verification|webauthn|passkey|password|credential|credentials|session|callback|consent|recover|recovery|reset|device)(?:$|[\/?#&=._-])/i;
  const AUTH_HOST_PATTERN = /^(login|logon|signin|auth|oauth|account|accounts|identity|id|sso|secure|security|verify|verification|console)\./i;
  const AUTH_INTERACTION_PATTERN = /(login|logon|sign\s*in|authorize|verification|verify|passkey|webauthn|2fa|mfa|otp|登录|验证码|身份验证|双重验证|两步验证)/i;
  const DISABLE_GUARD_EVENT = 'virus-detector:disable-navigation-guard';
  const AUTH_CONTROL_SELECTOR = [
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="new-password"]',
    'input[autocomplete="one-time-code"]',
    'input[name*="otp"]',
    'input[id*="otp"]',
    'input[name*="verification"]',
    'input[id*="verification"]'
  ].join(',');

  function isSensitiveAuthenticationUrl(url) {
    try {
      const parsed = new URL(url, window.location.href);
      if (AUTH_HOST_PATTERN.test(parsed.hostname)) return true;
      return AUTH_URL_PATTERN.test(parsed.pathname + parsed.search + parsed.hash);
    } catch (e) {
      return false;
    }
  }

  function isAuthenticationPage() {
    if (isSensitiveAuthenticationUrl(window.location.href)) return true;

    try {
      return document.querySelector(AUTH_CONTROL_SELECTOR) !== null;
    } catch (e) {
      return false;
    }
  }

  async function isCurrentPageWhitelisted() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CHECK_WHITELIST',
        payload: { url: window.location.href }
      });
      return response?.isWhitelisted === true;
    } catch (e) {
      return false;
    }
  }

  let _watchingAuthenticationInteraction = false;
  let _pageInterferenceDisabled = false;

  function disablePageNavigationGuard() {
    if (_pageInterferenceDisabled) return;
    _pageInterferenceDisabled = true;

    try {
      document.dispatchEvent(new CustomEvent(DISABLE_GUARD_EVENT));
    } catch (e) { /* ignore */ }

    chrome.runtime.sendMessage({
      type: 'AUTH_INTERACTION_DETECTED',
      payload: { url: window.location.href }
    }).catch(function() {});

    if (_watchingAuthenticationInteraction) {
      document.removeEventListener('click', handleAuthenticationInteraction, true);
      document.removeEventListener('focusin', handleAuthenticationInteraction, true);
      _watchingAuthenticationInteraction = false;
    }
  }

  function handleAuthenticationInteraction(event) {
    if (!event.target || typeof event.target.closest !== 'function') return;
    const control = event.target.closest('a, button, input, form, [role="button"]');
    if (!control) return;

    const inputType = (control.getAttribute('type') || '').toLowerCase();
    const autocomplete = (control.getAttribute('autocomplete') || '').toLowerCase();
    const identity = [
      control.getAttribute('href'), control.getAttribute('action'), control.id,
      control.getAttribute('name'), control.getAttribute('aria-label'),
      control.textContent
    ].filter(Boolean).join(' ');

    if (inputType === 'password' || autocomplete.includes('password') ||
        autocomplete.includes('one-time-code') || AUTH_INTERACTION_PATTERN.test(identity)) {
      disablePageNavigationGuard();
    }
  }

  function watchForAuthenticationInteraction() {
    if (_watchingAuthenticationInteraction) return;
    document.addEventListener('click', handleAuthenticationInteraction, true);
    document.addEventListener('focusin', handleAuthenticationInteraction, true);
    _watchingAuthenticationInteraction = true;
  }

  async function shouldSkipPageAnalysis() {
    const whitelisted = await isCurrentPageWhitelisted();
    if (whitelisted) disablePageNavigationGuard();
    return whitelisted;
  }

  // ==================== 规则四：链接分析数据采集 ====================

  /**
   * 异步采集链接分析指标
   * - 同页链接（完全一致URL）
   * - 死链（仅包括指向不存在子页面的链接）
   * - 重复链接（≥4个元素指向同一链接）
   * - 外链下载分析
   */
  async function collectLinkMetrics(options) {
    options = options || {};
    var checkDeadLinks = options.checkDeadLinks !== false;
    var currentUrl = window.location.href;
    var currentOrigin = window.location.origin;
    var currentHost = window.location.hostname;

    var links = document.querySelectorAll('a[href]');
    var samePageLinks = 0;
    var deadLinks = 0;
    var deadLinkSamples = [];
    var externalDownloadLinks = [];

    // 用于规则四A-③：跟踪链接被多少不同元素指向
    var linkElementMap = new Map();  // href (normalized) → Set of element signatures

    // 使用文件顶层内联常量，与 utils/constants.js 保持同步

    // 收集待检测死链的候选项（同域名的不同路径链接）
    var deadLinkCandidates = [];

    // 辅助函数：检查元素是否在导航/页头/页脚区域（这些区域的同页链接是正常行为）
    function isInNavigationZone(el) {
      return el.closest('nav, header, footer, [role="navigation"]') !== null;
    }

    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var href = (link.getAttribute('href') || '').trim();
      if (!href) continue;
      var lowerHref = href.toLowerCase();

      // 跳过 javascript: 和纯锚点链接（不计入任何检测）
      if (/^javascript\s*:/i.test(href) || /^#?$/.test(href) || /^#\d*$/.test(href)) {
        continue;
      }

      // ① 同页链接：仅当链接完整URL与当前页URL完全一致、且不在导航区域时计入
      try {
        var resolved = new URL(href, window.location.href);
        var resolvedHref = resolved.href;

        // 严格比对：完整URL完全一致 + 排除导航/页头/页脚
        if (resolvedHref === currentUrl) {
          if (!isInNavigationZone(link)) {
            samePageLinks++;
          }
        } else if (resolved.hostname === currentHost && !isSensitiveAuthenticationUrl(resolved.href)) {
          // 同域名但不同路径 → 可能是死链候选
          deadLinkCandidates.push({ href: resolvedHref, text: (link.textContent || '').trim().substring(0, 50), element: link });
        }

        // 规则四A-③：跟踪有多少不同元素指向同一个链接
        var normalizedHref = resolvedHref.replace(/#.*$/, ''); // 去除hash后归一化
        if (!linkElementMap.has(normalizedHref)) {
          linkElementMap.set(normalizedHref, new Set());
        }
        // 使用元素标签+文本前30字符作为元素签名去重
        var elemSig = link.tagName + '|' + (link.textContent || '').trim().substring(0, 30);
        linkElementMap.get(normalizedHref).add(elemSig);
      } catch (e) {
        // 无法解析的URL忽略（不包括hash/javascript，已在上面过滤）
      }

      // 外链分析（同之前逻辑）
      try {
        var resolved2 = new URL(href, window.location.href);
        if (resolved2.hostname && resolved2.hostname !== currentHost) {
          var linkText = (link.textContent || '').toLowerCase();
          var parentText = (link.parentElement ? link.parentElement.textContent : '').toLowerCase();
          var ariaLabel = (link.getAttribute('aria-label') || '').toLowerCase();
          var className = (link.className || '').toLowerCase();
          var parentClass = (link.parentElement ? link.parentElement.className : '').toLowerCase();
          var combined = [linkText, parentText, ariaLabel, className, parentClass].join(' ');

          var hasDownloadText = DOWNLOAD_BUTTON_KW.some(function(kw) { return combined.includes(kw); });
          var isFileLink = FILE_EXTENSIONS.some(function(ext) { return lowerHref.endsWith(ext); });
          var isArchive = ARCHIVE_EXTENSIONS_ALL.some(function(ext) { return lowerHref.endsWith(ext); });

          if (hasDownloadText || isFileLink) {
            externalDownloadLinks.push({
              href: href.substring(0, 200),
              text: (link.textContent || '').trim().substring(0, 80),
              hasDownloadText: hasDownloadText, isFileLink: isFileLink, isArchive: isArchive
            });
          }
        }
      } catch (e) {}
    }

    // ② 死链检测：对同域名不同路径的链接进行HEAD请求验证（限5个）
    if (checkDeadLinks && deadLinkCandidates.length > 0) {
      // 去重（按href）
      var uniqueCandidates = [];
      var seenHrefs = new Set();
      for (var c = 0; c < deadLinkCandidates.length; c++) {
        var chref = deadLinkCandidates[c].href;
        if (!seenHrefs.has(chref)) {
          seenHrefs.add(chref);
          uniqueCandidates.push(deadLinkCandidates[c]);
        }
      }
      // 最多检查5个候选
      var candidatesToCheck = uniqueCandidates.slice(0, 5);

      // 并行HEAD请求（原串行for循环改为Promise.allSettled，最坏耗时从15秒降至3秒）
      var deadCheckPromises = candidatesToCheck.map(function(candidate) {
        return fetchWithTimeout(candidate.href, {
          method: 'HEAD',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
          cache: 'no-store'
        }, 3000)
          .then(function(resp) { return { candidate: candidate, response: resp, error: null }; })
          .catch(function(err) { return { candidate: candidate, response: null, error: err }; });
      });
      var deadCheckResults = await Promise.allSettled(deadCheckPromises);

      for (var r = 0; r < deadCheckResults.length; r++) {
        var result = deadCheckResults[r].value;
        if (result.response && result.response.status >= 400) {
          deadLinks++;
          if (deadLinkSamples.length < 5) {
            deadLinkSamples.push({ href: result.candidate.href.substring(0, 100), text: result.candidate.text, status: result.response.status });
          }
        } else if (result.error) {
          deadLinks++;
          if (deadLinkSamples.length < 5) {
            deadLinkSamples.push({ href: result.candidate.href.substring(0, 100), text: result.candidate.text, error: 'network_error' });
          }
        }
      }
    }

    // ③ 重复链接检测：统计≥4个不同元素指向同一个链接
    var duplicateLinks = [];
    var DUPLICATE_THRESHOLD = 4;
    var DOWNLOAD_LINK_KW = ['down', 'download', '下載', '下载', 'dl', 'get', 'setup',
      'install', 'free', 'app', 'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z'];

    linkElementMap.forEach(function(elements, href) {
      if (elements.size >= DUPLICATE_THRESHOLD) {
        var lowerHrefForCheck = href.toLowerCase();
        var isDownloadLink = DOWNLOAD_LINK_KW.some(function(kw) {
          return lowerHrefForCheck.includes(kw);
        });
        duplicateLinks.push({
          href: href.substring(0, 200),
          elementCount: elements.size,
          isDownloadLink: isDownloadLink,
          isCrossDomain: (() => {
            try { return new URL(href, location.href).hostname !== location.host; }
            catch (e) { return false; }
          })()
        });
      }
    });

    // 去重外链
    var seen = new Set();
    var unique = externalDownloadLinks.filter(function(d) {
      if (seen.has(d.href)) return false; seen.add(d.href); return true;
    });

    // ==================== 压缩包下载链接专项采集（Rule 2 Phase A 数据源） ====================
    // 扫描所有 <a> 标签的第二遍：专门收集指向压缩包文件的链接（同域+跨域全覆盖）
    // 与 externalDownloadLinks（仅跨域）互补，为 Rule 2 的主动检测提供完整数据
    var archiveDownloadLinks = [];
    var archiveSeen = new Set();
    // 下载关键词（复用于判断链接意图）
    // 使用文件顶层内联常量 ARCHIVE_EXTENSIONS_ALL + DOWNLOAD_BUTTON_KW

    for (var j = 0; j < links.length; j++) {
      var alink = links[j];
      var ahref = (alink.getAttribute('href') || '').trim();
      if (!ahref) continue;
      var alowerHref = ahref.toLowerCase();

      // 跳过非压缩包扩展名
      var matchedExt = null;
      for (var e = 0; e < ARCHIVE_EXTENSIONS_ALL.length; e++) {
        var ext = ARCHIVE_EXTENSIONS_ALL[e];
        if (alowerHref.endsWith(ext)) {
          matchedExt = ext;
          break;
        }
      }
      if (!matchedExt) continue;

      // 跳过 javascript: 和纯锚点
      if (/^javascript\s*:/i.test(ahref)) continue;

      try {
        var aresolved = new URL(ahref, window.location.href);
        var aisCrossDomain = aresolved.hostname !== currentHost;

        // 去重（按完整 URL）
        var anormalized = aresolved.href.replace(/#.*$/, '');
        if (archiveSeen.has(anormalized)) continue;
        archiveSeen.add(anormalized);

        // 检测下载意图：链接文本 + 父元素文本
        var alinkText = (alink.textContent || '').toLowerCase();
        var aparentText = (alink.parentElement ? alink.parentElement.textContent : '').toLowerCase();
        var aariaLabel = (alink.getAttribute('aria-label') || '').toLowerCase();
        var acombined = alinkText + ' ' + aparentText + ' ' + aariaLabel;
        var ahasDownloadKW = DOWNLOAD_BUTTON_KW.some(function(kw) { return acombined.includes(kw); });

        archiveDownloadLinks.push({
          href: ahref.substring(0, 200),
          text: (alink.textContent || '').trim().substring(0, 80),
          isCrossDomain: aisCrossDomain,
          hasDownloadKW: ahasDownloadKW,
          ext: matchedExt
        });
      } catch (e2) { /* URL 解析失败，跳过 */ }
    }

    // ==================== 页面文本中扫描隐藏压缩包链接（多级跳转检测） ====================
    // 恶意跳转页面常在正文中以纯文本形式写下载链接（非 <a> 标签）
    var TEXT_ARCHIVE_PATTERN = /https?:\/\/[^\s<>"'{}[\]|\\^`]+\.(zip|rar|7z|tar|gz|tgz|bz2|xz|iso|cab|arj|lzh|zst)(\?[^\s<>"'{}[\]|\\^`]*)?/gi;
    var pageTextForScan = (document.body ? document.body.innerText : '') || '';
    var textArchiveUrls = [];
    var textArchiveSeen = new Set();

    var tmatch;
    while ((tmatch = TEXT_ARCHIVE_PATTERN.exec(pageTextForScan)) !== null) {
      var rawUrl = tmatch[0];
      try {
        var tparsed = new URL(rawUrl);
        var tnormalized = tparsed.href.replace(/#.*$/, '');
        if (!textArchiveSeen.has(tnormalized)) {
          textArchiveSeen.add(tnormalized);
          textArchiveUrls.push({
            href: tnormalized.substring(0, 200),
            isCrossDomain: tparsed.hostname !== currentHost,
            ext: '.' + tmatch[1].toLowerCase(),
            source: 'text'
          });
        }
      } catch (e) { /* 无效 URL，跳过 */ }
    }

    // ==================== .txt 文件内容解析（多级跳转检测） ====================
    // 页面 <a> 标签可能指向 .txt 文件，其内容包含真实的下载链接
    var txtLinks = [];
    for (var j2 = 0; j2 < links.length; j2++) {
      var tlink = links[j2];
      var thref = (tlink.getAttribute('href') || '').trim();
      if (!thref) continue;
      var tlower = thref.toLowerCase();
      if (tlower.endsWith('.txt') && !/^javascript\s*:/i.test(thref)) {
        try {
          var tresolved = new URL(thref, window.location.href);
          txtLinks.push(tresolved.href);
        } catch (e) {}
      }
    }

    // 去重后最多尝试 3 个 .txt 文件
    var uniqueTxtLinks = [];
    var txtSeen = new Set();
    for (var u = 0; u < txtLinks.length; u++) {
      if (!txtSeen.has(txtLinks[u])) {
        txtSeen.add(txtLinks[u]);
        uniqueTxtLinks.push(txtLinks[u]);
      }
    }
    var txtToFetch = uniqueTxtLinks.slice(0, 3);
    var txtDerivedArchiveUrls = [];

    for (var t2 = 0; t2 < txtToFetch.length; t2++) {
      try {
        var resp = await fetchWithTimeout(txtToFetch[t2], {}, 3000);
        if (resp.ok) {
          var txtContent = await resp.text();
          var ZIP_PATTERN = /https?:\/\/[^\s<>"'{}[\]|\\^`]+\.(zip|rar|7z|tar|gz|tgz|bz2|xz|iso|cab)(\?[^\s<>"'{}[\]|\\^`]*)?/gi;
          var zmatch;
          while ((zmatch = ZIP_PATTERN.exec(txtContent)) !== null) {
            try {
              var zurl = new URL(zmatch[0]);
              txtDerivedArchiveUrls.push({
                href: zurl.href.substring(0, 200),
                isCrossDomain: zurl.hostname !== currentHost,
                ext: '.' + zmatch[1].toLowerCase(),
                source: 'txt-derived'
              });
            } catch (e) {}
          }
        }
      } catch (e) { /* CORS 阻止或网络错误，跳过 */ }
    }

    return {
      totalLinks: links.length,
      samePageLinks: samePageLinks, deadLinks: deadLinks, deadLinkSamples: deadLinkSamples,
      externalDownloadLinks: unique,
      externalWithDownloadText: unique.filter(function(d) { return d.hasDownloadText; }).length,
      externalFileLinks: unique.filter(function(d) { return d.isFileLink; }).length,
      externalArchiveLinks: unique.filter(function(d) { return d.isArchive; }).length,
      // 规则二 Phase A 数据源：压缩包下载链接（同域+跨域全覆盖）
      archiveDownloadLinks: archiveDownloadLinks,
      // 规则四A-③
      duplicateLinks: duplicateLinks,
      hasDuplicateLinks: duplicateLinks.length > 0,
      hasDuplicateDownloadLink: duplicateLinks.some(function(d) { return d.isDownloadLink; }),
      // 规则四 Part C 数据源：多级跳转检测
      textArchiveUrls: textArchiveUrls,
      txtDerivedArchiveUrls: txtDerivedArchiveUrls
    };
  }

  /**
   * 带超时的fetch封装
   */
  function fetchWithTimeout(url, options, timeoutMs) {
    return new Promise(function(resolve, reject) {
      var controller = new AbortController();
      var signal = controller.signal;
      var timeoutId = setTimeout(function() {
        controller.abort();
        reject(new Error('timeout'));
      }, timeoutMs);

      fetch(url, Object.assign({}, options, { signal: signal }))
        .then(function(response) {
          clearTimeout(timeoutId);
          resolve(response);
        })
        .catch(function(err) {
          clearTimeout(timeoutId);
          reject(err);
        });
    });
  }

  // ==================== 规则五：页面度量采集 ====================

  function collectTextSignals(bodyText) {
    bodyText = bodyText || '';
    const textLength = bodyText.length;

    // CJK 统计与 background/icp-utils.js 保持同一判定口径。
    function isCJKChar(codePoint) {
      return (codePoint >= 0x4E00 && codePoint <= 0x9FFF) ||
        (codePoint >= 0x3400 && codePoint <= 0x4DBF) ||
        (codePoint >= 0xF900 && codePoint <= 0xFAFF);
    }

    let cjkCount = 0;
    for (let i = 0; i < textLength; i++) {
      const cp = bodyText.codePointAt(i);
      if (isCJKChar(cp)) cjkCount++;
      if (cp > 0xFFFF) i++;
    }
    const cjkRatio = textLength > 0 ? cjkCount / textLength : 0;
    // 与 background/icp-utils.js 的 detectCJKContent 保持同一判定口径：
    // 放宽阈值以兼容中英混排的中文钓鱼页（详见 icp-utils.js 注释）。
    const hasCJK = (cjkCount >= 20 && cjkRatio >= 0.02) || cjkCount >= 120;

    const lowerText = bodyText.toLowerCase();
    let promoKeywordMatchCount = 0;
    for (const kw of PROMO_KEYWORDS) {
      if (lowerText.includes(kw.toLowerCase())) promoKeywordMatchCount++;
    }

    const emojiRegex = /\p{Emoji_Presentation}|\p{Emoji}️/gu;
    const emojiMatches = bodyText.match(emojiRegex) || [];
    const emojiCount = emojiMatches.length;
    const emojiDensity = textLength > 0 ? (emojiCount / textLength) * 1000 : 0;

    return {
      textLength,
      cjkCount,
      cjkRatio: Math.round(cjkRatio * 10000) / 10000,
      hasCJK,
      promoKeywordMatchCount,
      emojiCount,
      emojiDensity: Math.round(emojiDensity * 100) / 100
    };
  }

  // ==================== Resource Resolver 数据采集 ====================
  /**
   * 采集页面资源数据供 Resource Resolver 使用。
   * 提取 HTML 中的所有 URL、Inline Script 内容、Meta Refresh、iframe src。
   * 不修改任何现有函数，仅新增数据采集层。
   */
  function extractAllHtmlUrls() {
    var currentUrl = window.location.href;
    var currentHost = window.location.hostname;
    var results = [];

    // 扫描所有带 URL 属性的标签
    var urlElements = [
      { sel: 'a[href]', attr: 'href' },
      { sel: 'link[href]', attr: 'href' },
      { sel: 'script[src]', attr: 'src' },
      { sel: 'img[src]', attr: 'src' },
      { sel: 'iframe[src]', attr: 'src' },
      { sel: 'form[action]', attr: 'action' },
      { sel: 'source[src]', attr: 'src' },
      { sel: 'video[src]', attr: 'src' },
      { sel: 'audio[src]', attr: 'src' },
      { sel: 'object[data]', attr: 'data' },
      { sel: 'embed[src]', attr: 'src' }
    ];

    var seenUrls = new Set();

    for (var i = 0; i < urlElements.length; i++) {
      var item = urlElements[i];
      try {
        var elements = document.querySelectorAll(item.sel);
        for (var j = 0; j < elements.length; j++) {
          var el = elements[j];
          var rawUrl = (el.getAttribute(item.attr) || '').trim();
          if (!rawUrl) continue;

          // 跳过 javascript:/data: 等非 HTTP 协议
          if (/^(javascript|data|mailto|tel|file|vbscript):/i.test(rawUrl)) continue;
          // 跳过纯锚点
          if (/^#/.test(rawUrl)) continue;

          // 相对路径 → 绝对 URL
          try {
            var absoluteUrl = new URL(rawUrl, currentUrl).href;
            // 去重
            var key = absoluteUrl.replace(/#.*$/, '');
            if (seenUrls.has(key)) continue;
            seenUrls.add(key);

            results.push({
              rawUrl: rawUrl.substring(0, 300),
              absoluteUrl: absoluteUrl,
              tagName: el.tagName.toLowerCase(),
              attrName: item.attr
            });
          } catch (e) { /* skip invalid */ }
        }
      } catch (e) { /* selector error */ }
    }

    return results;
  }

  function extractInlineScripts() {
    var MAX_SCRIPT_LEN = 32 * 1024; // 32KB per script
    var scripts = document.querySelectorAll('script:not([src])');
    var results = [];
    for (var i = 0; i < scripts.length; i++) {
      var text = scripts[i].textContent || '';
      if (text.length > 3) {
        results.push({
          text: text.length > MAX_SCRIPT_LEN ? text.substring(0, MAX_SCRIPT_LEN) : text,
          lineCount: text.split('\n').length
        });
      }
    }
    return results;
  }

  function extractMetaRefresh() {
    var metas = document.querySelectorAll('meta[http-equiv="refresh"]');
    var results = [];
    for (var i = 0; i < metas.length; i++) {
      var content = (metas[i].getAttribute('content') || '').trim();
      if (!content) continue;

      // 解析 content="5;url=..." 或 content="0;URL=..."
      var urlMatch = content.match(/url\s*=\s*["']?([^"';]+)["']?/i);
      var delayMatch = content.match(/^(\d+)/);

      results.push({
        url: urlMatch ? urlMatch[1].trim() : '',
        delay: delayMatch ? parseInt(delayMatch[1]) : 0,
        originalContent: content.substring(0, 200)
      });
    }
    return results;
  }

  function extractIframeSrcs() {
    var iframes = document.querySelectorAll('iframe[src]');
    var results = [];
    for (var i = 0; i < iframes.length; i++) {
      var src = (iframes[i].getAttribute('src') || '').trim();
      if (src && !/^(javascript|data|about):/i.test(src)) {
        results.push(src);
      }
    }
    return results;
  }

  function collectIntermediatePageLinks() {
    // 标记可疑中间下载页：<a> 标签指向 HTML 页面，且链接文本含下载关键词
    var INTERMEDIATE_KW = [
      '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
      '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
      'download now', 'free download', '立即安装', '一键安装',
      '安装包', 'setup', 'install', 'get started',
      '百度网盘', '蓝奏云', '天翼云', '123云盘', '阿里云盘',
      '迅雷下载', 'bt下载', '磁力链接'
    ];
    // 使用文件顶层内联常量 FILE_EXTENSIONS（压缩包 + 可执行文件全覆盖）
    var currentHost = window.location.hostname;
    var currentUrl = window.location.href;
    var results = [];
    var seen = new Set();

    var links = document.querySelectorAll('a[href]');
    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var href = (link.getAttribute('href') || '').trim();
      if (!href) continue;
      if (/^(javascript|data|mailto|tel|file|#)/i.test(href)) continue;

      try {
        var resolved = new URL(href, currentUrl);
        var lowerPath = resolved.pathname.toLowerCase();

        // 跳过归档/可执行文件（它们不需要中间页抓取）
        var isArchive = false;
        for (var e = 0; e < FILE_EXTENSIONS.length; e++) {
          if (lowerPath.endsWith(FILE_EXTENSIONS[e])) { isArchive = true; break; }
        }
        if (isArchive) continue;

        // 只关注跨域 HTML 链接
        if (resolved.hostname === currentHost) continue;

        // 检查下载关键词
        var linkText = (link.textContent || '').toLowerCase();
        var parentText = (link.parentElement ? link.parentElement.textContent : '').toLowerCase();
        var ariaLabel = (link.getAttribute('aria-label') || '').toLowerCase();
        var className = (link.className || '').toLowerCase();
        var combined = linkText + ' ' + parentText + ' ' + ariaLabel + ' ' + className;
        var hasDownloadKW = false;
        for (var k = 0; k < INTERMEDIATE_KW.length; k++) {
          if (combined.indexOf(INTERMEDIATE_KW[k].toLowerCase()) !== -1) {
            hasDownloadKW = true;
            break;
          }
        }
        if (!hasDownloadKW && resolved.hostname.indexOf('download') === -1 &&
            resolved.hostname.indexOf('down') === -1 && resolved.hostname.indexOf('dl.') === -1) continue;

        var key = resolved.href.replace(/#.*$/, '');
        if (seen.has(key)) continue;
        seen.add(key);

        results.push({
          url: resolved.href,
          text: (link.textContent || '').trim().substring(0, 80),
          hasDownloadKW: hasDownloadKW
        });
      } catch (e2) { /* skip */ }
    }

    return results;
  }

  function collectResourceData() {
    return {
      htmlUrls: extractAllHtmlUrls(),
      inlineScripts: extractInlineScripts(),
      metaRefreshUrls: extractMetaRefresh(),
      iframeSrcs: extractIframeSrcs(),
      pageText: (document.body ? document.body.innerText : '').substring(0, 65536) || '',
      intermediatePages: collectIntermediatePageLinks()
    };
  }

  function collectPageMetrics(bodyText) {
    bodyText = bodyText || '';
    const html = document.documentElement.outerHTML || '';
    const htmlLines = html.split('\n').length;

    // DOM复杂度：节点总数（替代HTML行数作为结构复杂度指标，不受代码压缩/格式化影响）
    const domNodeCount = document.getElementsByTagName('*').length;

    // 外部资源总计数（云上/服务器资源：含外部脚本、外部样式、图片、字体、媒体等）
    const currentHost = window.location.hostname;
    function isExternal(url) {
      if (!url) return false;
      try {
        var u = new URL(url, window.location.href);
        return u.hostname && u.hostname !== currentHost;
      } catch (e) { return false; }
    }

    // 统计各类外部资源（合并查询，避免重复 querySelectorAll）
    var extRes = {
      scripts: [],
      styles: [],
      images: [],
      media: [],
      fonts: []
    };

    // 外部脚本：带 src 属性的 <script>（不含内联脚本）
    extRes.scripts = Array.from(document.querySelectorAll('script[src]'))
      .map(function(s) { return s.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部样式：<link rel="stylesheet">
    extRes.styles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
      .map(function(l) { return l.getAttribute('href') || ''; })
      .filter(isExternal);

    // 外部图片
    extRes.images = Array.from(document.querySelectorAll('img[src]'))
      .map(function(i) { return i.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部媒体：视频、音频、iframe 等
    extRes.media = Array.from(document.querySelectorAll('video[src], audio[src], source[src], iframe[src]'))
      .map(function(el) { return el.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部字体
    extRes.fonts = Array.from(document.querySelectorAll('link[rel*="font"], link[as="font"]'))
      .map(function(l) { return l.getAttribute('href') || ''; })
      .filter(isExternal);

    // 外部资源去重总数（同URL只计一次）
    var allExternal = new Set();
    Object.values(extRes).forEach(function(urls) {
      urls.forEach(function(u) { allExternal.add(u); });
    });

    var totalExternalResources = allExternal.size;
    var hasExternalResources = totalExternalResources > 0;

    // 框架标记检测：优先基于资源 URL 和 DOM 特征，避免依赖 Content Script 隔离世界中不可靠的 window.* 全局变量。
    // 注：HTML marker 列表需与 utils/constants.js 中 FRAMEWORK_HTML_MARKERS 保持同步
    const FRAMEWORK_HTML_MARKERS = [
      'react', 'vue', 'angular', 'webpack', '__initial_state__',
      '_next/', 'nuxt', 'svelte', 'jquery', 'bootstrap',
      'node_modules', '.jsx', '.tsx', 'data-v-', 'ng-version',
      '__vue__', '__react', 'redux', 'react-dom', 'vue-router',
      'webpackjsonp', '__webpack_require__', '__nuxt', '__next'
    ];

    const FRAMEWORK_RESOURCE_MARKERS = [
      '_next/', '/_next/', 'next/static', '_nuxt/', '/_nuxt/',
      'react', 'react-dom', 'vue', 'vue-router', 'angular',
      'svelte', 'jquery', 'bootstrap', 'webpack'
    ];

    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
      .map(function(s) { return s.getAttribute('src') || ''; })
      .filter(Boolean);
    const linkHrefs = Array.from(document.querySelectorAll('link[href]'))
      .map(function(l) { return l.getAttribute('href') || ''; })
      .filter(Boolean);
    const resourceUrlText = scriptSrcs.concat(linkHrefs).join(' ').toLowerCase();

    // A. 资源 URL 扫描（框架产物通常会在 script/link URL 中留下稳定目录或包名）
    var resourceFrameworkHits = [];
    for (var rf = 0; rf < FRAMEWORK_RESOURCE_MARKERS.length; rf++) {
      if (resourceUrlText.indexOf(FRAMEWORK_RESOURCE_MARKERS[rf]) !== -1) {
        resourceFrameworkHits.push(FRAMEWORK_RESOURCE_MARKERS[rf]);
      }
    }

    // B. DOM 特征扫描：框架根节点、SSR 数据节点、编译产物属性等。
    var domFrameworkHits = [];
    try {
      if (document.getElementById('__next') || document.querySelector('[id="__next"]')) domFrameworkHits.push('next-dom');
      if (document.getElementById('__nuxt') || document.querySelector('[id="__nuxt"]')) domFrameworkHits.push('nuxt-dom');
      if (document.querySelector('[ng-version]')) domFrameworkHits.push('angular-dom');
      if (document.querySelector('[data-reactroot], [data-reactid]')) domFrameworkHits.push('react-dom');
      if (document.querySelector('[data-svelte-h], [data-sveltekit]')) domFrameworkHits.push('svelte-dom');
      if (document.querySelector('[x-data]')) domFrameworkHits.push('alpine-dom');

      const attrScanNodes = document.getElementsByTagName('*');
      const attrScanLimit = Math.min(attrScanNodes.length, 2000);
      for (let ai = 0; ai < attrScanLimit; ai++) {
        const attrs = attrScanNodes[ai].attributes || [];
        for (let aj = 0; aj < attrs.length; aj++) {
          const attrName = attrs[aj].name || '';
          if (attrName.startsWith('data-v-')) {
            domFrameworkHits.push('vue-sfc-dom');
            ai = attrScanLimit; // 跳出外层扫描
            break;
          }
        }
      }
    } catch (e) { /* DOM 查询异常时跳过框架 DOM 特征 */ }

    // C. HTML 源码全文扫描（兜底，覆盖 SSR 数据和内联框架标记）
    const htmlLower = html.toLowerCase();
    var htmlFrameworkHits = [];
    for (var i = 0; i < FRAMEWORK_HTML_MARKERS.length; i++) {
      if (htmlLower.indexOf(FRAMEWORK_HTML_MARKERS[i]) !== -1) {
        htmlFrameworkHits.push(FRAMEWORK_HTML_MARKERS[i]);
      }
    }

    // 合并并去重
    var allFrameworkHits = [];
    var frameworkSeen = new Set();
    resourceFrameworkHits.concat(domFrameworkHits, htmlFrameworkHits).forEach(function(hit) {
      if (!frameworkSeen.has(hit)) {
        frameworkSeen.add(hit);
        allFrameworkHits.push(hit);
      }
    });
    var hasFrameworkMarkers = allFrameworkHits.length > 0;

    // JS 引用规范检查：模板化/克隆式资源布局，不依赖单一固定路径。
    const suspiciousScriptRefs = [];
    const suspiciousScriptPatterns = [
      {
        type: 'generic_lang_bundle',
        pattern: /(^|\/)js\/(lang|language|i18n|locale|locales)\/[^/]+\.js$/
      },
      {
        type: 'template_lang_bundle',
        pattern: /(^|\/)(p|template|templates|theme|themes|skin|skins|static|statics|public|assets)\/js\/(lang|language|i18n|locale|locales)\/[^/]+\.js$/
      },
      {
        type: 'template_generic_bundle',
        pattern: /(^|\/)(p|template|templates|theme|themes|skin|skins|statics)\/js\/(common|config|public|base|main|app|index|jquery)[^/]*\.js$/
      }
    ];
    for (let si = 0; si < scriptSrcs.length; si++) {
      const rawSrc = scriptSrcs[si];
      let pathname = '';
      try {
        pathname = new URL(rawSrc, window.location.href).pathname.toLowerCase();
      } catch (e) {
        pathname = rawSrc.toLowerCase().split('?')[0].split('#')[0];
      }
      for (let pi = 0; pi < suspiciousScriptPatterns.length; pi++) {
        const item = suspiciousScriptPatterns[pi];
        if (item.pattern.test(pathname)) {
          suspiciousScriptRefs.push({
            type: item.type,
            src: rawSrc.substring(0, 160)
          });
          break;
        }
      }
    }

    // 页面文本长度
    const textLength = bodyText.length;

    // Meta generator（AI生成页面的典型特征，保留供未来分析）
    const metaGenerator = document.querySelector('meta[name="generator"]');
    const generator = metaGenerator ? metaGenerator.getAttribute('content') : null;

    // 内联样式数量
    const inlineStyles = document.querySelectorAll('[style]').length;

    // <head>中的<link>数量
    const headLinks = document.querySelectorAll('head link').length;

    // 带src的脚本总数（含同源+外部，保留供参考）
    const totalScriptsWithSrc = document.querySelectorAll('script[src]').length;
     
    // ----  新强信号度量：混淆脚本 / 隐藏 iframe / 内联样式比 ----
    // 信号A：混淆内联脚本（强信号源）。仅扫描无 src 的内联 <script>，命中打包/混淆器
    // 特征才计，避免误伤普通最小化（minified）脚本。
    const inlineScriptEls = Array.from(document.querySelectorAll('script:not([src])'));
    let obfuscatedInlineScriptCount = 0;
    for (let ix = 0; ix < inlineScriptEls.length; ix++) {
      const code = inlineScriptEls[ix].textContent || '';
      if (code.length < 80) continue;
      let hit = false;
      // (1) eval / new Function 解析长字符串 + 转义序列（典型打包器）
      if (/(\beval|new\s+Function)\s*\(/.test(code) && /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(code)) {
        hit = true;
      // (2) 长 base64 / hex blob（>= 512 连续可打印，排除普通小串与标识符）
      } else if (/(?:[A-Za-z0-9+/]{512,}={0,2})/.test(code) || /(?:[0-9a-f]{512,})/i.test(code)) {
        hit = true;
      // (3) fromCharCode / unescape 解码循环（多次出现）
      } else if (/fromCharCode|String\.fromCharCode|unescape/.test(code) &&
                 (code.match(/fromCharCode|unescape/g) || []).length >= 3) {
        hit = true;
      }
      if (hit) obfuscatedInlineScriptCount++;
    }

    // 信号B：隐藏 iframe（强信号源）。视觉不可见的 iframe 是钓鱼 cloaking 典型手法；
    // 仅多 iframe 叠套(>=2) 或 单体隐藏 + 自包含(data:/blob:/srcdoc) 才计，避免误伤
    // 分析/验证等正常隐藏 widget（单体隐藏 iframe 常见）。
    const iframeEls = Array.from(document.querySelectorAll('iframe'));
    let hiddenIframeCount = 0;
    let hiddenDataIframe = false;
    for (let fx = 0; fx < iframeEls.length; fx++) {
      const fel = iframeEls[fx];
      const fstyle = (fel.getAttribute('style') || '').toLowerCase();
      const fw = parseInt(fel.getAttribute('width') || '', 10);
      const fh = parseInt(fel.getAttribute('height') || '', 10);
      const hiddenByAttr = fel.hasAttribute('hidden');
      const hiddenByStyle = /display\s*:\s*none/.test(fstyle) ||
                            /visibility\s*:\s*hidden/.test(fstyle) ||
                            /opacity\s*:\s*0(\b|\.)/.test(fstyle) ||
                            /(position\s*:\s*(?:absolute|fixed))[^;}]*?(left|top|right|bottom)\s*:\s*-/.test(fstyle);
      const zeroSize = (fw === 0 || fh === 0) ||
                       /width\s*:\s*0/.test(fstyle) || /height\s*:\s*0/.test(fstyle);
      if (hiddenByAttr || hiddenByStyle || zeroSize) {
        hiddenIframeCount++;
        const fsrc = (fel.getAttribute('src') || '').toLowerCase();
        if (/^data:|^blob:/.test(fsrc) || fel.hasAttribute('srcdoc')) hiddenDataIframe = true;
      }
    }

    // 信号C：内联样式比（强信号源）。克隆/钓鱼页常把样式全部内联（单文件克隆），
    // 正常站多用外部样式表。ratio = (内联 style 属性 + <style> 块) / (上述 + <link rel=stylesheet>)。
    const styleBlockCount = document.querySelectorAll('style').length;
    const stylesheetLinkCount = document.querySelectorAll('link[rel="stylesheet"]').length;
    const inlineStyleVolume = inlineStyles + styleBlockCount;
    const totalStyleMech = inlineStyleVolume + stylesheetLinkCount;
    const inlineStyleRatio = totalStyleMech > 0 ? inlineStyleVolume / totalStyleMech : 0;

    return {
      htmlLines,
      domNodeCount,
      totalScriptsWithSrc,
      hasFrameworkMarkers,
      frameworkHits: allFrameworkHits,
      suspiciousScriptRefCount: suspiciousScriptRefs.length,
      suspiciousScriptRefs: suspiciousScriptRefs.slice(0, 5),
      textLength,
      generator,
      inlineStyles,
      headLinks,
      //  新强信号度量字段
      obfuscatedInlineScriptCount,
      hiddenIframeCount,
      hiddenDataIframe,
      styleBlockCount,
      stylesheetLinkCount,
      inlineStyleRatio,
      url: window.location.href,
      hasExternalResources: hasExternalResources,
      totalExternalResources: totalExternalResources,
      externalBreakdown: {
        scripts: extRes.scripts.length,
        styles: extRes.styles.length,
        images: extRes.images.length,
        media: extRes.media.length,
        fonts: extRes.fonts.length
      }
    };
  }

  // ==================== ICP备案号扫描 ====================

  function findIcpStrings() {
    const icpStrings = [];
    const seen = new Set();

    function add(text) {
      const t = text.trim();
      if (t.length > 3 && t.length < 500 && !seen.has(t) &&
          /ICP|icp|备案|beian|BeiAn|BEIAN|公安|公网安备|经营许可证|B2-|增值电信/.test(t)) {
        icpStrings.push(t); seen.add(t);
      }
    }

    // 1. footer元素（包括任何class/id含footer的元素）
    document.querySelectorAll(
      'footer, .footer, #footer, [class*="footer"], [id*="footer"], ' +
      '[class*="foot"], [id*="foot"], ' +
      'div:last-of-type, section:last-of-type'
    ).forEach(el => add(el.textContent || ''));

    // 2. icp/beian/copyright/record 命名的元素
    const sel = '[id*="icp"],[class*="icp"],[id*="beian"],[class*="beian"],' +
                '[id*="备案"],[class*="备案"],[id*="copyright"],[class*="copyright"],' +
                '[id*="record"],[class*="record"],[id*="公安"],[class*="公安"],' +
                '.record,#record,.icp-info,#icp-info,.beian-info,#beian-info,' +
                '[id*="license"],[class*="license"],[id*="police"],[class*="police"],' +
                '[id*="icpNo"],[class*="icpNo"],[id*="beianNo"],[class*="beianNo"]';
    try {
      document.querySelectorAll(sel).forEach(el => add(el.textContent || ''));
    } catch (e) { /* selector error */ }

    // 3. 页面底部区域元素（body 最后 30% 的直接子元素及其内部文本）
    if (document.body) {
      const children = [...document.body.children];
      const startIdx = Math.max(0, Math.floor(children.length * 0.7));
      for (let i = startIdx; i < children.length; i++) {
        const t = (children[i].textContent || '').trim();
        if (t.length > 5 && t.length < 1000) add(t);
        // 同时检查该元素内的所有<a>链接文本
        const links = children[i].querySelectorAll('a');
        for (const link of links) {
          const linkText = (link.textContent || '').trim();
          if (linkText.length > 2 && linkText.length < 200) add(linkText);
        }
      }
    }

    // 4. 检查所有页面<a>元素（很多ICP备案号嵌在链接中）
    document.querySelectorAll('a').forEach(el => {
      const href = (el.getAttribute('href') || '').toLowerCase();
      const text = (el.textContent || '').trim();
      if (text.length > 3 && text.length < 300 &&
          /ICP|备案|beian|公安/.test(text + href)) {
        add(text);
      }
      if (href.includes('beian') || href.includes('icp') || href.includes('miit')) {
        add(text || href);
      }

      // 专项：beian.gov.cn / beian.miit.gov.cn 等政府备案查询链接
      // 链接文本通常为完整备案号，如 "粤ICP备2024178421号"
      if (/(beian\.gov\.cn|beian\.miit\.gov\.cn|miitbeian\.gov\.cn)/i.test(href)) {
        // 优先取链接文本，其次取父元素文本，再取相邻文本
        var linkText = (el.textContent || '').trim();
        if (linkText.length > 5 && /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]/.test(linkText)) {
          add(linkText);
        }
        // 同时检查父元素中的完整备案信息
        var parentEl = el.parentElement;
        if (parentEl) {
          var parentText = (parentEl.textContent || '').trim();
          if (parentText.length > 5 && parentText.length < 500 &&
              /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]/.test(parentText)) {
            add(parentText);
          }
        }
      }
    });

    // 5. 检查 position:fixed bottom:0 的元素（底部固定栏）
    // 优化：原 querySelectorAll('*') 扫描全部元素+getComputedStyle会触发布局重算。
    // 改为只扫描 body 最后 500 个元素（ICP备案的固定栏都在页面底部）。
    try {
      const bodyChildren = document.body ? [...document.body.children] : [];
      const startScan = Math.max(0, bodyChildren.length - 500); // 最多扫描底部500个
      for (let si = startScan; si < bodyChildren.length; si++) {
        // 先快速检查子元素数量，子元素多的容器更可能含底部固定栏
        const container = bodyChildren[si];
        if (container.children.length === 0 && !container.classList.length && !container.id) continue;
        const style = window.getComputedStyle(container);
        if (style.position === 'fixed' &&
            (style.bottom === '0px' || parseInt(style.bottom) < 50)) {
          const t = (container.textContent || '').trim();
          if (t.length > 5 && t.length < 500) add(t);
        }
        // 同时检查容器内的直接子元素
        for (const child of container.children) {
          const childStyle = window.getComputedStyle(child);
          if (childStyle.position === 'fixed' &&
              (childStyle.bottom === '0px' || parseInt(childStyle.bottom) < 50)) {
            const t = (child.textContent || '').trim();
            if (t.length > 5 && t.length < 500) add(t);
          }
        }
      }
    } catch (e) { /* ignore */ }

    // 6. TreeWalker 扫描全页面所有文本节点
    let count = 0;
    const MAX_NODES = 15000; // 控制大型页面扫描成本，常规 ICP 文本通常位于页脚或备案相关元素
    try {
      const walker = document.createTreeWalker(
        document.body || document.documentElement, NodeFilter.SHOW_TEXT,
        { acceptNode: () => (count++ < MAX_NODES) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT }
      );
      let node;
      while ((node = walker.nextNode())) {
        const t = node.textContent.trim();
        if (t.length > 5 && t.length < 300 &&
            (t.includes('ICP') || t.includes('icp') || t.includes('备案') ||
             t.includes('beian') || t.includes('公安') || t.includes('B2-') ||
             t.includes('经营许可证') || t.includes('增值电信'))) {
          add(t);
        }
      }
    } catch (e) { /* ignore */ }

    return icpStrings;
  }

  /**
   * 检测页面是否存在可点击的工信部备案查询链接
   * 检查 <a> 标签 href 是否指向 beian.miit.gov.cn 等政府备案域名
   * @returns {boolean}
   */
  function checkIcpGovLink() {
    try {
      var links = document.querySelectorAll('a[href*="beian.miit.gov.cn"], a[href*="beian.gov.cn"], a[href*="miitbeian.gov.cn"], a[href*="beian.mps.gov.cn"]');
      return links.length > 0;
    } catch (e) {
      return false;
    }
  }

  // ==================== 发送分析结果 ====================

  function safeCollect(fn, fallback) {
    try { return fn(); } catch (e) { console.error('[VirusDetector] 采集失败:', e); return fallback; }
  }

  // 首次扫描结果缓存，用于二次扫描去重
  var _firstScanData = null;

  async function sendAnalysisResult(options) {
    options = options || {};
    if (await shouldSkipPageAnalysis()) return;

    const authenticationPage = isAuthenticationPage();
    if (authenticationPage) disablePageNavigationGuard();
    // 每个采集函数独立 try-catch，一个失败不影响其他
    var bodyText = safeCollect(function() { return (document.body ? document.body.innerText : '') || ''; }, '');
    var pageMetrics = safeCollect(function() { return collectPageMetrics(bodyText); }, null);
    var icpStrings = safeCollect(findIcpStrings, []);
    // 链接分析含异步HEAD请求检测死链，需await
    var linkMetrics = null;
    try {
      linkMetrics = await collectLinkMetrics({
        checkDeadLinks: options.checkDeadLinks !== false && !authenticationPage
      });
    } catch (e) {
      console.error('[VirusDetector] 链接分析采集失败:', e);
    }

    var hasIcpGovLink = checkIcpGovLink();
    var textSignals = safeCollect(function() { return collectTextSignals(bodyText); }, null);
    var resourceData = safeCollect(function() { return collectResourceData(); }, null);

    // Gate: 下载意图门控 — 任一条件触发即视为有下载意图
    // 条件1：任意 <a> 链接文本含下载关键词（不论 href 指向什么、甚至 javascript: 函数调用）
    // 条件2：页面正文中下载关键词密度 ≥ 阈值（默认 2.0 次/千字符，可在设置中调整）
    // Gate 条件1：扫描所有 <a> 元素文本（使用顶层 DOWNLOAD_BUTTON_KW）
    var anyLinkDownloadText = false;
    var allLinks = document.querySelectorAll('a');
    for (var gi = 0; gi < allLinks.length && !anyLinkDownloadText; gi++) {
      var gLink = allLinks[gi];
      var gText = (gLink.textContent || '').toLowerCase();
      var gAria = (gLink.getAttribute('aria-label') || '').toLowerCase();
      var gCombined = gText + ' ' + gAria;
      for (var gk = 0; gk < DOWNLOAD_BUTTON_KW.length; gk++) {
        if (gCombined.indexOf(DOWNLOAD_BUTTON_KW[gk]) !== -1) {
          anyLinkDownloadText = true;
          break;
        }
      }
    }

    // Gate 条件2：页面正文下载关键词密度
    var downloadDensity = 0;
    var bodyTextLower = bodyText.toLowerCase();
    var kwHitCount = 0;
    for (var dk = 0; dk < DOWNLOAD_BUTTON_KW.length; dk++) {
      var kw = DOWNLOAD_BUTTON_KW[dk];
      var searchPos = 0;
      while ((searchPos = bodyTextLower.indexOf(kw, searchPos)) !== -1) {
        kwHitCount++;
        searchPos += kw.length;
      }
    }
    if (bodyText.length > 100) {
      downloadDensity = (kwHitCount / bodyText.length) * 1000;
    }
    var needsDetection = anyLinkDownloadText || downloadDensity >= 2.0;

    var payload = {
      url: window.location.href, domain: window.location.hostname, title: document.title,
      icpStrings: icpStrings, pageMetrics: pageMetrics, linkMetrics: linkMetrics,
      hasIcpGovLink: hasIcpGovLink, textSignals: textSignals, resourceData: resourceData,
      needsDetection: needsDetection
    };

    // 二次扫描去重：与首次结果比对，无新增数据则跳过发送
    if (_firstScanData) {
      var firstIcpCount = (_firstScanData.icpStrings || []).length;
      var firstLinkCount = _firstScanData.linkMetrics ? _firstScanData.linkMetrics.totalLinks : 0;
      var newIcpCount = (icpStrings || []).length;
      var newLinkCount = linkMetrics ? linkMetrics.totalLinks : 0;
      var firstExternalCount = _firstScanData.linkMetrics ? _firstScanData.linkMetrics.externalDownloadLinks.length : 0;
      var newExternalCount = linkMetrics ? linkMetrics.externalDownloadLinks.length : 0;
      var firstNeedsDetection = _firstScanData.needsDetection === true;

      // Gate 状态变化时强制发送（动态内容可能给已有链接添加下载文本）
      if (firstNeedsDetection !== needsDetection) {
        console.log('[VirusDetector] 二次扫描检测到 Gate 状态变化 (' + firstNeedsDetection + '→' + needsDetection + ')，强制发送');
      }
      // ICP 备案号无新增 且 链接/外链数量无增长 且 Gate 状态未变 → 跳过二次发送
      else if (newIcpCount <= firstIcpCount && newLinkCount <= firstLinkCount && newExternalCount <= firstExternalCount) {
        console.log('[VirusDetector] 二次扫描无新增数据，跳过重复发送');
        return;
      }
      console.log('[VirusDetector] 二次扫描检测到新数据 (ICP:' + firstIcpCount + '→' + newIcpCount +
        ', 链接:' + firstLinkCount + '→' + newLinkCount + ', 外链:' + firstExternalCount + '→' + newExternalCount + ')');
    } else {
      _firstScanData = { icpStrings: icpStrings, linkMetrics: linkMetrics, needsDetection: needsDetection };
    }

    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS_RESULT',
      payload: payload,
      timestamp: Date.now()
    }).catch(function() {});
  }

  // ==================== 消息监听 ====================

  /**
   * 读取 checkDeadLinks 设置（从 chrome.storage.local）。
   * 优先使用已缓存的设置值，缓存未命中时返回 true（默认启用死链检测）。
   * @returns {Promise<boolean>}
   */
  let _cachedCheckDeadLinks = true;
  async function getCheckDeadLinksSetting() {
    try {
      const r = await chrome.storage.local.get('global_settings');
      const gs = r.global_settings || {};
      _cachedCheckDeadLinks = gs.checkDeadLinks !== false;
    } catch (e) { /* ignore */ }
    return _cachedCheckDeadLinks;
  }

  // 监听设置变更广播
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'UPDATE_SETTINGS') {
      if (message.payload && message.payload.checkDeadLinks !== undefined) {
        _cachedCheckDeadLinks = message.payload.checkDeadLinks;
      }
    }
  });

  // 主消息监听
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'REQUEST_PAGE_TEXT') {
      (async () => {
        try {
          if (await shouldSkipPageAnalysis()) {
            sendResponse({ success: false, skipped: 'whitelisted' });
            return;
          }
          const authenticationPage = isAuthenticationPage();
          if (authenticationPage) disablePageNavigationGuard();
          var linkMetrics = null;
          try {
            linkMetrics = await collectLinkMetrics({
              checkDeadLinks: _cachedCheckDeadLinks && !authenticationPage
            });
          } catch (e) {
            console.error('[VirusDetector] 链接分析采集失败:', e);
          }
          var bodyText = (document.body ? document.body.innerText : '') || '';
          // Gate: 同 sendAnalysisResult 中的逻辑
          // Gate: 复用顶层 DOWNLOAD_BUTTON_KW
          var anyLinkDL = false;
          var allAnchors = document.querySelectorAll('a');
          for (var gi2 = 0; gi2 < allAnchors.length && !anyLinkDL; gi2++) {
            var gl2 = allAnchors[gi2];
            var gc2 = ((gl2.textContent || '') + ' ' + (gl2.getAttribute('aria-label') || '')).toLowerCase();
            for (var gk2 = 0; gk2 < DOWNLOAD_BUTTON_KW.length; gk2++) {
              if (gc2.indexOf(DOWNLOAD_BUTTON_KW[gk2]) !== -1) { anyLinkDL = true; break; }
            }
          }
          var btLower = bodyText.toLowerCase();
          var kwHits = 0;
          for (var dk2 = 0; dk2 < DOWNLOAD_BUTTON_KW.length; dk2++) {
            var kw2 = DOWNLOAD_BUTTON_KW[dk2]; var sp2 = 0;
            while ((sp2 = btLower.indexOf(kw2, sp2)) !== -1) { kwHits++; sp2 += kw2.length; }
          }
          var density2 = bodyText.length > 100 ? (kwHits / bodyText.length) * 1000 : 0;
          var needsDetection2 = anyLinkDL || density2 >= 2.0;
          sendResponse({
            success: true,
            pageMetrics: safeCollect(function() { return collectPageMetrics(bodyText); }, null),
            linkMetrics: linkMetrics,
            icpStrings: safeCollect(findIcpStrings, []),
            hasIcpGovLink: checkIcpGovLink(),
            textSignals: safeCollect(function() { return collectTextSignals(bodyText); }, null),
            resourceData: safeCollect(function() { return collectResourceData(); }, null),
            needsDetection: needsDetection2,
            title: document.title,
            url: window.location.href
          });
        } catch (e) {
          sendResponse({ success: false, error: e.message });
        }
      })();
      return true;
    }
    return false;
  });

  // ==================== 初始化 ====================

  function runWhenIdle(fn) {
    if (typeof window.requestIdleCallback === 'function') {
      window.requestIdleCallback(fn, { timeout: 1500 });
    } else {
      setTimeout(fn, 0);
    }
  }

  function scheduleAnalysis(delayMs, options) {
    setTimeout(function() {
      runWhenIdle(function() { sendAnalysisResult(options); });
    }, delayMs);
  }

  async function init() {
    if (await shouldSkipPageAnalysis()) return;

    watchForAuthenticationInteraction();
    // 先读取用户设置中的 checkDeadLinks 偏好，再开始扫描
    _cachedCheckDeadLinks = await getCheckDeadLinksSetting();
    const authenticationPage = isAuthenticationPage();
    if (authenticationPage) disablePageNavigationGuard();
    scheduleAnalysis(600, { checkDeadLinks: _cachedCheckDeadLinks && !authenticationPage });
    // 二次扫描用于捕获懒加载内容，但跳过 HEAD 死链验证以降低页面和网络成本。
    scheduleAnalysis(3500, { checkDeadLinks: false });
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    init();
  } else {
    window.addEventListener('load', init, { once: true });
  }

})();
