/**
 * 银狐木马检测 - 下载风险确认窗口控制器
 *
 * 职责：
 *   - 从 URL 参数读取下载信息和检测结果并渲染界面
 *   - 处理三种用户操作：仅此次放行 / 信任网站 / 拦截并拉黑
 *   - 将用户选择回传给 Service Worker 执行对应操作
 *
 * URL 参数（由 Service Worker 传入）：
 *   domain         — 页面域名
 *   score          — 当前风险评分
 *   filename       — 下载文件名
 *   downloadDomain — 下载来源域名
 *   downloadUrl    — 原始下载 URL（用于重新发起下载）
 *   tabId          — 来源标签页 ID
 *   downloadId     — 被取消的下载 ID
 *   correctUrl     — 官方网站 URL（如有）
 *   officialName   — 官方名称（如有）
 */
(function () {
  'use strict';

  /**
   * 验证 URL 协议，仅允许 http/https，防止 javascript: 等注入
   * @param {string} url
   * @returns {string} 安全 URL，无效时返回空字符串
   */
  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    try {
      const u = new URL(url);
      if (u.protocol === 'http:' || u.protocol === 'https:') return url;
    } catch (e) { /* fall through */ }
    return '';
  }

  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || '未知网站';
  const score = parseInt(params.get('score'), 10) || 0;
  const filename = params.get('filename') || '未知文件';
  const downloadDomain = params.get('downloadDomain') || '未知';
  const downloadUrl = params.get('downloadUrl') || '';
  const tabId = parseInt(params.get('tabId'), 10) || 0;
  const downloadId = parseInt(params.get('downloadId'), 10) || 0;
  const correctUrl = sanitizeUrl(params.get('correctUrl') || '');
  const officialName = params.get('officialName') || '';

  // 渲染基本信息
  document.getElementById('risk-score').textContent = score;
  document.getElementById('info-filename').textContent = filename;
  document.getElementById('info-download-domain').textContent = downloadDomain;
  document.getElementById('info-page-domain').textContent = domain;

  // 信任网站描述：显示具体的域名
  const trustDesc = document.getElementById('trust-desc');
  if (trustDesc) {
    trustDesc.textContent = '将 ' + domain + ' 加入白名单，此后不再拦截';
  }

  // 拉黑描述：显示具体的下载域名
  const blockDesc = document.getElementById('block-desc');
  if (blockDesc) {
    blockDesc.textContent = '将 ' + downloadDomain + ' 标记为恶意下载域名，跨站免疫';
  }

  // 官方网站区域
  if (correctUrl) {
    document.getElementById('official-section').style.display = 'block';
    document.getElementById('official-domain').textContent = correctUrl;
    document.getElementById('official-btn').href = correctUrl;
  }

  /**
   * 向 Service Worker 发送用户选择并关闭窗口
   * @param {string} action - "allow_once" | "trust_site" | "block_blacklist"
   */
  async function sendChoice(action) {
    try {
      await chrome.runtime.sendMessage({
        type: 'DOWNLOAD_CONFIRMATION',
        payload: {
          action: action,
          downloadUrl: downloadUrl,
          tabId: tabId,
          downloadId: downloadId,
          pageDomain: domain,
          downloadDomain: downloadDomain,
          filename: filename
        }
      });

      // 同步上报用户决策
      if (action === 'trust_site') {
        // 信任网站 = 用户认为这是误报
        chrome.runtime.sendMessage({
          type: 'SUBMIT_REPORT',
          payload: { reportType: 'false_positive', domain, note: '下载确认中信任网站' }
        }).catch(() => {});
      } else if (action === 'block_blacklist') {
        // 拉黑下载域名 = 用户确认威胁
        chrome.runtime.sendMessage({
          type: 'SUBMIT_REPORT',
          payload: { reportType: 'confirmed_phish', domain, note: '下载确认中拉黑下载域名: ' + downloadDomain }
        }).catch(() => {});
      }
    } catch (e) {
      console.error('[DownloadConfirm] 发送确认消息失败:', e);
    }
    window.close();
  }

  // ---- 按钮事件 ----

  // 仅此次放行
  document.getElementById('btn-allow-once').addEventListener('click', () => {
    sendChoice('allow_once');
  });

  // 信任网站并放行
  document.getElementById('btn-trust-site').addEventListener('click', () => {
    sendChoice('trust_site');
  });

  // 拦截并拉黑
  document.getElementById('btn-block-blacklist').addEventListener('click', () => {
    sendChoice('block_blacklist');
  });

  // ---- 自动关闭 ----

  // 60 秒倒计时后自动关闭（比警告窗口更长，给用户足够时间决策）
  const AUTO_CLOSE_SECONDS = 60;
  let remaining = AUTO_CLOSE_SECONDS;
  const hintEl = document.getElementById('auto-close-hint');

  function renderCountdown() {
    if (hintEl) {
      hintEl.textContent = '本提示将在 ' + remaining + ' 秒后自动关闭（默认拦截）';
    }
  }

  let autoCloseTimer = null;

  function clearAutoClose() {
    if (autoCloseTimer) {
      clearInterval(autoCloseTimer);
      autoCloseTimer = null;
    }
  }

  renderCountdown();
  autoCloseTimer = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearAutoClose();
      // 超时默认行为：拦截（不写入黑名单，等同于关闭窗口）
      window.close();
      return;
    }
    renderCountdown();
  }, 1000);

  // 任意按钮点击取消倒计时
  document.getElementById('btn-allow-once').addEventListener('click', clearAutoClose);
  document.getElementById('btn-trust-site').addEventListener('click', clearAutoClose);
  document.getElementById('btn-block-blacklist').addEventListener('click', clearAutoClose);
})();
