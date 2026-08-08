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
import {
  MSG_TYPES, REPORT_TYPES, DOWNLOAD_CONFIRM_ACTIONS, CONFIRM_AUTO_CLOSE_SECONDS
} from '../utils/constants.js';

(function () {
  'use strict';

  /**
   * 验证 URL 协议，仅允许 http/https，防止 javascript: 等注入
   * 双重校验：URL 解析器协议白名单 + 显式 scheme 正则（防畸形输入与编码绕过）
   * @param {string} url
   * @returns {string} 安全 URL，无效时返回空字符串
   */
  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed)) return '';
    try {
      const u = new URL(trimmed);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    } catch (e) { /* fall through */ }
    return trimmed;
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

  document.getElementById('risk-score').textContent = score;
  document.getElementById('info-filename').textContent = filename;
  document.getElementById('info-download-domain').textContent = downloadDomain;
  document.getElementById('info-page-domain').textContent = domain;

  const trustDesc = document.getElementById('trust-desc');
  if (trustDesc) {
    trustDesc.textContent = '将 ' + domain + ' 加入白名单，此后不再拦截';
  }

  const blockDesc = document.getElementById('block-desc');
  if (blockDesc) {
    blockDesc.textContent = '将 ' + downloadDomain + ' 标记为恶意下载域名，跨站免疫';
  }

  // correctUrl 已经 sanitizeUrl 协议白名单验证；赋值前再显式校验一次（防御性双保险）
  const safeOfficialHref = /^https?:\/\//i.test(correctUrl) ? correctUrl : '';
  if (safeOfficialHref) {
    document.getElementById('official-section').style.display = 'block';
    document.getElementById('official-domain').textContent = safeOfficialHref;
    document.getElementById('official-btn').href = safeOfficialHref;
  }

  /**
   * 向 Service Worker 发送用户选择并关闭窗口
   * @param {string} action - DOWNLOAD_CONFIRM_ACTIONS 枚举值
   */
  async function sendChoice(action) {
    try {
      await chrome.runtime.sendMessage({
        type: MSG_TYPES.DOWNLOAD_CONFIRMATION,
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

      if (action === DOWNLOAD_CONFIRM_ACTIONS.TRUST_SITE) {
        // 信任网站 = 用户认为这是误报
        chrome.runtime.sendMessage({
          type: MSG_TYPES.SUBMIT_REPORT,
          payload: { reportType: REPORT_TYPES.FALSE_POSITIVE, domain, note: '下载确认中信任网站' }
        }).catch(() => {});
      } else if (action === DOWNLOAD_CONFIRM_ACTIONS.BLOCK_BLACKLIST) {
        // 拉黑下载域名 = 用户确认威胁
        chrome.runtime.sendMessage({
          type: MSG_TYPES.SUBMIT_REPORT,
          payload: { reportType: REPORT_TYPES.CONFIRMED_PHISH, domain, note: '下载确认中拉黑下载域名: ' + downloadDomain }
        }).catch(() => {});
      }
    } catch (e) {
      console.error('[DownloadConfirm] 发送确认消息失败:', e);
    }
    window.close();
  }

  // ---- 按钮事件 ----

  document.getElementById('btn-allow-once').addEventListener('click', () => {
    sendChoice(DOWNLOAD_CONFIRM_ACTIONS.ALLOW_ONCE);
  });

  document.getElementById('btn-trust-site').addEventListener('click', () => {
    sendChoice(DOWNLOAD_CONFIRM_ACTIONS.TRUST_SITE);
  });

  document.getElementById('btn-block-blacklist').addEventListener('click', () => {
    sendChoice(DOWNLOAD_CONFIRM_ACTIONS.BLOCK_BLACKLIST);
  });

  // ---- 自动关闭 ----

  // 60 秒倒计时后自动关闭（比警告窗口更长，给用户足够时间决策）
  let remaining = CONFIRM_AUTO_CLOSE_SECONDS;
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

  document.getElementById('btn-allow-once').addEventListener('click', clearAutoClose);
  document.getElementById('btn-trust-site').addEventListener('click', clearAutoClose);
  document.getElementById('btn-block-blacklist').addEventListener('click', clearAutoClose);
})();
