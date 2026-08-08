/**
 * 控制高风险网页拦截页的主题、返回安全页面、AI 咨询、信任确认和报告入口。
 * 所有敏感操作均携带后台签发的 nonce，由 Service Worker 校验并执行。
 *
 * 职责：
 * - 从 URL 参数读取检测结果并渲染警告界面
 * - 处理关闭危险页面、跳转安全页面的用户操作
 *
 * 前置条件：
 * - 由 Service Worker 构造 URL 参数打开本页：domain、score、correctUrl、officialName
 *   （correctUrl 经 sanitizeUrl 协议白名单校验，仅允许 http/https，防 javascript: 注入）
 *
 * 输入与输出：
 * - 输入：URL 参数 + 用户操作（继续访问/关闭危险页面/前往官方）
 * - 副作用：关闭匹配危险域名（去 www. 前缀）的所有标签页、window.close() 自关；
 *   误报/钓鱼上报经 SUBMIT_REPORT 回传 SW 并延时自关（PHISH_CONFIRM_TIMEOUT_MS）
 */
import {
  MSG_TYPES, REPORT_TYPES, WARNING_AUTO_CLOSE_SECONDS, PHISH_CONFIRM_TIMEOUT_MS
} from '../utils/constants.js';

(function () {
  'use strict';

  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
  let selectedTheme = 'dark';

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
  const nonce = params.get('nonce') || '';
  const domain = params.get('domain') || '未知网站';
  const score = Math.max(0, parseInt(params.get('score'), 10) || 0);
  const correctUrl = sanitizeUrl(params.get('correctUrl') || '');
  const fallbackUrl = sanitizeUrl('https://' + domain);
  const originalUrl = sanitizeUrl(params.get('originalUrl') || '') || fallbackUrl;
  const reasons = (params.get('reasons') || '').trim();

  document.getElementById('risk-score').textContent = score;
  document.getElementById('info-domain').textContent = domain;
  document.getElementById('info-time').textContent = new Date().toLocaleString('zh-CN');

  // correctUrl 已经 sanitizeUrl 协议白名单验证；赋值前再显式校验一次（防御性双保险）
  const safeOfficialHref = /^https?:\/\//i.test(correctUrl) ? correctUrl : '';
  if (safeOfficialHref) {
    document.getElementById('official-section').style.display = 'block';
    document.getElementById('official-domain').textContent = safeOfficialHref;
    document.getElementById('official-btn').href = safeOfficialHref;
  }

  /**
   * @param {string} message 页面状态文字
   * @returns {void}
   */
  function setPageStatus(message) {
    pageStatusEl.textContent = message || '';
  }

  /** @returns {Promise<void>} */
  async function refreshBlockedState() {
    if (!originalUrl || accessRefreshRunning) return;
    accessRefreshRunning = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CHECK_WHITELIST',
        payload: { url: originalUrl }
      });
      if (response?.isWhitelisted) {
        setPageStatus('白名单已更新，正在继续访问');
        window.location.replace(originalUrl);
        return;
      }
    } catch {}
    accessRefreshRunning = false;
  }

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.whitelist) refreshBlockedState();
  });

  refreshBlockedState();

  /**
   * @param {string} url 目标网址
   * @returns {Promise<void>}
   */
  async function openSafePage(url) {
    try {
      const existingTabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (existingTabs.length > 0) {
        await chrome.tabs.create({ url, index: existingTabs[0].index + 1 });
      } else {
        await chrome.tabs.create({ url });
      }
    } catch (e) {
      console.error('[Warning] 打开安全页面失败:', e);
    }
  }

  // ---- 按钮事件 ----

  document.getElementById('btn-close').addEventListener('click', async () => {
    await closeDangerousTabs(domain);
    window.close();
  });

  // 仅当 correctUrl 通过 sanitizeUrl 验证后才打开，否则仅关闭危险标签页和弹窗
  document.getElementById('btn-back-safe').addEventListener('click', async () => {
    clearAutoClose();
    await closeDangerousTabs(domain);
    if (correctUrl) {
      await openSafePage(correctUrl);
    }
    window.close();
  });

  // ---- 自动关闭 ----

  // 30 秒倒计时后自动关闭警告弹窗，用户点击任意按钮则取消倒计时
  let remaining = WARNING_AUTO_CLOSE_SECONDS;
  const countdownEl = document.getElementById('auto-close-countdown');

  function renderCountdown() {
    if (countdownEl) {
      countdownEl.textContent = `本提示将在 ${remaining} 秒后自动关闭`;
    }
  }

  function clearAutoClose() {
    clearInterval(autoCloseTimer);
    if (countdownEl) countdownEl.textContent = '';
  }

  renderCountdown();
  const autoCloseTimer = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearAutoClose();
      window.close();
      return;
    }
    renderCountdown();
  }, 1000);

  // 关闭按钮也取消倒计时（事件已绑定，补充清理）
  document.getElementById('btn-close').addEventListener('click', clearAutoClose);

  // ---- 误报上报 ----
  const reportFalseBtn = document.getElementById('btn-report-false');
  if (reportFalseBtn) {
    reportFalseBtn.addEventListener('click', async () => {
      reportFalseBtn.disabled = true;
      reportFalseBtn.textContent = '上报中...';
      try {
        await chrome.runtime.sendMessage({
          type: MSG_TYPES.SUBMIT_REPORT,
          payload: { reportType: REPORT_TYPES.FALSE_POSITIVE, domain, note: '' }
        });
        reportFalseBtn.textContent = '✅ 已上报为误报，感谢反馈';
        setTimeout(() => window.close(), PHISH_CONFIRM_TIMEOUT_MS);
      } catch (e) {
        console.error('[Warning] 误报上报失败:', e);
        reportFalseBtn.textContent = '上报失败，请重试';
        reportFalseBtn.disabled = false;
      }
    });
  }

  /** @returns {Promise<void>} */
  async function returnToSafety() {
    setPageStatus('正在返回安全页面');
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'RETURN_TO_SAFETY',
        payload: { nonce }
      });
      if (!response?.success) throw new Error(response?.error || 'return_failed');
    } catch (error) {
      try {
        await moveCurrentTab(correctUrl || 'chrome://newtab/');
      } catch {
        window.close();
      }
    }
  }

  /** @returns {string} 发送给 AI 的风险询问文本 */
  function buildAiPrompt() {
    const shareableUrl = getShareableUrl(originalUrl);
    const lines = [
      '银狐木马检测扩展拦截了一个网站，请帮我判断它是否安全。',
      '网站：' + (shareableUrl || domain),
      '威胁评分：' + score + ' 分'
    ];
    if (reasons) lines.push('命中信号：' + reasons);
    lines.push('请分析它可能存在的风险，并告诉我是否应该继续访问。不要打开或执行该网站提供的文件。');
    return lines.join('\n');
  }

  /** @returns {Promise<void>} */
  async function askAi() {
    const prompt = buildAiPrompt();
    const doubaoUrl = 'https://www.doubao.com/chat/?q=' + encodeURIComponent(prompt);
    setPageStatus('正在打开豆包');

    try {
      await navigator.clipboard.writeText(prompt);
    } catch {}

    try {
      await chrome.tabs.create({ url: doubaoUrl, active: true });
      setPageStatus('');
    } catch (error) {
      setPageStatus('无法打开豆包，请稍后重试');
    }
  }

  /** @returns {Promise<void>} */
  async function trustSite() {
    if (!originalUrl) {
      dialogStatusEl.textContent = '无法确认原始网址，请返回安全页面';
      return;
    }

    confirmTrustButton.disabled = true;
    dialogStatusEl.textContent = '正在保存信任设置';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'TRUST_BLOCKED_SITE',
        payload: { nonce }
      });
      if (!response || response.success !== true) {
        throw new Error(response && response.error ? response.error : 'unknown_error');
      }
      window.location.replace(response.url);
    } catch (error) {
      confirmTrustButton.disabled = false;
      dialogStatusEl.textContent = '保存失败，请重试或返回安全页面';
    }
  }

  /** @returns {Promise<void>} */
  async function openReport() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'OPEN_BLOCKED_REPORT',
        payload: { nonce }
      });
      if (!response?.success) throw new Error(response?.error || 'report_failed');
    } catch (error) {
      setPageStatus('无法打开报告，请稍后重试');
    }
  }

  document.getElementById('btn-back').addEventListener('click', returnToSafety);
  document.getElementById('btn-ask-ai').addEventListener('click', askAi);
  document.getElementById('btn-review-trust').addEventListener('click', () => {
    dialogStatusEl.textContent = '';
    trustDialog.showModal();
  });
  document.getElementById('btn-confirm-trust').addEventListener('click', trustSite);
  document.getElementById('btn-cancel-trust').addEventListener('click', returnToSafety);
  document.getElementById('btn-open-report').addEventListener('click', openReport);

  trustDialog.addEventListener('cancel', event => {
    event.preventDefault();
    returnToSafety();
  });
})();
