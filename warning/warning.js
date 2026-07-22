/**
 * 控制高风险网页拦截页的主题、返回安全页面、AI 咨询、信任确认和报告入口。
 * 所有敏感操作均携带后台签发的 nonce，由 Service Worker 校验并执行。
 *
 * @module warning-page
 */

(function () {
  'use strict';

  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
  let selectedTheme = 'dark';

  /**
   * @param {string} theme 主题设置
   * @returns {'light'|'dark'|'auto'} 规范化主题
   */
  function normalizeTheme(theme) {
    return theme === 'light' || theme === 'auto' ? theme : 'dark';
  }

  /**
   * 应用扩展主题并保存用户选择。
   * @param {'light'|'dark'|'auto'} theme 主题设置
   * @returns {void}
   */
  function applyTheme(theme) {
    selectedTheme = normalizeTheme(theme);
    const resolvedTheme = selectedTheme === 'auto'
      ? (systemTheme.matches ? 'dark' : 'light')
      : selectedTheme;

    document.documentElement.dataset.theme = resolvedTheme;
    try {
      localStorage.setItem('vt_theme', selectedTheme);
    } catch {}
  }

  /** @returns {Promise<void>} */
  async function syncThemeFromSettings() {
    try {
      const stored = await chrome.storage.local.get('global_settings');
      const settings = stored && stored.global_settings ? stored.global_settings : {};
      applyTheme(settings.theme || 'dark');
    } catch (error) {
      applyTheme(selectedTheme);
    }
  }

  try {
    selectedTheme = normalizeTheme(localStorage.getItem('vt_theme'));
  } catch (error) {
    selectedTheme = 'dark';
  }

  syncThemeFromSettings();

  systemTheme.addEventListener('change', () => {
    if (selectedTheme === 'auto') applyTheme('auto');
  });

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes.global_settings) return;
    const settings = changes.global_settings.newValue || {};
    applyTheme(settings.theme || 'dark');
  });

  /**
   * @param {string} url 待校验网址
   * @returns {string} 安全的 HTTP(S) 网址；无效输入返回空字符串
   */
  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : '';
    } catch (error) {
      return '';
    }
  }

  /**
   * 仅返回站点 origin，避免向外部 AI 分享路径和查询参数。
   * @param {string} url 原始网址
   * @returns {string} 可分享的站点 origin
   */
  function getShareableUrl(url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
      return parsed.origin;
    } catch (error) {
      return '';
    }
  }

  const params = new URLSearchParams(window.location.search);
  const nonce = params.get('nonce') || '';
  const domain = params.get('domain') || '未知网站';
  const score = Math.max(0, parseInt(params.get('score'), 10) || 0);
  const correctUrl = sanitizeUrl(params.get('correctUrl') || '');
  const fallbackUrl = sanitizeUrl('https://' + domain);
  const originalUrl = sanitizeUrl(params.get('originalUrl') || '') || fallbackUrl;
  const reasons = (params.get('reasons') || '').trim();

  const domainEl = document.getElementById('info-domain');
  const dialogDomainEl = document.getElementById('dialog-domain');
  const pageStatusEl = document.getElementById('page-status');
  const dialogStatusEl = document.getElementById('dialog-status');
  const trustDialog = document.getElementById('trust-dialog');
  const confirmTrustButton = document.getElementById('btn-confirm-trust');
  let accessRefreshRunning = false;

  domainEl.textContent = domain;
  dialogDomainEl.textContent = domain;

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
  async function moveCurrentTab(url) {
    const currentTab = await chrome.tabs.getCurrent();
    if (currentTab && currentTab.id) {
      await chrome.tabs.update(currentTab.id, { url });
      return;
    }
    window.location.replace(url);
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
