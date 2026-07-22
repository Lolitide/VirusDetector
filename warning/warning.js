/**
 * 银狐木马检测拦截页控制器。
 * 负责安全回退、向豆包携带上下文提问，以及二次确认后的白名单放行。
 */
(function () {
  'use strict';

  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : '';
    } catch (error) {
      return '';
    }
  }

  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || '未知网站';
  const score = Math.max(0, parseInt(params.get('score'), 10) || 0);
  const correctUrl = sanitizeUrl(params.get('correctUrl') || '');
  const fallbackUrl = sanitizeUrl('https://' + domain);
  const originalUrl = sanitizeUrl(params.get('originalUrl') || '') || fallbackUrl;
  const reasons = (params.get('reasons') || '').trim();
  const historySteps = Math.min(2, Math.max(1, parseInt(params.get('historySteps'), 10) || 1));

  const domainEl = document.getElementById('info-domain');
  const dialogDomainEl = document.getElementById('dialog-domain');
  const scoreEl = document.getElementById('risk-score');
  const pageStatusEl = document.getElementById('page-status');
  const dialogStatusEl = document.getElementById('dialog-status');
  const trustDialog = document.getElementById('trust-dialog');
  const confirmTrustButton = document.getElementById('btn-confirm-trust');

  domainEl.textContent = domain;
  dialogDomainEl.textContent = domain;
  scoreEl.textContent = String(score);

  function setPageStatus(message) {
    pageStatusEl.textContent = message || '';
  }

  async function moveCurrentTab(url) {
    const currentTab = await chrome.tabs.getCurrent();
    if (currentTab && currentTab.id) {
      await chrome.tabs.update(currentTab.id, { url });
      return;
    }
    window.location.replace(url);
  }

  async function returnToSafety() {
    setPageStatus('正在返回安全页面');

    if (window.history.length > historySteps) {
      window.history.go(-historySteps);
      return;
    }

    try {
      await moveCurrentTab(correctUrl || 'chrome://newtab/');
    } catch (error) {
      window.close();
    }
  }

  function buildAiPrompt() {
    const lines = [
      '银狐木马检测扩展拦截了一个网站，请帮我判断它是否安全。',
      '网站：' + (originalUrl || domain),
      '威胁评分：' + score + ' 分'
    ];
    if (reasons) lines.push('命中信号：' + reasons);
    lines.push('请分析它可能存在的风险，并告诉我是否应该继续访问。不要打开或执行该网站提供的文件。');
    return lines.join('\n');
  }

  async function askAi() {
    const prompt = buildAiPrompt();
    const doubaoUrl = 'https://www.doubao.com/chat/?q=' + encodeURIComponent(prompt);
    setPageStatus('正在打开豆包，问题已复制');

    try {
      await navigator.clipboard.writeText(prompt);
    } catch (error) {
      // URL 仍会携带问题，剪贴板仅作为兼容兜底。
    }

    try {
      await chrome.tabs.create({ url: doubaoUrl, active: true });
      setPageStatus('');
    } catch (error) {
      setPageStatus('无法打开豆包，请稍后重试');
    }
  }

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
        payload: { url: originalUrl, domain, score }
      });
      if (!response || response.success !== true) {
        throw new Error(response && response.error ? response.error : 'unknown_error');
      }
      window.location.replace(originalUrl);
    } catch (error) {
      confirmTrustButton.disabled = false;
      dialogStatusEl.textContent = '保存失败，请重试或返回安全页面';
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

  trustDialog.addEventListener('cancel', event => {
    event.preventDefault();
    returnToSafety();
  });
})();
