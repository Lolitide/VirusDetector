(function () {
  'use strict';

  function safeUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '';
    } catch {
      return '';
    }
  }

  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || '未知网站';
  const score = Math.max(0, parseInt(params.get('score'), 10) || 0);
  const correctUrl = safeUrl(params.get('correctUrl') || '');

  document.getElementById('report-domain').textContent = domain;
  document.getElementById('report-score').textContent = String(score);
  document.getElementById('report-time').textContent = new Date().toLocaleString('zh-CN');

  if (correctUrl) {
    document.getElementById('official-section').hidden = false;
    document.getElementById('official-domain').textContent = correctUrl;
    document.getElementById('official-link').href = correctUrl;
  }

  document.getElementById('btn-close-report').addEventListener('click', () => window.close());
  document.getElementById('btn-back-safe').addEventListener('click', async () => {
    if (correctUrl) await chrome.tabs.create({ url: correctUrl, active: true });
    window.close();
  });

  const falsePositiveButton = document.getElementById('btn-report-false');
  falsePositiveButton.addEventListener('click', async () => {
    falsePositiveButton.disabled = true;
    falsePositiveButton.textContent = '上报中…';
    try {
      await chrome.runtime.sendMessage({
        type: 'SUBMIT_REPORT',
        payload: { reportType: 'false_positive', domain, note: '' }
      });
      falsePositiveButton.textContent = '已上报为误报，感谢反馈';
    } catch {
      falsePositiveButton.disabled = false;
      falsePositiveButton.textContent = '上报失败，请重试';
    }
  });

  let remaining = 30;
  const countdown = document.getElementById('countdown');
  countdown.textContent = `本报告将在 ${remaining} 秒后自动关闭`;

  const timer = setInterval(() => {
    remaining -= 1;
    countdown.textContent = `本报告将在 ${remaining} 秒后自动关闭`;
    if (remaining > 0) return;
    clearInterval(timer);
    window.close();
  }, 1000);
})();
