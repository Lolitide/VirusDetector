(function () {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const correctUrl = params.get('correctUrl') || '';
  const officialButton = document.getElementById('official');
  const frameMessage = (action) => window.parent.postMessage({ source: 'virus-detector-overlay', action }, '*');

  document.getElementById('domain').textContent = params.get('domain') || '未知网站';
  document.getElementById('score').textContent = params.get('score') || '0';

  try {
    const url = new URL(correctUrl);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') officialButton.hidden = true;
  } catch (e) {
    officialButton.hidden = true;
  }

  document.getElementById('leave').addEventListener('click', () => frameMessage('leave'));
  officialButton.addEventListener('click', () => frameMessage('official'));
  document.getElementById('details-button').addEventListener('click', () => {
    document.getElementById('details').classList.toggle('visible');
  });

  const focusable = () => Array.from(document.querySelectorAll('button:not([hidden])'));
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const buttons = focusable();
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  document.getElementById('leave').focus();
})();
