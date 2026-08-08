/**
 * 同步读取 localStorage 中缓存的主题，在 CSS 加载前立即设置 data-theme。
 * 作为独立的外部脚本在 <head> 最顶部同步加载，确保零闪烁。
 * 不依赖 chrome.storage（异步），因为那会导致一帧深色残留。
 * 存储键名来自 window.VT_CONSTANTS.UI_KEYS（content-constants.js 注入，含字面量兜底）。
 */
(function () {
  try {
    var C = (typeof window !== 'undefined' && window.VT_CONSTANTS) || {};
    var UI = C.UI_KEYS || { THEME: 'vt_theme', MODE: 'vt_mode', ACTIVE_SECTION: 'vt_activeSection' };
    var t = localStorage.getItem(UI.THEME) || 'dark';
    if (t === 'auto') {
      t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
  document.documentElement.style.display = '';
})();
