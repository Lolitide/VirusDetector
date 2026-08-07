/**
 * 同步读取 localStorage 中缓存的主题和模式，在 CSS 加载前立即设置 data-theme 和 data-mode，
 * 避免页面首次渲染时出现深→浅色闪烁或侧边栏闪烁。
 * 当主题为 'auto' 时，通过 matchMedia 解析为实际深色/浅色。
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
    document.documentElement.setAttribute('data-mode', localStorage.getItem(UI.MODE) || 'basic');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.documentElement.setAttribute('data-mode', 'basic');
  }
  // display:none 由 body-sync.js 在所有 DOM 修正完成后解除
})();
