/**
 * 同步读取 localStorage 中缓存的主题和模式，在 CSS 加载前立即设置 data-theme 和 data-mode，
 * 避免页面首次渲染时出现深→浅色闪烁或侧边栏闪烁。
 */
(function () {
  try {
    document.documentElement.setAttribute('data-theme', localStorage.getItem('vt_theme') || 'dark');
    document.documentElement.setAttribute('data-mode', localStorage.getItem('vt_mode') || 'basic');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.documentElement.setAttribute('data-mode', 'basic');
  }
  // display:none 由 body-sync.js 在所有 DOM 修正完成后解除
})();
