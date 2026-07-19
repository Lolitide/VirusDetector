/**
 * 同步读取 localStorage 中缓存的主题和模式，在 CSS 加载前立即设置 data-theme 和 data-mode，
 * 避免页面首次渲染时出现深→浅色闪烁或侧边栏闪烁。
 * 当主题为 'auto' 时，通过 matchMedia 解析为实际深色/浅色。
 */
(function () {
  try {
    var t = localStorage.getItem('vt_theme') || 'dark';
    if (t === 'auto') {
      t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', t);
    document.documentElement.setAttribute('data-mode', localStorage.getItem('vt_mode') || 'basic');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.documentElement.setAttribute('data-mode', 'basic');
  }
  // display:none 由 body-sync.js 在所有 DOM 修正完成后解除
})();
