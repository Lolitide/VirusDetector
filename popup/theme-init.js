/**
 * 同步读取 localStorage 中缓存的主题，在 CSS 加载前立即设置 data-theme。
 * 作为独立的外部脚本在 <head> 最顶部同步加载，确保零闪烁。
 * 不依赖 chrome.storage（异步），因为那会导致一帧深色残留。
 */
(function () {
  try {
    var t = localStorage.getItem('vt_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
  document.documentElement.style.display = '';
})();
