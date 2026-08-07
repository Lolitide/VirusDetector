/**
 * 在 DOM 解析完成后、页面首次渲染前同步修正侧栏和模式控件的 active 状态。
 * 必须放在 </body> 之前的同步脚本中，确保 display:none 在一切就绪后才解除。
 * 存储键名来自 window.VT_CONSTANTS.UI_KEYS（content-constants.js 注入，含字面量兜底）。
 *
 * 输入与输出：
 *   - 输入：localStorage 中 ACTIVE_SECTION、MODE 键值，以及 HTML 内 .nav-item /
 *     .mode-segment 元素的 data-section / data-mode 属性
 *   - 输出：修正侧栏与模式分段控件的 active 类，并解除 documentElement 的
 *     display:none，页面可见
 */
(function () {
  var C = (typeof window !== 'undefined' && window.VT_CONSTANTS) || {};
  var UI = C.UI_KEYS || { THEME: 'vt_theme', MODE: 'vt_mode', ACTIVE_SECTION: 'vt_activeSection' };
  var ADVANCED_ONLY = C.ADVANCED_ONLY_SECTIONS || ['thresholds', 'download', 'blacklist'];
  // 修正侧栏激活项
  var activeId = localStorage.getItem(UI.ACTIVE_SECTION) || 'general';
  var mode = localStorage.getItem(UI.MODE) || 'basic';
  // 基础模式下不在高级专属分区
  if (mode === 'basic' && ADVANCED_ONLY.indexOf(activeId) !== -1) {
    activeId = 'general';
  }
  var navItems = document.querySelectorAll('.nav-item');
  for (var i = 0; i < navItems.length; i++) {
    navItems[i].classList.toggle('active', navItems[i].dataset.section === activeId);
  }
  // 修正模式分段控件
  var segs = document.querySelectorAll('.mode-segment');
  for (var j = 0; j < segs.length; j++) {
    segs[j].classList.toggle('active', segs[j].dataset.mode === mode);
  }
  // 一切就绪，显示页面
  document.documentElement.style.display = '';
})();
