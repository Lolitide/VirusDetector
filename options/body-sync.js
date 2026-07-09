/**
 * 在 DOM 解析完成后、页面首次渲染前同步修正侧栏和模式控件的 active 状态。
 * 必须放在 </body> 之前的同步脚本中，确保 display:none 在一切就绪后才解除。
 */
(function () {
  // 修正侧栏激活项
  var activeId = localStorage.getItem('vt_activeSection') || 'general';
  var mode = localStorage.getItem('vt_mode') || 'basic';
  // 基础模式下不在高级专属分区
  if (mode === 'basic' && ['thresholds', 'download', 'blacklist'].indexOf(activeId) !== -1) {
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
