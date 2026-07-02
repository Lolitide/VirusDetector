/**
 * 银狐木马检测 - 警告窗口控制器 (v2.2.4)
 *
 * 职责：
 * - 从 URL 参数读取检测结果并渲染警告界面
 * - 处理关闭危险页面、跳转安全页面的用户操作
 */
(function () {
  'use strict';

  // 从 URL 参数读取后台传入的检测结果
  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || '未知网站';
  const score = parseInt(params.get('score')) || 0;
  const correctUrl = params.get('correctUrl') || '';
  const officialName = params.get('officialName') || '';

  // 渲染基本信息
  document.getElementById('risk-score').textContent = score;
  document.getElementById('info-domain').textContent = domain;
  document.getElementById('info-time').textContent = new Date().toLocaleString('zh-CN');

  // 如果有正确的官方网站地址则展示链接区域
  if (correctUrl) {
    document.getElementById('official-section').style.display = 'block';
    document.getElementById('official-domain').textContent = correctUrl;
    document.getElementById('official-btn').href = correctUrl;
  }

  /**
   * 关闭匹配危险域名的所有标签页
   * @param {string} targetDomain - 需要关闭的域名
   * @returns {Promise<number>} 关闭的标签页数量
   */
  async function closeDangerousTabs(targetDomain) {
    try {
      // 去掉 www. 前缀以扩大匹配范围
      const cleanDomain = targetDomain.replace(/^www\./i, '');
      const allTabs = await chrome.tabs.query({});
      const targets = allTabs.filter(tab => {
        try {
          const host = new URL(tab.url || '').hostname.replace(/^www\./i, '');
          return host === cleanDomain || host.endsWith('.' + cleanDomain);
        } catch (e) { return false; }
      });

      if (targets.length > 0) {
        await chrome.tabs.remove(targets.map(t => t.id));
      }
      return targets.length;
    } catch (e) {
      console.error('[Warning] 关闭危险标签页失败:', e);
      return 0;
    }
  }

  /**
   * 打开安全页面
   * @param {string} url - 目标 URL
   */
  async function openSafePage(url) {
    try {
      // 在当前窗口创建一个新标签页打开安全页面
      const existingTabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (existingTabs.length > 0) {
        await chrome.tabs.create({ url, index: existingTabs[0].index + 1 });
      } else {
        await chrome.tabs.create({ url });
      }
    } catch (e) {
      console.error('[Warning] 打开安全页面失败:', e);
    }
  }

  // ---- 按钮事件 ----

  // 关闭此页面：关闭所有危险标签页，然后关闭警告弹窗
  document.getElementById('btn-close').addEventListener('click', async () => {
    await closeDangerousTabs(domain);
    window.close();
  });

  // 返回安全页面：先关闭所有危险标签页，再打开正确官网，最后关闭警告弹窗
  document.getElementById('btn-back-safe').addEventListener('click', async () => {
    clearAutoClose();
    await closeDangerousTabs(domain);
    await openSafePage(correctUrl || 'https://www.baidu.com');
    window.close();
  });

  // ---- 自动关闭 ----

  // 30 秒倒计时后自动关闭警告弹窗，用户点击任意按钮则取消倒计时
  const AUTO_CLOSE_SECONDS = 30;
  let remaining = AUTO_CLOSE_SECONDS;
  const countdownEl = document.getElementById('auto-close-countdown');

  function renderCountdown() {
    if (countdownEl) {
      countdownEl.textContent = `本提示将在 ${remaining} 秒后自动关闭`;
    }
  }

  function clearAutoClose() {
    clearInterval(autoCloseTimer);
    if (countdownEl) countdownEl.textContent = '';
  }

  renderCountdown();
  const autoCloseTimer = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearAutoClose();
      window.close();
      return;
    }
    renderCountdown();
  }, 1000);

  // 关闭按钮也取消倒计时（事件已绑定，补充清理）
  document.getElementById('btn-close').addEventListener('click', clearAutoClose);
})();
