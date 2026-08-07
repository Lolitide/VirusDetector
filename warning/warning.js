/**
 * 银狐木马检测 - 警告窗口控制器
 *
 * 职责：
 * - 从 URL 参数读取检测结果并渲染警告界面
 * - 处理关闭危险页面、跳转安全页面的用户操作
 *
 * 前置条件：
 * - 由 Service Worker 构造 URL 参数打开本页：domain、score、correctUrl、officialName
 *   （correctUrl 经 sanitizeUrl 协议白名单校验，仅允许 http/https，防 javascript: 注入）
 *
 * 输入与输出：
 * - 输入：URL 参数 + 用户操作（继续访问/关闭危险页面/前往官方）
 * - 副作用：关闭匹配危险域名（去 www. 前缀）的所有标签页、window.close() 自关；
 *   误报/钓鱼上报经 SUBMIT_REPORT 回传 SW 并延时自关（PHISH_CONFIRM_TIMEOUT_MS）
 */
import {
  MSG_TYPES, REPORT_TYPES, WARNING_AUTO_CLOSE_SECONDS, PHISH_CONFIRM_TIMEOUT_MS
} from '../utils/constants.js';

(function () {
  'use strict';

  /**
   * 验证 URL 协议，仅允许 http/https，防止 javascript: 等注入
   * 双重校验：URL 解析器协议白名单 + 显式 scheme 正则（防畸形输入与编码绕过）
   * @param {string} url
   * @returns {string} 安全 URL，无效时返回空字符串
   */
  function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed)) return '';
    try {
      const u = new URL(trimmed);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    } catch (e) { /* fall through */ }
    return trimmed;
  }

  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || '未知网站';
  const score = parseInt(params.get('score'), 10) || 0;
  const correctUrl = sanitizeUrl(params.get('correctUrl') || '');
  const officialName = params.get('officialName') || '';

  document.getElementById('risk-score').textContent = score;
  document.getElementById('info-domain').textContent = domain;
  document.getElementById('info-time').textContent = new Date().toLocaleString('zh-CN');

  // correctUrl 已经 sanitizeUrl 协议白名单验证；赋值前再显式校验一次（防御性双保险）
  const safeOfficialHref = /^https?:\/\//i.test(correctUrl) ? correctUrl : '';
  if (safeOfficialHref) {
    document.getElementById('official-section').style.display = 'block';
    document.getElementById('official-domain').textContent = safeOfficialHref;
    document.getElementById('official-btn').href = safeOfficialHref;
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

  document.getElementById('btn-close').addEventListener('click', async () => {
    await closeDangerousTabs(domain);
    window.close();
  });

  // 仅当 correctUrl 通过 sanitizeUrl 验证后才打开，否则仅关闭危险标签页和弹窗
  document.getElementById('btn-back-safe').addEventListener('click', async () => {
    clearAutoClose();
    await closeDangerousTabs(domain);
    if (correctUrl) {
      await openSafePage(correctUrl);
    }
    window.close();
  });

  // ---- 自动关闭 ----

  // 30 秒倒计时后自动关闭警告弹窗，用户点击任意按钮则取消倒计时
  let remaining = WARNING_AUTO_CLOSE_SECONDS;
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

  // ---- 误报上报 ----
  const reportFalseBtn = document.getElementById('btn-report-false');
  if (reportFalseBtn) {
    reportFalseBtn.addEventListener('click', async () => {
      reportFalseBtn.disabled = true;
      reportFalseBtn.textContent = '上报中...';
      try {
        await chrome.runtime.sendMessage({
          type: MSG_TYPES.SUBMIT_REPORT,
          payload: { reportType: REPORT_TYPES.FALSE_POSITIVE, domain, note: '' }
        });
        reportFalseBtn.textContent = '✅ 已上报为误报，感谢反馈';
        setTimeout(() => window.close(), PHISH_CONFIRM_TIMEOUT_MS);
      } catch (e) {
        console.error('[Warning] 误报上报失败:', e);
        reportFalseBtn.textContent = '上报失败，请重试';
        reportFalseBtn.disabled = false;
      }
    });
  }
})();
