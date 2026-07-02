/**
 * 银狐木马检测 - Popup UI (v2.2.4)
 * SVG图标系统 + 优化排版 + 白名单极简模式
 */
(function () {
  'use strict';

  const SCORE_THRESHOLD = 100;

  const $ = (id) => document.getElementById(id);

  // ==================== SVG 图标定义 ====================
  const ICONS = {
    // 绿色勾（通过）
    check: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#4CAF50"/><path d="M6 10l3 3 5-5" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    // 红色叉（触发）
    cross: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#F44336"/><path d="M7 7l6 6M13 7l-6 6" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>',
    // 灰色横线（不适用）
    dash: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="none" stroke="#757575" stroke-width="1.5"/><path d="M7 10h6" stroke="#757575" stroke-width="2" stroke-linecap="round"/></svg>',
    // 橙色感叹号（部分可疑）
    warn: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#FF9800"/><path d="M10 5v5M10 14v1" stroke="white" stroke-width="2.5" stroke-linecap="round"/></svg>',
    // 加载中（三点旋转）
    pending: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="none" stroke="#757575" stroke-width="1.5" stroke-dasharray="4 3"/></svg>',
    // 白名单星标按钮
    star: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2l3.1 6.3L22 9.3l-5 4.9 1.2 6.8-6.2-3.3-6.2 3.3 1.2-6.8-5-4.9 6.9-1z"/></svg>',
    // 白名单取消星标
    starOff: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="3" x2="21" y2="21"/><path d="M12 2l3.1 6.3L22 9.3l-5 4.9 1.2 6.8-6.2-3.3-6.2 3.3 1.2-6.8-5-4.9 6.9-1z"/></svg>',
    // 刷新
    refresh: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.5 9a9 9 0 0114.8-3.7L23 10M.5 15a9 9 0 0014.8 3.7L20 15"/></svg>',
    // 绿色大勾（白名单/安全分数）
    checkLarge: '<svg viewBox="0 0 24 24" width="44" height="44"><circle cx="12" cy="12" r="11" fill="#4CAF50"/><path d="M7 12l3 3 7-7" stroke="white" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  };

  const els = {
    header: $('header'), loading: $('loading'),
    safePanel: $('safe-panel'), warningPanel: $('warning-panel'),
    whitelistPanel: $('whitelist-panel'),
    scoreValue: $('score-value'), statusText: $('status-text'),
    currentDomain: $('current-domain'),
    riskLevelText: $('risk-level-text'),
    warningScoreValue: $('warning-score-value'),
    warningStatusText: $('warning-status-text'),
    officialLinkSection: $('official-link-section'),
    officialLinkBtn: $('official-link-btn'),
    officialLinkText: $('official-link-text'),
    safetyTips: $('safety-tips'),
    detailsSection: $('details-section'),
    refreshBtn: $('refresh-btn'),
    whitelistBtn: $('whitelist-btn'),
    // 刻度尺相关元素
    safeScoreIcon: $('safe-score-icon'),
    safeGaugeIndicator: $('safe-gauge-indicator'),
    warningScoreIcon: $('warning-score-icon'),
    warningGaugeIndicator: $('warning-gauge-indicator'),
    detailRules: {
      rule1: $('detail-rule1'), rule2: $('detail-rule2'),
      rule3: $('detail-rule3'), rule4: $('detail-rule4'),
      rule5: $('detail-rule5'),
      domainAge: $('detail-domainAge'), ageBonus: $('detail-ageBonus')
    }
  };

  // ==================== UI 状态切换 ====================

  function showLoading() {
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-safe';
    _resetDetailIcons();
  }

  function _resetDetailIcons() {
    for (const key of Object.keys(els.detailRules)) {
      const el = els.detailRules[key];
      if (!el) continue;
      const iconEl = el.querySelector('.detail-icon');
      const textEl = el.querySelector('.detail-text');
      iconEl.innerHTML = ICONS.pending;
      textEl.textContent = '待检测';
      textEl.className = 'detail-text neutral';
    }
  }

  // ==================== 刻度尺（Gauge）逻辑 ====================

  /**
   * 计算刻度尺指示器的水平位置百分比
   * 分段线性映射: 0→0%, 80→50%(中间), 100→75%(右四等分), 200→100%(最右)
   * 评分 >200 视为 200（封顶）
   */
  function calcGaugePosition(score) {
    const clamped = Math.max(0, Math.min(200, score));
    if (clamped <= 80) {
      return (clamped / 80) * 50;                // 0% → 50%
    } else if (clamped <= 100) {
      return 50 + ((clamped - 80) / 20) * 25;     // 50% → 75%
    } else {
      return 75 + ((clamped - 100) / 100) * 25;    // 75% → 100%
    }
  }

  /**
   * 获取评分对应的颜色区域
   * @returns {'green'|'yellow'|'red'}
   */
  function getScoreColorZone(score) {
    if (score < 80) return 'green';
    if (score < 100) return 'yellow';
    return 'red';
  }

  /** 安全面板对勾图标 SVG（颜色动态） */
  function buildCheckIconSvg(color) {
    return '<svg viewBox="0 0 24 24" width="44" height="44">' +
      '<circle cx="12" cy="12" r="11" fill="' + color + '"/>' +
      '<path d="M7 12l3 3 7-7" stroke="white" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>' +
      '</svg>';
  }

  /** 警告面板三角警告图标 SVG（颜色动态） */
  function buildWarningIconSvg(color) {
    return '<svg viewBox="0 0 24 24" width="44" height="44">' +
      '<path d="M12 2L1 22h22L12 2z" fill="' + color + '"/>' +
      '<path d="M12 10v4M12 17.5v.5" stroke="white" stroke-width="2.5" stroke-linecap="round"/>' +
      '</svg>';
  }

  /**
   * 动态更新评分卡片的颜色、图标、刻度尺指示器
   * @param {HTMLElement} scoreValueEl  评分数字元素
   * @param {HTMLElement} gaugeIndEl    刻度尺指示器容器
   * @param {HTMLElement} scoreIconEl   图标容器（可选，仅安全面板）
   * @param {number}      score         评分值
   * @param {boolean}     isWarning     是否为警告面板
   */
  function updateScoreDisplay(scoreValueEl, gaugeIndEl, scoreIconEl, score, isWarning) {
    const zone = getScoreColorZone(score);

    // 1. 更新评分数字颜色
    scoreValueEl.classList.remove('safe-color', 'warn-color', 'danger-color');
    scoreValueEl.classList.add(
      zone === 'green' ? 'safe-color' : zone === 'yellow' ? 'warn-color' : 'danger-color'
    );

    // 2. 更新图标颜色
    if (scoreIconEl) {
      const iconColorMap = { green: '#4CAF50', yellow: '#FF9800', red: '#F44336' };
      const color = iconColorMap[zone];
      if (isWarning) {
        scoreIconEl.innerHTML = buildWarningIconSvg(color);
      } else {
        scoreIconEl.innerHTML = buildCheckIconSvg(color);
      }
    }

    // 3. 更新刻度尺指示器位置
    const position = calcGaugePosition(score);
    gaugeIndEl.style.left = position + '%';

    // 4. 更新刻度尺指示器颜色
    const arrow = gaugeIndEl.querySelector('.gauge-arrow');
    if (arrow) {
      arrow.classList.remove('arrow-green', 'arrow-yellow', 'arrow-red');
      arrow.classList.add('arrow-' + zone);
    }
  }

  function updateWhitelistButton(isWhitelisted) {
    if (isWhitelisted) {
      els.whitelistBtn.innerHTML = ICONS.starOff + '移出白名单';
      els.whitelistBtn.classList.add('active');
    } else {
      els.whitelistBtn.innerHTML = ICONS.star + '加入白名单';
      els.whitelistBtn.classList.remove('active');
    }
  }

  function showSafe(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'block';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-safe';
    var score = data.score || 0;
    els.scoreValue.textContent = score;
    // 动态更新评分卡片（颜色、图标、刻度尺指示器）
    updateScoreDisplay(els.scoreValue, els.safeGaugeIndicator, els.safeScoreIcon, score, false);
    els.statusText.textContent = '安全';
    els.currentDomain.textContent = data.domain || '-';
    els.riskLevelText.textContent = '正常';
    els.riskLevelText.className = 'info-value safe-text';
  }

  function showWhitelisted(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'block';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'none';
    els.header.className = 'header-whitelist';
  }

  function showWarning(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'block';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'block';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-danger';
    var score = data.score || 0;
    els.warningScoreValue.textContent = score;
    // 动态更新评分卡片（颜色、图标、刻度尺指示器）
    updateScoreDisplay(els.warningScoreValue, els.warningGaugeIndicator, els.warningScoreIcon, score, true);
    els.warningStatusText.textContent = '危险警告';

    if (data.correctUrl) {
      els.officialLinkSection.style.display = 'block';
      els.officialLinkBtn.href = data.correctUrl;
      els.officialLinkText.textContent = data.correctUrl;
    } else {
      els.officialLinkSection.style.display = 'none';
    }
  }

  // ==================== 检测详情更新（SVG图标，基于 rule.status 字段判定） ====================

  function updateDetails(ruleResults) {
    if (!ruleResults) return;
    for (const key of Object.keys(els.detailRules)) {
      const rule = ruleResults[key];
      const el = els.detailRules[key];
      if (!el) continue;
      const iconEl = el.querySelector('.detail-icon');
      const textEl = el.querySelector('.detail-text');

      if (!rule || !rule.detailCN) {
        iconEl.innerHTML = ICONS.pending;
        textEl.textContent = '待检测';
        textEl.className = 'detail-text neutral';
        continue;
      }

      // 根据 rule.status 字段确定图标（不再依赖 detailCN 文本前缀）
      if (rule.triggered && key === 'ageBonus') {
        // 域名年龄减分触发是正面信号（抵消可疑分数），显示绿色对勾
        iconEl.innerHTML = ICONS.check;
        textEl.textContent = rule.detailCN;
        textEl.className = 'detail-text passed';
      } else if (rule.triggered) {
        iconEl.innerHTML = ICONS.cross;
        textEl.textContent = rule.detailCN;
        textEl.className = 'detail-text triggered';
      } else if (rule.status === 'warn') {
        iconEl.innerHTML = ICONS.warn;
        textEl.textContent = rule.detailCN;
        textEl.className = 'detail-text neutral';
      } else if (rule.status === 'neutral') {
        iconEl.innerHTML = ICONS.dash;
        textEl.textContent = rule.detailCN;
        textEl.className = 'detail-text neutral';
      } else {
        // status === 'pass' 或 undefined（向后兼容旧缓存数据）
        iconEl.innerHTML = ICONS.check;
        textEl.textContent = rule.detailCN;
        textEl.className = 'detail-text passed';
      }

      // —— ICP 备案号核验状态与查询链接 ——
      if (key === 'rule3') {
        // 移除旧的核验元素
        const oldBadge = el.querySelector('.icp-verify-badge');
        const oldLink = el.querySelector('.icp-query-link');
        if (oldBadge) oldBadge.remove();
        if (oldLink) oldLink.remove();

        if (rule && rule.icpVerified && rule.icpNumbers && rule.icpNumbers.length > 0) {
          // 已核验 → 显示工信部查询链接
          textEl.textContent = `ICP备案: 已检测到 (${rule.icpNumbers[0]})`;
          const linkEl = document.createElement('a');
          linkEl.className = 'icp-query-link';
          linkEl.href = 'https://beian.miit.gov.cn/';
          linkEl.target = '_blank';
          linkEl.rel = 'noopener noreferrer';
          linkEl.textContent = '工信部查询 ›';
          el.appendChild(linkEl);
        } else if (rule && rule.icpBlacklisted) {
          // 备案号疑似虚假
          const badge = document.createElement('span');
          badge.className = 'icp-verify-badge badge-fake';
          badge.textContent = '虚假备案';
          el.appendChild(badge);
        } else if (rule && rule.icpFound && !rule.icpVerified) {
          // 已找到但未核验
          const badge = document.createElement('span');
          badge.className = 'icp-verify-badge badge-unverified';
          badge.textContent = '未核验';
          el.appendChild(badge);
        }
      }
    }
  }

  function showError(msg) {
    els.loading.innerHTML = '<div style="text-align:center;padding:20px;">' +
      '<p style="color:#F44336;font-size:14px;">' +
      '<svg viewBox="0 0 20 20" width="14" height="14" style="vertical-align:middle;margin-right:4px;"><path d="M10 2L1 18h18L10 2z" fill="#F44336"/><path d="M10 7v4M10 14.5v.5" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>' +
      (msg || '无法获取检测结果') + '</p>' +
      '<p style="font-size:12px;color:#a0a0a0;margin-top:8px;">请确保已打开网页，点击"重新检测"重试</p></div>';
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.detailsSection.style.display = 'none';
  }

  // ==================== 数据获取 ====================

  async function fetchState() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', payload: {} });
      return (resp && resp.success) ? resp.data : null;
    } catch (e) { return null; }
  }

  async function requestReanalysis() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0) {
        await chrome.tabs.sendMessage(tabs[0].id, { type: 'REQUEST_PAGE_TEXT', payload: {} });
      }
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) { /* content script may not be ready */ }
  }

  // ==================== 主渲染 ====================

  async function render() {
    showLoading();
    let data = await fetchState();
    if (!data || !data.isAnalyzed) {
      await requestReanalysis();
      data = await fetchState();
    }
    if (!data) { showError('无法获取页面分析结果'); return; }

    // 白名单优先显示（极简模式：仅绿色勾，无文字无详情）
    if (data.isWhitelisted) {
      showWhitelisted(data);
      updateWhitelistButton(true);
      return;
    }

    if (data.score >= SCORE_THRESHOLD) {
      showWarning(data);
    } else {
      showSafe(data);
    }
    updateDetails(data.ruleResults);
    updateWhitelistButton(false);
  }

  // ==================== 按钮事件 ====================

  els.refreshBtn.addEventListener('click', async () => {
    showLoading();
    els.refreshBtn.innerHTML = ICONS.pending + '检测中...';
    els.refreshBtn.disabled = true;
    await requestReanalysis();
    await render();
    els.refreshBtn.innerHTML = ICONS.refresh + '重新检测';
    els.refreshBtn.disabled = false;
  });

  // 白名单按钮
  els.whitelistBtn.addEventListener('click', async () => {
    showLoading();
    els.whitelistBtn.disabled = true;
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) return;
      const url = tabs[0].url || '';

      // 先检查当前白名单状态
      const checkResp = await chrome.runtime.sendMessage({
        type: 'CHECK_WHITELIST',
        payload: { url }
      });
      const isCurrentlyWhitelisted = checkResp?.isWhitelisted || false;

      if (isCurrentlyWhitelisted) {
        await chrome.runtime.sendMessage({
          type: 'REMOVE_FROM_WHITELIST',
          payload: { url }
        });
      } else {
        await chrome.runtime.sendMessage({
          type: 'ADD_TO_WHITELIST',
          payload: { url }
        });
      }

      // 等待后台处理完成
      await new Promise(r => setTimeout(r, 400));
      await render();
    } catch (e) {
      console.error('[Popup] 白名单操作失败:', e);
    }
    els.whitelistBtn.disabled = false;
  });

  // ==================== 初始化 ====================

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    render();
  } else {
    document.addEventListener('DOMContentLoaded', render);
  }
})();
