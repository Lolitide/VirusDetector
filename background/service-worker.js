/**
 * Virus Detector — Service Worker (主协调器)
 *
 * 是整个扩展的中央调度模块，负责协调所有后台任务：
 *
 * @module service-worker
 * @version 2.2.4
 *
 * 核心职责：
 *   1. 页面导航监听 → 白名单检查 → 缓存查询 → 触发评分分析
 *   2. 评分汇总     → 徽章更新（绿/红/蓝） + 警告弹窗 + 下载拦截注入
 *   3. 下载监听     → 压缩包检测 → 取消下载 → 重新评分
 *   4. 消息路由     → 处理来自 Popup / Content Script 的 12 种消息类型
 *   5. 白名单管理   → 存储持久化 / 增删查 / 跳过检测 / 缓存清理
 *
 * 生命周期：
 *   - 安装/更新时自动初始化并清理过期缓存
 *   - 标签页关闭时自动清理对应状态
 *   - 5 秒冷却期内不重复触发警告（同标签页 / 同域名）
 */

import { ScoringEngine } from './scoring-engine.js';
import { DomainDatabase } from './domain-database.js';
import { CacheManager } from './cache-manager.js';
import { registerNonChineseBrandDomains } from './icp-utils.js';
import { UrlUtils } from '../utils/url-utils.js';
import {
  SCORE_THRESHOLD, RISK_LEVEL, MSG_TYPES,
  STORAGE_KEYS, CACHE_TTL
} from '../utils/constants.js';

// ==================== URL 协议守卫 ====================

/**
 * 判断 URL 是否应跳过分析（仅分析 http/https 协议）
 *
 * 修复历史误报：file://、data:、ftp:、view-source: 等协议的 URL
 *  - 没有可分析的主机名（hostname 为 ""）
 *  - 历史上所有 file:// 页面共享同一个空字符串缓存键 `domain_cache_`，
 *    一次恶意缓存会污染所有本地文件
 *  - Content Script 在 `<all_urls>` 下也会运行于 file:// 页面并发送数据
 *
 * @param {string} url
 * @returns {boolean} true 表示应跳过（不分析）
 */
function shouldSkipUrl(url) {
  if (!url || typeof url !== 'string') return true;
  try {
    const protocol = new URL(url).protocol;
    return protocol !== 'http:' && protocol !== 'https:';
  } catch (e) {
    return true; // 无法解析的 URL 视为应跳过
  }
}

// ==================== 缓存清洗 ====================

/**
 * 清理 ruleResults 中的瞬时事件数据，仅保留页面级检测结果供缓存使用。
 *
 * 被清除的字段：
 *   - downloadLink.whoisResult   （下载链接域名的 Whois 数据，非当前页面所有）
 *   - downloadLink.downloadDomain（下载链接的特定域名）
 *   - rule2.fileName            （下载的具体文件名，非页面固有属性）
 *
 * 分数不受影响（已在 CacheManager 的 score 字段中持久化）。
 *
 * @param {Object} ruleResults - 完整规则结果对象
 * @returns {Object} 清洗后的副本（不修改原对象）
 */
function sanitizeRuleResultsForCache(ruleResults) {
  if (!ruleResults) return {};
  // 浅拷贝 + 替换瞬时字段
  const sanitized = { ...ruleResults };

  // 清洗 downloadLink：只保留分数和触发状态，移除 whoisResult 和 downloadDomain
  if (sanitized.downloadLink && typeof sanitized.downloadLink === 'object') {
    sanitized.downloadLink = {
      ...sanitized.downloadLink,
      downloadDomain: '',
      whoisResult: null
    };
  }

  // 清洗 rule2：移除具体文件名
  if (sanitized.rule2 && typeof sanitized.rule2 === 'object') {
    sanitized.rule2 = {
      ...sanitized.rule2,
      fileName: null
    };
  }

  return sanitized;
}

// ==================== 模块初始化 ====================

// 将 domain-database 中所有非中国品牌的官方域名注册到 ICP 豁免白名单
(function initIcpExemptList() {
  const allEntries = DomainDatabase.getAllEntries();
  for (const entry of allEntries) {
    if (!entry.isChineseBrand && entry.officialDomains) {
      registerNonChineseBrandDomains(entry.officialDomains);
    }
  }
  console.log('[ServiceWorker] ICP豁免白名单已初始化');
})();

// ==================== 标签页状态管理 ====================

/**
 * 创建初始标签页状态对象
 * @returns {Object} 包含所有规则结果、下载状态、页面数据、白名单标志的初始状态
 */
function createTabState() {
  return {
    url: '', domain: '', score: 0, riskLevel: RISK_LEVEL.SAFE,
    isAnalyzed: false, correctUrl: null, officialName: null,
    ruleResults: {
      rule1: { score: 0, triggered: false, detailCN: '待检测' },
      rule2: { score: 0, triggered: false, detailCN: '待检测' },
      rule3: { score: 0, triggered: false, detailCN: '待检测' },
      rule4: { score: 0, triggered: false, detailCN: '待检测' },
      rule5: { score: 0, triggered: false, detailCN: '待检测' },
      domainAge: { score: 0, triggered: false, detailCN: '待检测' },
      ageBonus: { score: 0, triggered: false, detailCN: '待检测' },
      downloadLink: { score: 0, triggered: false, detailCN: '待检测' }
    },
    pageText: '', icpStrings: [], pageMetrics: null, linkMetrics: null,
    downloadState: { hasDownloadedArchive: false, archiveFileName: null },
    lastAnalyzed: 0
  };
}

async function loadTabState(tabId) {
  try {
    const key = STORAGE_KEYS.TAB_STATE_PREFIX + tabId;
    const r = await chrome.storage.local.get(key);
    return r[key] || createTabState();
  } catch (e) { return createTabState(); }
}

async function saveTabState(tabId, s) {
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.TAB_STATE_PREFIX + tabId]: s });
  } catch (e) { /* ignore */ }
}

async function clearTabState(tabId) {
  try {
    await chrome.storage.local.remove(STORAGE_KEYS.TAB_STATE_PREFIX + tabId);
  } catch (e) { /* ignore */ }
}

// ==================== 工具栏图标与徽章更新 ====================
// 使用统一的护盾图标，仅通过右下角徽章（badge）的颜色和文字区分状态：
//   setIconGreen  → 绿色底 + 分数数字 = 安全
//   setIconRed    → 红色底 + "!"      = 危险
//   setIconWhitelist → 蓝色底 + "✓"   = 白名单
//   resetIcon     → 清除徽章          = 内部页面 / 未分析

/** 危险状态：红色底 + "!" 徽章 */
function setIconRed(tabId) {
  chrome.action.setBadgeText({ tabId, text: '!' }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#F44336' }).catch(() => {});
}

/** 安全状态：绿色底 + 分数数字徽章 */
function setIconGreen(tabId, score) {
  chrome.action.setBadgeText({ tabId, text: String(score || 0) }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#4CAF50' }).catch(() => {});
}

/** 重置：清除徽章文字 */
function resetIcon(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
}

/** 白名单状态：蓝色底 + "✓" 徽章 */
function setIconWhitelist(tabId) {
  chrome.action.setBadgeText({ tabId, text: '✓' }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#2196F3' }).catch(() => {});
}

// ==================== 白名单管理 ====================
// 白名单存储在 chrome.storage.local 中，键名为 STORAGE_KEYS.WHITELIST
// 数据结构：string[] — 域名列表（不含协议和路径，如 "example.com"）
// 白名单中的域名完全跳过 5 规则检测，工具栏图标显示蓝色 "✓" 徽章
//
// 性能优化：内存缓存 + storage.onChanged 失效机制，避免每次操作都读存储。

/** @type {Set<string>|null} 内存缓存的白名单域名集合 */
let _whitelistCache = null;

/**
 * 从存储加载白名单（优先返回内存缓存）
 * @returns {Promise<string[]>}
 */
async function loadWhitelist() {
  if (_whitelistCache) {
    return [..._whitelistCache];
  }
  try {
    const r = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
    const list = r[STORAGE_KEYS.WHITELIST] || [];
    _whitelistCache = new Set(list);
    return list;
  } catch (e) { return []; }
}

/** 使白名单内存缓存失效，下次 loadWhitelist 重新从存储读取 */
function _invalidateWhitelistCache() {
  _whitelistCache = null;
}

async function saveWhitelist(whitelist) {
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist });
    // 同步更新内存缓存
    _whitelistCache = new Set(whitelist);
  } catch (e) { /* ignore */ }
}

/**
 * 检查URL对应域名是否在白名单中
 * 优化：优先 O(1) 内存缓存查找，避免每次异步读存储
 */
async function isWhitelisted(url) {
  const domain = UrlUtils.extractHostname(url);
  if (_whitelistCache) {
    return _whitelistCache.has(domain);
  }
  const whitelist = await loadWhitelist();
  return whitelist.includes(domain);
}

/**
 * 将域名加入白名单
 */
async function addToWhitelist(url) {
  const domain = UrlUtils.extractHostname(url);
  // 先用内存缓存快速判断，避免无谓的存储读取
  if (_whitelistCache && _whitelistCache.has(domain)) {
    console.log('[ServiceWorker] 域名已在白名单:', domain);
    return;
  }
  const whitelist = await loadWhitelist();
  if (!whitelist.includes(domain)) {
    whitelist.push(domain);
    await saveWhitelist(whitelist);
    console.log('[ServiceWorker] 已加入白名单:', domain);
  }
}

/**
 * 将域名从白名单移除
 */
async function removeFromWhitelist(url) {
  const domain = UrlUtils.extractHostname(url);
  const whitelist = await loadWhitelist();
  const idx = whitelist.indexOf(domain);
  if (idx !== -1) {
    whitelist.splice(idx, 1);
    await saveWhitelist(whitelist);
    console.log('[ServiceWorker] 已移出白名单:', domain);
  }
}

// ==================== 高危响应流程 ====================

// 去重：每个标签页的警告冷却期（5秒内不重复弹窗）
const _warningCooldown = new Map();
const WARNING_COOLDOWN_MS = 5000;

/**
 * 触发高危响应：
 * 1. 图标变红（总是执行）
 * 2. 注入下载拦截脚本（仅首次）
 * 3. 弹出系统通知（5秒冷却）
 * 4. 创建警告窗口（5秒冷却，同域名不重复）
 */
async function triggerWarningFlow(tabId, tabState) {
  const domain = tabState.domain;
  const score = tabState.score;
  const correctUrl = tabState.correctUrl;
  const now = Date.now();

  // 1. 图标即时变红（总是执行）
  setIconRed(tabId);

  // 2. 注入下载拦截脚本（仅首次，避免重复注入）
  await injectDownloadBlocker(tabId);

  // 去重检查：同标签页冷却期内跳过通知和弹窗
  const lastTime = _warningCooldown.get(tabId) || 0;
  if (now - lastTime < WARNING_COOLDOWN_MS) {
    console.log('[ServiceWorker] ⚠️ 冷却期内，跳过重复弹窗:', domain);
    return;
  }
  _warningCooldown.set(tabId, now);

  // 3. 桌面通知
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '⚠️ 银狐木马检测 - 风险警告',
    message: `检测到疑似钓鱼网站: ${domain}\n风险评分: ${score}分${correctUrl ? '\n正确官网: ' + correctUrl : ''}`,
    priority: 2,
    buttons: correctUrl ? [{ title: '✅ 前往官网' }] : [],
    requireInteraction: true
  }).catch(() => {});

  // 4. 创建警告窗口（同域名去重）
  openWarningWindow(tabState);

  console.log('[ServiceWorker] ⚠️ 高危响应已触发:', { domain, score, correctUrl });
}

/**
 * 注入下载拦截脚本
 */
async function injectDownloadBlocker(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        // 避免重复注入
        if (window.__virusDetectorInjected) return;
        window.__virusDetectorInjected = true;

        // 移除所有链接的download属性
        document.querySelectorAll('a[download]').forEach(a => a.removeAttribute('download'));

        // 拦截可能导致下载的点击
        const DANGEROUS_EXTS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz',
          '.bz2', '.xz', '.iso', '.cab', '.arj', '.exe', '.msi', '.dmg', '.apk',
          '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar', '.appx', '.deb', '.rpm'];

        // 下载相关中英文关键词（用于匹配按钮文本）
        const DOWNLOAD_KEYWORDS = [
          '下载', 'download', '下載', 'ダウンロード',
          '立即安装', '立即下载', '免费下载', '高速下载', '安全下载',
          '点击下载', '直接下载', '本地下载', '官方下载',
          'Download Now', 'Free Download', 'Download Free',
          'install', 'setup', 'get started'
        ];

        /**
         * 检查元素是否带有下载意图
         */
        function hasDownloadIntent(el) {
          const text = (el.textContent || '').toLowerCase().trim();
          const aria = (el.getAttribute('aria-label') || '').toLowerCase();
          const title = (el.getAttribute('title') || '').toLowerCase();
          const combined = text + ' ' + aria + ' ' + title;

          return DOWNLOAD_KEYWORDS.some(kw => combined.includes(kw.toLowerCase()));
        }

        // 全局点击拦截
        document.addEventListener('click', function(e) {
          const target = e.target.closest('a, button, [role="button"], [onclick]');
          if (!target) return;

          let shouldBlock = false;

          // 检查1: href指向危险扩展名
          if (target.tagName === 'A' && target.href) {
            const href = target.href.toLowerCase();
            if (DANGEROUS_EXTS.some(ext => href.endsWith(ext))) {
              shouldBlock = true;
            }
          }

          // 检查2: 按钮或链接文本包含下载关键词
          if (!shouldBlock && hasDownloadIntent(target)) {
            shouldBlock = true;
          }

          // 检查3: 父级元素文本也包含下载关键词
          if (!shouldBlock) {
            const parent = target.closest('[class*="download"], [id*="download"], ' +
              '[class*="btn-dl"], [class*="btn_dl"]');
            if (parent) shouldBlock = true;
          }

          if (shouldBlock) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            alert('⚠️ 当前网站已被识别为危险网站，下载已被禁用。\n请前往官方网站下载安全版本。');
            return false;
          }
        }, true);

        // 页面加载后遍历并禁用现有的下载按钮
        function disableExistingDownloadButtons() {
          // 禁用所有带下载文本的<a>和<button>
          const allInteractive = document.querySelectorAll('a, button, [role="button"], input[type="submit"], input[type="button"]');
          for (const el of allInteractive) {
            if (hasDownloadIntent(el)) {
              el.style.pointerEvents = 'none';
              el.style.opacity = '0.5';
              el.style.cursor = 'not-allowed';
              el.title = '下载已被安全插件禁用';
              if (el.tagName === 'A') {
                el.removeAttribute('href');
                el.setAttribute('data-original-href', el.href || '');
              }
              el.setAttribute('disabled', 'disabled');
              el.classList.add('virus-detector-blocked');
            }
          }

          // 禁用常见的下载容器
          const downloadContainers = document.querySelectorAll(
            '[class*="download"], [id*="download"], ' +
            '[class*="btn-dl"], [class*="btn_dl"], ' +
            '[class*="down-btn"], [class*="down_btn"], ' +
            '.dl-btn, .dl_box, .down_url'
          );
          for (const container of downloadContainers) {
            const links = container.querySelectorAll('a, button');
            for (const link of links) {
              link.style.pointerEvents = 'none';
              link.style.opacity = '0.4';
              link.title = '下载已被安全插件禁用';
              if (link.tagName === 'A') link.removeAttribute('href');
              link.setAttribute('disabled', 'disabled');
            }
          }
        }

        // 初始执行
        disableExistingDownloadButtons();

        // 监听DOM变化（处理动态加载的下载按钮）
        const observer = new MutationObserver(() => {
          disableExistingDownloadButtons();
        });

        if (document.body) {
          observer.observe(document.body, { childList: true, subtree: true });
          // 30秒后停止观察
          setTimeout(() => observer.disconnect(), 30000);
        }

        // 添加半透明遮罩警告
        if (!document.getElementById('__virus_detector_overlay')) {
          const overlay = document.createElement('div');
          overlay.id = '__virus_detector_overlay';
          overlay.innerHTML = `
            <div style="position:fixed;top:0;left:0;right:0;z-index:2147483646;
              background:linear-gradient(135deg,#b71c1c,#c62828);color:#fff;
              text-align:center;padding:12px 20px;font-size:14px;font-weight:bold;
              font-family:-apple-system,BlinkMacSystemFont,'Microsoft YaHei',sans-serif;
              box-shadow:0 2px 12px rgba(183,28,28,0.5);">
              ⚠️ 风险警告：该网站被检测为疑似钓鱼/恶意网站，请勿输入个人信息或下载任何文件！
            </div>
          `;
          document.documentElement.appendChild(overlay);
        }
      },
      injectImmediately: true
    }).catch(e => console.error('[ServiceWorker] 注入拦截脚本失败:', e));
  } catch (e) {
    console.error('[ServiceWorker] 注入失败:', e);
  }
}

/**
 * 打开警告窗口
 */
// 记录上次弹窗的域名，避免同域名重复弹窗
let _lastWarningDomain = '';
let _lastWarningTime = 0;

function openWarningWindow(tabState) {
  const domain = tabState.domain || '';
  const now = Date.now();

  // 同域名冷却期内不重复弹窗
  if (domain === _lastWarningDomain && (now - _lastWarningTime) < WARNING_COOLDOWN_MS) {
    console.log('[ServiceWorker] 同域名弹窗冷却中，跳过:', domain);
    return;
  }
  _lastWarningDomain = domain;
  _lastWarningTime = now;

  const params = new URLSearchParams({
    domain: tabState.domain || '未知',
    score: String(tabState.score || 0),
    correctUrl: tabState.correctUrl || '',
    officialName: tabState.officialName || ''
  });

  chrome.windows.create({
    url: chrome.runtime.getURL('warning/warning.html?' + params.toString()),
    type: 'popup',
    width: 480,
    height: 560,
    focused: true
  }).catch(() => {
    chrome.tabs.create({
      url: chrome.runtime.getURL('warning/warning.html?' + params.toString())
    }).catch(() => {});
  });
}

// ==================== 页面分析 ====================

/**
 * 完整的页面分析流程
 */
async function analyzePage(tabId, url, domain, pageMetrics, linkMetrics) {
  // 防御性深度：所有进入分析入口的 URL 都先经协议守卫
  // 覆盖三个调用方：webNavigation、PAGE_ANALYSIS_RESULT 消息、REMOVE_FROM_WHITELIST
  if (shouldSkipUrl(url)) {
    console.log('[ServiceWorker] 跳过非 http(s) URL:', url);
    await CacheManager.remove('').catch(() => {});
    resetIcon(tabId);
    await clearTabState(tabId);
    return;
  }

  let tabState = await loadTabState(tabId);

  // 白名单检查：如果在白名单中，跳过所有检测
  if (await isWhitelisted(url)) {
    console.log('[ServiceWorker] 网站已在白名单中，跳过检测:', domain);
    tabState.isAnalyzed = true;
    tabState.isWhitelisted = true;
    tabState.url = url;
    tabState.domain = domain;
    tabState.score = 0;
    tabState.riskLevel = RISK_LEVEL.SAFE;
    await saveTabState(tabId, tabState);
    setIconWhitelist(tabId);
    return;
  }

  tabState.isWhitelisted = false;

  // 是否有来自 Content Script 的新数据
  const hasFreshData = !!(pageMetrics || linkMetrics);

  // 缓存检查（仅当无新数据时才使用缓存，避免用不含规则四/五的结果拦截更新）
  if (!hasFreshData) {
    const cached = await CacheManager.get(domain);
    if (cached) {
      console.log('[ServiceWorker] 使用缓存结果:', domain, cached.score);
      tabState.score = cached.score;
      tabState.riskLevel = cached.isMalicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;
      tabState.isAnalyzed = true;
      tabState.correctUrl = cached.correctUrl;
      tabState.ruleResults = cached.ruleResults || tabState.ruleResults;
      tabState.lastAnalyzed = Date.now();
      tabState.url = url;
      tabState.domain = domain;

      await saveTabState(tabId, tabState);

      if (cached.isMalicious) {
        setIconRed(tabId);
        await injectDownloadBlocker(tabId);
      } else {
        setIconGreen(tabId, cached.score);
      }
      return;
    }
  }

  // 构建页面上下文（不再需要SSL检测）
  const ctx = {
    url: tabState.url || url,
    domain: tabState.domain || domain,
    pageText: tabState.pageText || '',
    icpStrings: tabState.icpStrings || [],
    hasIcpGovLink: tabState.hasIcpGovLink || false,
    linkMetrics: linkMetrics || tabState.linkMetrics || null,
    downloadState: tabState.downloadState || { hasDownloadedArchive: false },
    pageMetrics: pageMetrics || tabState.pageMetrics || null
  };

  // 运行评分引擎
  try {
    const evalResult = await ScoringEngine.evaluate(ctx);

    tabState.score = evalResult.totalScore;
    tabState.riskLevel = evalResult.riskLevel;
    tabState.ruleResults = evalResult.breakdown;
    tabState.correctUrl = evalResult.correctUrl;
    tabState.officialName = evalResult.officialName;
    tabState.isAnalyzed = true;
    tabState.lastAnalyzed = Date.now();
    if (pageMetrics) tabState.pageMetrics = pageMetrics;
    if (linkMetrics) tabState.linkMetrics = linkMetrics;

    await saveTabState(tabId, tabState);

    // 写入缓存（清洗瞬时事件数据，防止缓存污染）
    await CacheManager.set(domain, {
      score: evalResult.totalScore,
      isMalicious: evalResult.isSuspicious,
      correctUrl: evalResult.correctUrl,
      ruleResults: sanitizeRuleResultsForCache(evalResult.breakdown)
    });

    // 根据分数执行响应
    if (evalResult.totalScore >= SCORE_THRESHOLD) {
      await triggerWarningFlow(tabId, tabState);
    } else {
      setIconGreen(tabId, evalResult.totalScore);
    }

    console.log('[ServiceWorker] 分析完成:', {
      domain, score: evalResult.totalScore,
      riskLevel: evalResult.riskLevel, cached: false
    });

  } catch (error) {
    console.error('[ServiceWorker] 评分失败:', error);
  }
}

// ==================== 事件监听 ====================

// 页面导航完成
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;

  // 内部浏览器页面 / 本地文件 / 非 http(s) 协议：直接跳过
  // （一次性清理空域名旧缓存，避免历史恶意缓存影响所有 file:// 页面）
  if (shouldSkipUrl(url)) {
    await CacheManager.remove('').catch(() => {});
    resetIcon(tabId);
    await clearTabState(tabId);
    return;
  }

  const domain = UrlUtils.extractHostname(url);
  let tabState = await loadTabState(tabId);
  tabState.url = url; tabState.domain = domain;
  tabState.downloadState = tabState.downloadState || { hasDownloadedArchive: false };
  tabState.isAnalyzed = false;
  await saveTabState(tabId, tabState);

  // 白名单检查：如果在白名单中，直接跳过分析
  if (await isWhitelisted(url)) {
    tabState.isAnalyzed = true;
    tabState.isWhitelisted = true;
    tabState.score = 0;
    tabState.riskLevel = RISK_LEVEL.SAFE;
    await saveTabState(tabId, tabState);
    setIconWhitelist(tabId);
    console.log('[ServiceWorker] 白名单网站，跳过检测:', domain);
    return;
  }

  // 启动分析（异步，不阻塞导航事件）
  analyzePage(tabId, url, domain, null, null).catch(e =>
    console.error('[ServiceWorker] analyzePage error:', e));
});

// 下载创建事件
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  try {
    // 三层检测：文件名 + URL路径 + MIME类型
    if (!ScoringEngine.isArchiveFile(downloadItem.filename, downloadItem.url, downloadItem.mime)) return;

    console.log('[ServiceWorker] 检测到压缩包下载:', downloadItem.filename);

    // 尝试找到源标签页：优先通过 referrer 匹配所有已打开的标签页
    let tabId = null;
    if (downloadItem.referrer) {
      try {
        const referrerUrl = new URL(downloadItem.referrer);
        const allTabs = await chrome.tabs.query({});
        const sourceTab = allTabs.find(tab => {
          try {
            return new URL(tab.url || '').hostname === referrerUrl.hostname;
          } catch (e) { return false; }
        });
        if (sourceTab) {
          tabId = sourceTab.id;
          console.log('[ServiceWorker] 通过referrer定位到源标签页:', sourceTab.url);
        }
      } catch (e) { /* referrer解析失败，回退到活跃标签页 */ }
    }

    // 回退：通过referrer未找到时，查询活跃标签页
    if (!tabId) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) {
        console.log('[ServiceWorker] 无法找到下载源标签页，跳过下载检测');
        return;
      }
      tabId = tabs[0].id;
    }

    const tabState = await loadTabState(tabId);

    // 白名单检查：白名单中的网站不拦截下载
    if (tabState.isWhitelisted) {
      console.log('[ServiceWorker] 白名单网站，跳过下载检测:', tabState.domain);
      return;
    }

    // 更新下载状态
    tabState.downloadState = {
      hasDownloadedArchive: true,
      archiveFileName: downloadItem.filename.split(/[\\/]/).pop(),
      downloadId: downloadItem.id,
      downloadUrl: downloadItem.url || ''
    };

    // 重新计算规则二（先使用现有tabState评分）
    let existingScore = Object.values(tabState.ruleResults)
      .reduce((sum, r) => sum + (r.score || 0), 0);

    // 竞态条件回退：如果 tabState 尚未分析完成（所有规则评分为0），从缓存补充
    if (!tabState.isAnalyzed || existingScore === 0) {
      const cached = await CacheManager.get(tabState.domain);
      if (cached && cached.ruleResults) {
        existingScore = Object.values(cached.ruleResults)
          .reduce((sum, r) => sum + (r.score || 0), 0);
        console.log('[ServiceWorker] 缓存回退：从CacheManager补充评分:', tabState.domain, existingScore);
      }
    }
    const rule2Result = ScoringEngine._evaluateRule2(tabState.downloadState, existingScore);

    tabState.ruleResults.rule2 = rule2Result;

    // 下载链接跨域检测（Whois API）：检查下载链接域名是否跨域及是否为新建域名
    const downloadLinkResult = await ScoringEngine.evaluateDownloadLink(
      downloadItem.url || '', tabState.domain || ''
    );
    tabState.ruleResults.downloadLink = downloadLinkResult;

    // 重新计算总分（包含所有规则 + 下载链接跨域检测）
    const newScore = Object.values(tabState.ruleResults)
      .reduce((sum, r) => sum + (r.score || 0), 0);
    tabState.score = newScore;
    tabState.riskLevel = newScore >= SCORE_THRESHOLD ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;

    await saveTabState(tabId, tabState);

    // 分数达标 → 取消下载 + 高危响应
    if (newScore >= SCORE_THRESHOLD) {
      // 取消下载
      try {
        await chrome.downloads.cancel(downloadItem.id);
        console.log('[ServiceWorker] 已取消危险下载:', downloadItem.filename);
      } catch (e) {
        console.error('[ServiceWorker] 取消下载失败:', e);
      }

      // 更新缓存（清洗瞬时事件数据，防止缓存污染）
      await CacheManager.set(tabState.domain, {
        score: newScore, isMalicious: true,
        correctUrl: tabState.correctUrl,
        ruleResults: sanitizeRuleResultsForCache(tabState.ruleResults)
      });

      // 触发完整高危响应
      await triggerWarningFlow(tabId, tabState);
    } else {
      setIconGreen(tabId, newScore);
    }
  } catch (e) {
    console.error('[ServiceWorker] 下载处理失败:', e);
  }
});

// 消息路由
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) { sendResponse({ error: 'invalid' }); return false; }

  const type = message.type;

  switch (type) {
    case MSG_TYPES.PAGE_ANALYSIS_RESULT:
    case 'PAGE_ANALYSIS_RESULT': {
      const tabId = sender.tab ? sender.tab.id : null;
      if (!tabId) { sendResponse({ received: false }); return false; }
      const { url, domain, pageText, icpStrings, pageMetrics, linkMetrics, hasIcpGovLink } = message.payload;

      // 竞态条件防护：校验 content script 所在标签页的当前 URL 是否与采集数据的域名一致
      // 若用户已导航到其他页面，则丢弃此消息（旧页面的数据不应污染新页面的检测结果）
      if (sender.tab && sender.tab.url) {
        try {
          const senderTabDomain = new URL(sender.tab.url).hostname;
          if (senderTabDomain !== domain) {
            console.warn('[ServiceWorker] ⚠️ 丢弃过期内容脚本数据:',
              `采集域名=${domain}, 当前标签页域名=${senderTabDomain} (用户已导航到其他页面)`);
            sendResponse({ received: false, reason: 'stale_content_script' });
            return false;
          }
        } catch (e) {
          // URL 解析失败，继续处理（保守策略）
          console.warn('[ServiceWorker] 无法解析 sender.tab.url，跳过竞态校验:', sender.tab.url);
        }
      }

      loadTabState(tabId).then(async (ts) => {
        ts.pageText = pageText || '';
        ts.icpStrings = icpStrings || [];
        ts.hasIcpGovLink = !!hasIcpGovLink;
        ts.url = url || ts.url;
        ts.domain = domain || ts.domain;
        if (pageMetrics) ts.pageMetrics = pageMetrics;
        if (linkMetrics) ts.linkMetrics = linkMetrics;
        await saveTabState(tabId, ts);
        // 触发完整分析
        analyzePage(tabId, ts.url, ts.domain, pageMetrics, linkMetrics).catch(console.error);
      });
      sendResponse({ received: true });
      break;
    }

    case MSG_TYPES.GET_TAB_STATE:
    case 'GET_TAB_STATE': {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const ts = await loadTabState(tabs[0].id);
        // 实时检查白名单状态
        const whitelisted = await isWhitelisted(ts.url || '');
        ts.isWhitelisted = whitelisted;
        sendResponse({
          success: true,
          data: {
            url: ts.url, domain: ts.domain, score: ts.score,
            riskLevel: ts.riskLevel, isAnalyzed: ts.isAnalyzed,
            isWhitelisted: whitelisted,
            ruleResults: ts.ruleResults, correctUrl: ts.correctUrl,
            officialName: ts.officialName
          }
        });
      });
      return true;
    }

    case MSG_TYPES.GET_OFFICIAL_LINK:
    case 'GET_OFFICIAL_LINK': {
      const url = DomainDatabase.getCorrectUrl(message.payload?.name || '');
      sendResponse({ success: true, officialUrl: url });
      break;
    }

    case MSG_TYPES.CLEAR_TAB_STATE:
    case 'CLEAR_TAB_STATE': {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length > 0) { await clearTabState(tabs[0].id); resetIcon(tabs[0].id); }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.ADD_TO_WHITELIST:
    case 'ADD_TO_WHITELIST': {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const url = message.payload?.url || '';
        if (url) {
          await addToWhitelist(url);
          // 更新当前标签页状态
          const ts = await loadTabState(tabs[0].id);
          ts.isWhitelisted = true;
          ts.score = 0;
          ts.riskLevel = RISK_LEVEL.SAFE;
          ts.isAnalyzed = true;
          await saveTabState(tabs[0].id, ts);
          setIconWhitelist(tabs[0].id);
          // 清除该域名的缓存（使其不再被分析）
          const domain = UrlUtils.extractHostname(url);
          if (domain) await CacheManager.remove(domain);
        }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.REMOVE_FROM_WHITELIST:
    case 'REMOVE_FROM_WHITELIST': {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const url = message.payload?.url || '';
        if (url) {
          await removeFromWhitelist(url);
          // 清除标签页状态，触发重新分析
          const ts = await loadTabState(tabs[0].id);
          ts.isWhitelisted = false;
          ts.isAnalyzed = false;
          await saveTabState(tabs[0].id, ts);
          // 触发重新分析
          analyzePage(tabs[0].id, ts.url || url, ts.domain || UrlUtils.extractHostname(url),
            null, null).catch(console.error);
        }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.CHECK_WHITELIST:
    case 'CHECK_WHITELIST': {
      const url = message.payload?.url || '';
      isWhitelisted(url).then(result => {
        sendResponse({ success: true, isWhitelisted: result });
      });
      return true;
    }

    default: { sendResponse({ error: 'unknown type: ' + type }); }
  }
  return false;
});

// 通知按钮：点击"前往官网" → 关闭危险标签页 + 打开正确官网
chrome.notifications.onButtonClicked.addListener(async (notifId, btnIdx) => {
  if (btnIdx === 0) {
    // 获取当前活跃标签页的状态信息
    const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (activeTabs.length === 0) return;
    const ts = await loadTabState(activeTabs[0].id);

    // 查找并关闭包含危险域名的所有标签页
    const domain = ts?.domain || '';
    if (domain) {
      const cleanDomain = domain.replace(/^www\./i, '');
      const allTabs = await chrome.tabs.query({});
      const dangerTabs = allTabs.filter(tab => {
        try {
          const host = new URL(tab.url || '').hostname.replace(/^www\./i, '');
          return host === cleanDomain || host.endsWith('.' + cleanDomain);
        } catch (e) { return false; }
      });
      if (dangerTabs.length > 0) {
        await chrome.tabs.remove(dangerTabs.map(t => t.id)).catch(() => {});
      }
    }

    // 打开官方正确网址
    if (ts?.correctUrl) {
      chrome.tabs.create({ url: ts.correctUrl }).catch(() => {});
    }
  }
});

// 标签页关闭清理
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearTabState(tabId);
  _warningCooldown.delete(tabId);
});

// 安装/更新
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[ServiceWorker] 扩展已安装/更新:', details.reason);
  if (details.reason === 'update') {
    await CacheManager.clearAll();
  }
});

// 存储变更监听：白名单被其他页面修改时使内存缓存失效
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[STORAGE_KEYS.WHITELIST]) {
    _whitelistCache = null;
  }
});

console.log('[ServiceWorker] ✅ 银狐木马检测扩展 v2.2.4 已就绪');
