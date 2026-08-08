/**
 * Virus Detector — Service Worker (主协调器)
 *
 * 是整个扩展的中央调度模块，负责协调所有后台任务：
 *
 * @module service-worker
 *
 * 核心职责：
 *   1. 页面导航监听 → 白名单检查 → 缓存查询 → 触发评分分析
 *   2. 评分汇总     → 徽章更新（绿/红/蓝） + 警告弹窗 + 下载拦截注入
 *   3. 下载监听     → 压缩包检测 → 取消下载 → 二次确认弹窗 → 用户决策处理
 *   4. 消息路由     → 处理来自 Popup / Content Script / Warning 的消息（类型见 utils/constants.js MSG_TYPES）
 *   5. 白名单管理   → 存储持久化 / 增删查 / 跳过检测 / 缓存清理
 *   6. 黑名单维护   → 下载域名黑名单写入 / 过期清理 / 容量控制
 *   7. 全局设置     → 非压缩包检测开关读取（预留设置页接入）
 *
 * 生命周期：
 *   - 安装/更新时自动初始化、清理过期缓存、清理过期黑名单条目
 *   - 标签页关闭时自动清理对应状态
 *   - 5 秒冷却期内不重复触发警告（同标签页 / 同域名）
 *
 * 输入输出：
 *   - 输入：chrome.tabs.onUpdated 导航事件、chrome.downloads.onChanged 下载事件，
 *     Popup / Content Script / Warning 页面经 chrome.runtime.onMessage 发来的消息（MSG_TYPES）
 *   - 输出：分析结果写缓存（STORAGE_KEYS.DOMAIN_CACHE）、白名单（WHITELIST）、
 *     下载/站点黑名单（DOWNLOAD_BLACKLIST / SITE_BLACKLIST），
 *     回传消息给调用方、更新徽章（绿/红/蓝）、打开警告/下载确认页
 */

import { ScoringEngine, setActiveSettings } from './scoring-engine.js';
import { DomainDatabase } from './domain-database.js';
import { CacheManager, invalidateCacheTtl } from './cache-manager.js';
import { DownloadBlacklist } from './download-blacklist.js';
import { SiteBlacklist } from './site-blacklist.js';
import { ResourceResolver } from './resource-resolver/index.js';
import { registerNonChineseBrandDomains, IcpUtils } from './icp-utils.js';
import { IcpApiClient } from './icp-api.js';
import { WhoisClient } from './whois-client.js';
import { UrlUtils } from '../utils/url-utils.js';
import {
  normalizeWhitelistEntry, isWildcardPattern, matchWhitelistEntry, isWhitelistedDomain
} from '../utils/whitelist-matcher.js';
import { isFullyTrusted } from '../utils/exemptions/fully-trusted.js';
import {
  SCORE_THRESHOLD, DOWNLOAD_CONFIRM_THRESHOLD, RISK_LEVEL, MSG_TYPES,
  STORAGE_KEYS, CACHE_TTL, DETECT_NON_ARCHIVE_FILES_DEFAULT,
  VERSION, REPORT_API_URL, GITHUB_RELEASES_API_URL, GITHUB_RELEASES_PAGE,
  UPDATE_VERSION_API_URL, UPDATE_CHANNEL, UPDATE_CHECK_TIMEOUT_MS, UPDATE_RETRY_DELAY_MINUTES,
  ICP_API_CONFIG, SCORE_SITE_BLACKLIST, WARNING_COOLDOWN_MS,
  ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS, DOWNLOAD_INTENT_KEYWORDS,
  buildAuthPatterns, ALARM_NAME_UPDATE_CHECK, UPDATE_CHECK_PERIOD_MINUTES,
  CACHE_CLEANUP_ALARM_NAME, CACHE_CLEANUP_PERIOD_MINUTES, CACHE_LRU_KEEP_COUNT,
  GATE_TIMEOUT_MS, BLOCKER_OBSERVER_LIFETIME_MS, REPORTS_MAX_ENTRIES,
  DOWNLOAD_CONFIRM_ACTIONS, REPORT_TYPES
} from '../utils/constants.js';
import { SETTINGS_DEFAULTS, migrateSettings } from '../utils/settings-schema.js';

// ==================== URL 协议守卫 ====================

/**
 * 判断 URL 是否应跳过分析（仅分析 http/https 协议）
 *
 * 非 http(s) 协议（file:/data:/ftp:/view-source: 等）无有效主机名，
 * 无法分析也无缓存意义，统一跳过。
 *
 * @param {string} url
 * @returns {boolean} true 表示应跳过（不分析）
 */


/**
 * 判断主机名是否为内网/保留地址（RFC 1918 等），这类地址应跳过整站检测。
 * 覆盖：回环 127.0.0.0/8、私有 10.0.0.0/8、192.168.0.0/16、172.16.0.0/12、
 * 链路本地 169.254.0.0/16、以及 localhost。
 * @param {string} hostname
 * @returns {boolean}
 */
function isPrivateOrLocalIp(hostname) {
  if (!hostname) return false;
  if (hostname === 'localhost') return true;
  const m = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a > 255 || b > 255) return false;
  if (a === 127) return true;                          // 127.0.0.0/8 回环
  if (a === 10) return true;                           // 10.0.0.0/8 私有
  if (a === 192 && b === 168) return true;             // 192.168.0.0/16 私有（路由器/NAS/开发服务器）
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12 私有
  if (a === 169 && b === 254) return true;             // 169.254.0.0/16 链路本地
  return false;
}

function shouldSkipUrl(url) {
  if (!url || typeof url !== 'string') return true;
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return true;
    // 内网/保留地址：整站跳过检测，避免对 192.168.x.x 等局域网地址误报
    if (isPrivateOrLocalIp(u.hostname)) return true;
    return false;
  } catch (e) {
    return true; // 无法解析的 URL 视为应跳过
  }
}

// 认证 URL 特征正则（源串与构造统一来自 constants.js buildAuthPatterns）
const { host: AUTH_HOST_PATTERN, path: AUTH_PATH_PATTERN } = buildAuthPatterns();

function isSensitiveAuthenticationUrl(url) {
  try {
    const parsed = new URL(url);
    if (AUTH_HOST_PATTERN.test(parsed.hostname)) return true;
    return AUTH_PATH_PATTERN.test(parsed.pathname + parsed.search + parsed.hash);
  } catch (e) {
    return false;
  }
}

// ==================== 全局设置缓存 ====================

/** 内存缓存：避免每次评分都读取 storage */
let _settingsCache = null;

/**
 * 获取当前生效的全局设置（含缓存）。
 * 读取 chrome.storage.local 中的 global_settings，与默认值合并。
 * @returns {Promise<Object>} 完整设置对象
 */
async function getSettings() {
  if (_settingsCache) return _settingsCache;
  _settingsCache = await loadGlobalSettings();
  return _settingsCache;
}

/**
 * 同步获取有效阈值（优先使用缓存的设置值，缓存未命中时回退到默认常量）。
 * 用于不能 await 的同步上下文。
 * @param {string} key - 设置键名
 * @param {*} defaultVal - 回退默认值（通常为 constants.js 中的导出值）
 * @returns {*}
 */
function getEffectiveThreshold(key, defaultVal) {
  if (_settingsCache && _settingsCache[key] !== undefined) {
    return _settingsCache[key];
  }
  return defaultVal;
}

// ==================== 更新检测 ====================

/**
 * 语义版本比较：返回 1 (a > b), -1 (a < b), 0 (相等)
 */
function compareVersions(a, b) {
  const pa = String(a || '').split('.').map(Number);
  const pb = String(b || '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

/**
 * 判定更新渠道：
 * - UPDATE_CHANNEL 常量为 'store' / 'manual' 时直接使用（上架打包时由构建脚本改写为 'store'）
 * - 'auto' 时根据 manifest.update_url 判定：商店安装会被商店注入该字段，
 *   手动安装（开发者模式 / zip 解包）则为 undefined
 */
function getUpdateChannel() {
  if (UPDATE_CHANNEL === 'store' || UPDATE_CHANNEL === 'manual') return UPDATE_CHANNEL;
  return chrome.runtime.getManifest().update_url ? 'store' : 'manual';
}

/** 带超时的 fetch；超时产生的 AbortError 统一改写为可读的超时错误 */
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPDATE_CHECK_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`请求超时（>${UPDATE_CHECK_TIMEOUT_MS / 1000}s）`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** 主源：Cloudflare Worker 版本代理 */
async function fetchVersionFromWorker() {
  const resp = await fetchWithTimeout(UPDATE_VERSION_API_URL, {
    headers: { 'Accept': 'application/json' }
  });
  if (!resp.ok) throw new Error(`Worker HTTP ${resp.status}`);
  const data = await resp.json();
  if (!data || typeof data.version !== 'string' || !/^\d+\.\d+/.test(data.version)) {
    throw new Error('Worker 返回数据格式无效');
  }
  return {
    version: data.version,
    releaseUrl: data.releaseUrl || GITHUB_RELEASES_PAGE,
    releaseNotes: typeof data.releaseNotes === 'string' ? data.releaseNotes : '',
    publishedAt: data.publishedAt || null
  };
}

/** 回退源：GitHub Releases API 直连（未认证 60次/小时/IP，共享出口 IP 下易被限流） */
async function fetchVersionFromGitHub() {
  const resp = await fetchWithTimeout(GITHUB_RELEASES_API_URL, {
    headers: {
      'Accept': 'application/vnd.github+json',
      'User-Agent': `VirusDetector/${chrome.runtime.getManifest().version}`
    }
  });
  if (!resp.ok) throw new Error(`GitHub HTTP ${resp.status}`);
  const release = await resp.json();
  const version = String(release.tag_name || '').replace(/^v/i, '');
  if (!version) throw new Error('GitHub 返回数据缺少 tag_name');
  return {
    version,
    releaseUrl: release.html_url || GITHUB_RELEASES_PAGE,
    releaseNotes: String(release.body || '').substring(0, 2000),
    publishedAt: release.published_at || null
  };
}

/**
 * 检查更新，结果存入 chrome.storage.local。
 *
 * - 商店渠道（store）：跳过远程检查，由浏览器商店自动更新
 * - 手动渠道（manual）：Worker 代理 → GitHub API 直连，逐级回退
 * - 全部失败时保留上次成功的版本信息，仅更新错误状态，并提前安排重试
 * - 成功后恢复 24 小时周期的定时检查
 */
async function checkForUpdate() {
  const localVersion = chrome.runtime.getManifest().version;
  const channel = getUpdateChannel();
  console.log('[ServiceWorker] 正在检查更新，当前版本:', localVersion, '渠道:', channel);

  if (channel === 'store') {
    await chrome.storage.local.set({
      [STORAGE_KEYS.UPDATE_INFO]: {
        lastCheck: Date.now(),
        channel,
        latestVersion: null,
        currentVersion: localVersion,
        hasUpdate: false,
        releaseUrl: null,
        releaseNotes: null,
        publishedAt: null,
        error: null
      }
    });
    return;
  }

  const sources = [
    ['Worker 代理', fetchVersionFromWorker],
    ['GitHub API', fetchVersionFromGitHub]
  ];

  let lastError = null;
  for (const [name, fetchVersion] of sources) {
    try {
      const data = await fetchVersion();
      const hasUpdate = compareVersions(data.version, localVersion) > 0;
      await chrome.storage.local.set({
        [STORAGE_KEYS.UPDATE_INFO]: {
          lastCheck: Date.now(),
          channel,
          latestVersion: data.version,
          currentVersion: localVersion,
          hasUpdate,
          releaseUrl: data.releaseUrl,
          releaseNotes: data.releaseNotes,
          publishedAt: data.publishedAt,
          error: null
        }
      });
      // 恢复 24h 周期检查
      await chrome.alarms.create(ALARM_NAME_UPDATE_CHECK, { periodInMinutes: UPDATE_CHECK_PERIOD_MINUTES });
      console.log(`[ServiceWorker] 更新检查完成（${name}）:`, hasUpdate ? `发现新版本 v${data.version}` : '已是最新版本');
      return;
    } catch (e) {
      lastError = e;
      console.warn(`[ServiceWorker] 更新源「${name}」失败: ${e.message}`);
    }
  }

  // 全部更新源失败：保留上次成功的版本信息（按当前版本重新计算 hasUpdate），仅更新错误状态
  const prev = (await chrome.storage.local.get(STORAGE_KEYS.UPDATE_INFO))[STORAGE_KEYS.UPDATE_INFO];
  const latestVersion = prev?.latestVersion ?? null;
  console.error('[ServiceWorker] 更新检查失败:', lastError?.message);
  await chrome.storage.local.set({
    [STORAGE_KEYS.UPDATE_INFO]: {
      lastCheck: Date.now(),
      channel,
      latestVersion,
      currentVersion: localVersion,
      hasUpdate: latestVersion ? compareVersions(latestVersion, localVersion) > 0 : false,
      releaseUrl: prev?.releaseUrl ?? null,
      releaseNotes: prev?.releaseNotes ?? null,
      publishedAt: prev?.publishedAt ?? null,
      error: lastError?.message || '未知错误'
    }
  });
  // 安排提前重试（成功后会恢复 24h 周期）
  await chrome.alarms.create(ALARM_NAME_UPDATE_CHECK, { delayInMinutes: UPDATE_RETRY_DELAY_MINUTES });
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
 * 标签页状态存储介质选择。
 * tabState 为临时数据（浏览器会话内有效，SW 重启后重新分析即可），
 * 优先使用 chrome.storage.session（内存 10MB 独立配额，不占用 storage.local 的
 * 10MB 持久配额，浏览器会话结束自动清空）；Firefox 旧版等无 session 时回退 local。
 */
function _tabStateStorage() {
  return (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session)
    ? chrome.storage.session
    : chrome.storage.local;
}

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
    icpStrings: [], textSignals: null, pageMetrics: null, linkMetrics: null,
    downloadState: { hasDownloadedArchive: false, archiveFileName: null },
    lastAnalyzed: 0
  };
}

async function loadTabState(tabId) {
  try {
    const key = STORAGE_KEYS.TAB_STATE_PREFIX + tabId;
    const r = await _tabStateStorage().get(key);
    return r[key] || createTabState();
  } catch (e) { return createTabState(); }
}

async function saveTabState(tabId, s) {
  try {
    const sanitizedState = { ...s };
    delete sanitizedState.pageText; // 不持久化页面正文，仅保留派生指标 textSignals
    await _tabStateStorage().set({ [STORAGE_KEYS.TAB_STATE_PREFIX + tabId]: sanitizedState });
  } catch (e) { /* ignore */ }
}

async function clearTabState(tabId) {
  try {
    await _tabStateStorage().remove(STORAGE_KEYS.TAB_STATE_PREFIX + tabId);
  } catch (e) { /* ignore */ }
}

/**
 * 一次性清理：旧版本遗留的 chrome.storage.local 中的 tab_state_* 键。
 * tabState 已迁移至 chrome.storage.session，local 中的残留仅占配额无任何价值；
 * 在 onInstalled(update) 时执行一次，避免每启动扫描 local 的开销。
 * 注意：仅当当前介质确为 session 时才清理 local 残留——
 * Firefox(<142) 无 chrome.storage.session，回退路径下 tabState 存于 local，
 * 此时清理会删除活跃标签页的检测状态。
 */
async function cleanupLegacyLocalTabStates() {
  if (!(typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session)) return;
  try {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.TAB_STATE_PREFIX));
    if (keys.length > 0) {
      await chrome.storage.local.remove(keys);
      console.log(`[ServiceWorker] 已清理旧版遗留的 ${keys.length} 条 local tab_state`);
    }
  } catch (e) {
    console.warn('[ServiceWorker] 清理旧版遗留 tab_state 失败:', e.message);
  }
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

/** 预评估状态：清除徽章（等待 Gate 判定中） */
function setIconNeutral(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
}

// ==================== Gate 超时管理 ====================

// Gate 等待超时（Content Script 最长等待时间）来自 constants.js GATE_TIMEOUT_MS

/** 活跃的 Gate 超时定时器：tabId → setTimeout id */
const _gateTimeouts = new Map();

/** 预评估阶段的 Whois Promise（内存缓存，不可序列化到 storage）：tabId → Promise */
const _whoisPromises = new Map();

function scheduleGateTimeout(tabId, domain) {
  // 先清除已有超时
  cancelGateTimeout(tabId);
  const timerId = setTimeout(async () => {
    _gateTimeouts.delete(tabId);
    try {
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (!tab || !tab.url) return;
      // 超时降级：按 Gate 失败处理
      const tabState = await loadTabState(tabId);
      if (tabState._gatePhase !== 'preliminary') return; // 已经处理过了
      console.log('[ServiceWorker] Gate 超时（Content Script 未响应），按 Gate 失败降级:', domain);
      tabState._gatePhase = 'resolved';
      tabState._needsDetection = false;
      await saveTabState(tabId, tabState);
      setIconGreen(tabId, 0);
    } catch (e) { /* 标签页已关闭 */ }
  }, GATE_TIMEOUT_MS);
  _gateTimeouts.set(tabId, timerId);
}

function cancelGateTimeout(tabId) {
  const existing = _gateTimeouts.get(tabId);
  if (existing) {
    clearTimeout(existing);
    _gateTimeouts.delete(tabId);
  }
}

// ==================== 白名单管理 ====================
// 白名单存储在 chrome.storage.local 中，键名为 STORAGE_KEYS.WHITELIST
// 数据结构：string[] — 域名/通配符列表（不含协议和路径，如 "example.com"）
//   支持三种条目：
//     - 精确域名：example.com            → 仅匹配该主机名
//     - 通配符域名：*.example.com        → 匹配 example.com 及其所有子域名（任意层级）
//     - 全匹配：*                         → 匹配所有域名（完全跳过检测，慎用）
// 白名单中的域名完全跳过 5 规则检测，工具栏图标显示蓝色 "✓" 徽章
//
// 性能优化：内存缓存（精确域名 Set + 通配符数组）+ storage.onChanged 失效机制，
// 精确匹配保持 O(1)，通配符按条目数线性匹配（白名单规模通常很小，可接受）。

/** @type {Set<string>|null} 精确白名单域名集合（不含通配符，已规范化小写） */
let _whitelistExact = null;
/** @type {string[]|null} 通配符白名单条目（含 *，已规范化小写） */
let _whitelistPatterns = null;
/** @type {string[]|null} 原始白名单数组（用于增删等需要完整列表的操作） */
let _whitelistRaw = null;

/**
 * 根据原始白名单数组重建内存索引（精确集合 + 通配符数组）
 * @param {string[]} list
 */
function _buildWhitelistIndexes(list) {
  const exact = new Set();
  const patterns = [];
  for (const entry of (list || [])) {
    const norm = normalizeWhitelistEntry(entry);
    if (!norm) continue;
    if (isWildcardPattern(norm)) patterns.push(norm);
    else exact.add(norm);
  }
  _whitelistExact = exact;
  _whitelistPatterns = patterns;
  _whitelistRaw = list || [];
}

/**
 * 从存储加载白名单（优先返回内存缓存）
 * @returns {Promise<string[]>}
 */
async function loadWhitelist() {
  if (_whitelistExact !== null) {
    return [..._whitelistRaw];
  }
  try {
    const r = await chrome.storage.local.get(STORAGE_KEYS.WHITELIST);
    const list = r[STORAGE_KEYS.WHITELIST] || [];
    _buildWhitelistIndexes(list);
    return list;
  } catch (e) { return []; }
}

/** 使白名单内存缓存失效，下次 loadWhitelist 重新从存储读取 */
function _invalidateWhitelistCache() {
  _whitelistExact = null;
  _whitelistPatterns = null;
  _whitelistRaw = null;
}

async function saveWhitelist(whitelist) {
  try {
    // 规范化 + 去重，保证存储中的条目形式统一（小写、无协议/路径/尾点）
    const normalized = [...new Set(
      (whitelist || []).map(d => normalizeWhitelistEntry(d)).filter(Boolean)
    )];
    await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: normalized });
    // 同步更新内存缓存索引
    _buildWhitelistIndexes(normalized);
  } catch (e) { /* ignore */ }
}

/**
 * 检查URL对应域名是否在白名单中
 * 优化：优先 O(1) 精确集合查找，未命中再线性匹配通配符条目，避免每次异步读存储
 */
async function isWhitelisted(url) {
  const domain = UrlUtils.extractHostname(url);
  if (_whitelistExact !== null) {
    if (_whitelistExact.has(domain.toLowerCase())) return true;
    for (const p of _whitelistPatterns) {
      if (matchWhitelistEntry(domain, p)) return true;
    }
    return false;
  }
  const whitelist = await loadWhitelist();
  return isWhitelistedDomain(domain, whitelist);
}

/**
 * 将域名加入白名单（支持传入通配符条目，例如 "*.example.com"）
 */
async function addToWhitelist(url) {
  const entry = normalizeWhitelistEntry(UrlUtils.extractHostname(url));
  if (!entry) return;

  // 白名单与黑名单互斥：仅对精确域名执行黑名单移除；通配符条目不针对具体黑名单域名操作
  if (!isWildcardPattern(entry)) {
    await SiteBlacklist.remove(entry);
  }

  // 先用内存缓存快速判断，避免无谓的存储读取
  if (_whitelistRaw && _whitelistRaw.some(d => normalizeWhitelistEntry(d) === entry)) {
    console.log('[ServiceWorker] 域名已在白名单:', entry);
    return;
  }
  const whitelist = await loadWhitelist();
  if (!whitelist.some(d => normalizeWhitelistEntry(d) === entry)) {
    whitelist.push(entry);
    await saveWhitelist(whitelist);
    console.log('[ServiceWorker] 已加入白名单:', entry);
  }
}

/**
 * 将域名从白名单移除
 * 优先精确移除；若没有精确条目，则移除覆盖该域名的一个通配符条目
 * （例如白名单含 *.example.com 时，对 sub.example.com 执行移除会删掉 *.example.com）
 */
async function removeFromWhitelist(url) {
  const entry = normalizeWhitelistEntry(UrlUtils.extractHostname(url));
  if (!entry) return;
  const whitelist = await loadWhitelist();
  let idx = whitelist.findIndex(d => normalizeWhitelistEntry(d) === entry);
  if (idx === -1) {
    idx = whitelist.findIndex(d => {
      const norm = normalizeWhitelistEntry(d);
      return isWildcardPattern(norm) && matchWhitelistEntry(entry, norm);
    });
  }
  if (idx !== -1) {
    const removed = whitelist[idx];
    whitelist.splice(idx, 1);
    await saveWhitelist(whitelist);
    console.log('[ServiceWorker] 已移出白名单:', removed);
  }
}

/**
 * 从白名单数组中过滤掉指定域名：精确匹配项或覆盖该域的通配符项都会被移除
 * @param {string[]} list
 * @param {string} domain
 * @returns {string[]} 过滤后的新数组
 */
function _filterWhitelistOutDomain(list, domain) {
  const norm = normalizeWhitelistEntry(domain);
  if (!norm) return list;
  return (list || []).filter(d => {
    const e = normalizeWhitelistEntry(d);
    if (e === norm) return false;
    if (isWildcardPattern(e) && matchWhitelistEntry(norm, e)) return false;
    return true;
  });
}

/**
 * 加载全局设置，与默认值合并确保所有键存在。
 * 当前包含：
 *   - detectNonArchiveFiles：非压缩包可执行文件检测开关
 *   - 各检测规则开关、评分阈值、时间参数等（详见 settings-schema.js）
 * @returns {Promise<Object>} 完整设置对象
 */
async function loadGlobalSettings() {
  try {
    const r = await chrome.storage.local.get(STORAGE_KEYS.GLOBAL_SETTINGS);
    const stored = r[STORAGE_KEYS.GLOBAL_SETTINGS] || {};
    // Schema 迁移：旧版本设置自动升级（如 v1→v2 修正 apihz 键名），写回存储
    const migrated = migrateSettings(stored);
    if (migrated !== stored) {
      await chrome.storage.local.set({ [STORAGE_KEYS.GLOBAL_SETTINGS]: migrated });
    }
    // 合并默认值：新版本新增的键自动获得默认值
    return { ...SETTINGS_DEFAULTS, ...migrated };
  } catch (e) {
    return { ...SETTINGS_DEFAULTS };
  }
}

// ==================== 高危响应流程 ====================

// 去重：每个标签页的警告冷却期（5秒内不重复弹窗）
const _warningCooldown = new Map();
const _authenticationTabs = new Set();

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

  // 2. 收集已知压缩包链接 URL 列表（用于精准拦截）
  const archiveUrls = [];
  if (tabState.linkMetrics && tabState.linkMetrics.archiveDownloadLinks) {
    for (const link of tabState.linkMetrics.archiveDownloadLinks) {
      try {
        archiveUrls.push(new URL(link.href, 'http://' + domain).href);
      } catch (e) { archiveUrls.push(link.href); }
    }
  }

  // 3. 注入下载拦截脚本（仅首次，传入已知压缩包链接进行精准拦截）
  const settings = await getSettings();
  if (settings.downloadInjection !== false) {
    await injectDownloadBlocker(tabId, archiveUrls);
  }

  // 去重检查：同标签页冷却期内跳过通知和弹窗
  const cooldownMs = getEffectiveThreshold('warning_cooldownMs', WARNING_COOLDOWN_MS);
  const lastTime = _warningCooldown.get(tabId) || 0;
  if (now - lastTime < cooldownMs) {
    console.log('[ServiceWorker] ⚠️ 冷却期内，跳过重复弹窗:', domain);
    return;
  }
  _warningCooldown.set(tabId, now);

  // 4. 桌面通知（可通过设置关闭）
  if (settings.desktopNotifications !== false) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '⚠️ 银狐木马检测 - 风险警告',
      message: `检测到疑似钓鱼网站: ${domain}\n风险评分: ${score}分${correctUrl ? '\n正确官网: ' + correctUrl : ''}`,
      priority: 2,
      buttons: correctUrl ? [{ title: '✅ 前往官网' }] : [],
      requireInteraction: true
    }).catch(() => {});
  }

  // 5. 创建警告窗口（可通过设置关闭）
  if (settings.showWarningWindow !== false) {
    openWarningWindow(tabState);
  }

  console.log('[ServiceWorker] ⚠️ 高危响应已触发:', { domain, score, correctUrl });
}

/**
 * 注入下载拦截脚本（精准拦截 + 视觉禁用 + 动态监控）
 *
 * @param {number} tabId - 标签页 ID
 * @param {string[]} archiveUrls - 已知的压缩包下载链接 URL 列表
 * @param {string} [mode='full'] - 注入模式（档位机制已实现，当前调用方恒传 'full'）
 */
async function injectDownloadBlocker(tabId, archiveUrls = [], mode = 'full') {
  const settings = await loadGlobalSettings();
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || _authenticationTabs.has(tabId) ||
        isSensitiveAuthenticationUrl(tab.url) || await isWhitelisted(tab.url)) {
      await removeDownloadBlocker(tabId);
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId },
      func: injectBlockerFunc,
      // 扩展名/关键词列表从 constants.js 并集生成传入（页面注入函数保持自包含，附字面量兜底）
      args: [archiveUrls, settings.detectNonArchiveFiles, mode, {
        archives: ARCHIVE_EXTENSIONS,
        executables: EXECUTABLE_EXTENSIONS,
        downloadKeywords: DOWNLOAD_INTENT_KEYWORDS,
        // 注：注入函数经 executeScript 序列化执行，闭包不保留，
        // 所有模块级常量必须经 args 显式传入（历史回归点：BLOCKER_OBSERVER_LIFETIME_MS）
        observerLifetimeMs: BLOCKER_OBSERVER_LIFETIME_MS
      }],
      injectImmediately: true
    }).catch(e => console.error('[ServiceWorker] 注入拦截脚本失败:', e));
  } catch (e) {
    console.error('[ServiceWorker] 注入失败:', e);
  }
}

async function removeDownloadBlocker(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: removeDownloadBlockerFunc,
      injectImmediately: true
    });
  } catch (e) {
    // 页面可能已关闭或不允许脚本注入。
  }
}

async function removeBlockersFromWhitelistedTabs() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map(async (tab) => {
    if (!tab.id || !tab.url || !await isWhitelisted(tab.url)) return;
    await removeDownloadBlocker(tab.id);
    setIconWhitelist(tab.id);
  }));
}

function removeDownloadBlockerFunc() {
  const state = window.__virusDetectorBlockerState;
  if (!state) return;

  if (state.anchorClick && HTMLAnchorElement.prototype.click === state.patchedAnchorClick) {
    HTMLAnchorElement.prototype.click = state.anchorClick;
  }
  if (state.createElement && document.createElement === state.patchedCreateElement) {
    document.createElement = state.createElement;
  }
  if (state.clickHandler) {
    document.removeEventListener('click', state.clickHandler, true);
  }
  if (state.observer) state.observer.disconnect();
  if (state.overlay?.isConnected) state.overlay.remove();

  delete window.__virusDetectorBlockerState;
  delete window.__virusDetectorInjected;
  delete window.__virusDetectorInjectedRank; // 必须一并清理，否则重新注入被 rank 守卫拦截
}

/**
 * 注入到页面的拦截函数（独立定义以支持 args 传递）
 * @param {string[]} archiveUrls - 已知压缩包链接
 * @param {boolean} detectNonArchive - 是否检测非压缩包可执行文件
 * @param {string} mode - 注入模式 'lightweight' | 'standard' | 'full'（档位机制已实现，当前调用方恒传 'full'）
 * @param {Object} [extLists] - 扩展名/关键词列表（由 SW 从 constants.js 并集生成传入）
 */
function injectBlockerFunc(archiveUrls, detectNonArchive, mode, extLists) {
  detectNonArchive = detectNonArchive || false;
  mode = mode || 'full';

  // 避免重复注入：使用排名制守卫，允许从低等级升级到高等级。
  // 注意：rank 检查必须先于 __virusDetectorInjected 检查——
  // 若先检查 injected，则「移除拦截后重新注入」会被 rank 残留拦截，
  // 导致条幅/拦截在重新检测时永久失效（历史缺陷）。
  var MODE_RANK = { lightweight: 1, standard: 2, full: 3 };
  var newRank = MODE_RANK[mode] || 3;
  var existingRank = window.__virusDetectorInjectedRank || 0;
  if (existingRank >= newRank) return;

  if (window.__virusDetectorBlockerState || window.__virusDetectorInjected) return;
  var blockerState = {
    anchorClick: null,
    patchedAnchorClick: null,
    createElement: null,
    patchedCreateElement: null,
    clickHandler: null,
    observer: null,
    overlay: null
  };
  window.__virusDetectorBlockerState = blockerState;
  window.__virusDetectorInjected = true;
  window.__virusDetectorInjectedRank = newRank;

  // ══════════════════════════════════════════════════════
  // Part 0: JS 级别下载拦截（对抗 IDM 绕过 & 自动下载）
  // ══════════════════════════════════════════════════════

  // 扩展名/关键词列表：优先取 SW 传入的 extLists（来自 constants.js 并集），
  // 其次 MAIN world 的 window.VT_CONSTANTS 镜像，最后字面量兜底（防注入顺序异常）
  var C = (typeof window !== 'undefined' && window.VT_CONSTANTS) || {};

  // 压缩包扩展名（始终检测；并集含 .gz2/.img/.dmg）
  var ARCHIVE_EXTS = (extLists && extLists.archives) || C.ARCHIVE_EXTENSIONS || [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
    '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
    '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
  ];

  // 非压缩包可执行文件扩展名（由 detectNonArchive 开关控制）
  var NON_ARCHIVE_EXE_EXTS = (extLists && extLists.executables) || C.EXECUTABLE_EXTENSIONS || [
    '.exe', '.msi', '.dmg', '.apk', '.appx', '.deb', '.rpm',
    '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar', '.bin', '.run', '.sh', '.pkg'
  ];

  // 全部危险扩展名（用于各级拦截与视觉禁用，不受开关影响）
  var ALL_DANGEROUS_EXTS = ARCHIVE_EXTS.concat(NON_ARCHIVE_EXE_EXTS);

  // 下载相关中英文关键词（用于匹配按钮文本和下载意图；并集统一小写）
  var DOWNLOAD_KEYWORDS = (extLists && extLists.downloadKeywords) || C.DOWNLOAD_INTENT_KEYWORDS || [
    '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
    '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
    'download now', 'free download', 'download free',
    '立即安装', '一键安装', '安装包',
    'down', 'dl', 'get', 'setup', 'install', 'free', 'app',
    'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z',
    'get started', 'ダウンロード'
  ];

  function _isDangerousHref(href) {
    if (!href || typeof href !== 'string') return false;
    var low = href.toLowerCase().split('?')[0].split('#')[0];
    for (var i = 0; i < ALL_DANGEROUS_EXTS.length; i++) {
      if (low.endsWith(ALL_DANGEROUS_EXTS[i])) return true;
    }
    return false;
  }

  // --- Hook 1: 拦截 HTMLAnchorElement.prototype.click ---
  // 当任何脚本调用 a.click() 程式化触发下载时拦截
  try {
    var _origAnchorClick = HTMLAnchorElement.prototype.click;
    var _patchedAnchorClick = function () {
      var href = this.href || this.getAttribute('href') || '';
      if (href && _isDangerousHref(href)) {
        // 弹确认窗
        if (!confirm(
          '⚠️ Virus Detector 安全警告\n\n' +
          '脚本试图程式化触发危险文件下载：\n\n' +
          '文件: ' + (href.split('/').pop() || '未知').split('?')[0] + '\n' +
          'URL: ' + href.substring(0, 200) + '\n\n' +
          '点击「确定」继续（不推荐）\n' +
          '点击「取消」阻止下载'
        )) {
          // 阻止：不触发原始 click
          return;
        }
      }
      return _origAnchorClick.call(this);
    };
    blockerState.anchorClick = _origAnchorClick;
    blockerState.patchedAnchorClick = _patchedAnchorClick;
    HTMLAnchorElement.prototype.click = _patchedAnchorClick;
  } catch (e) { /* prototype hook 失败时静默降级 */ }

  // --- Hook 2: 拦截 document.createElement ---
  // 监控程序化创建的 <a> 元素，设置 href 时检查
  try {
    var _origCreateElement = document.createElement;
    var _patchedCreateElement = function (tagName, options) {
      var el = _origCreateElement.call(document, tagName, options);
      if (tagName && tagName.toLowerCase() === 'a') {
        // 对动态创建的 <a> 元素，hook 其 href setter
        var _origSetAttribute = el.setAttribute.bind(el);
        el.setAttribute = function (name, value) {
          if (name && name.toLowerCase() === 'href' && _isDangerousHref(String(value))) {
            // 标记为危险链接
            el.setAttribute('data-virus-detector-dangerous', 'true');
          }
          return _origSetAttribute(name, value);
        };

        // 也 hook 直接的 .href 属性
        try {
          var _hrefDescriptor = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
          if (_hrefDescriptor && _hrefDescriptor.set) {
            var _origHrefSet = _hrefDescriptor.set.bind(el);
            Object.defineProperty(el, 'href', {
              get: function () { return _hrefDescriptor.get.call(this); },
              set: function (val) {
                if (_isDangerousHref(String(val))) {
                  this.setAttribute('data-virus-detector-dangerous', 'true');
                }
                _origHrefSet.call(this, val);
              },
              configurable: true,
              enumerable: true
            });
          }
        } catch (e2) { /* href hook 失败 */ }
      }
      return el;
    };
    blockerState.createElement = _origCreateElement;
    blockerState.patchedCreateElement = _patchedCreateElement;
    document.createElement = _patchedCreateElement;
  } catch (e) { /* createElement hook 失败时静默降级 */ }

  // ══════════════════════════════════════════════════════
  // Part 1: 已知压缩包链接精准匹配
  // ══════════════════════════════════════════════════════
  var knownArchiveSet = new Set();
  if (archiveUrls && archiveUrls.length) {
    for (var i = 0; i < archiveUrls.length; i++) {
      try {
        knownArchiveSet.add(archiveUrls[i].toLowerCase().replace(/#.*$/, ''));
      } catch (e) { /* ignore */ }
    }
  }

  // 全部危险扩展名（用于视觉禁用，不受开关影响）— ARCHIVE_EXTS/NON_ARCHIVE_EXE_EXTS/DOWNLOAD_KEYWORDS
  // 已在 Part 0 定义（优先取 SW 传入的 extLists，来自 constants.js 并集）
  var DANGEROUS_EXTS = ALL_DANGEROUS_EXTS;

  // ══════════════════════════════════════════════════════
  // Part 2: 辅助函数
  // ══════════════════════════════════════════════════════

  function isArchiveUrl(href) {
    var lower = href.toLowerCase();
    for (var i = 0; i < ARCHIVE_EXTS.length; i++) {
      if (lower.endsWith(ARCHIVE_EXTS[i])) return true;
    }
    return false;
  }

  function isNonArchiveExeUrl(href) {
    var lower = href.toLowerCase();
    for (var i = 0; i < NON_ARCHIVE_EXE_EXTS.length; i++) {
      if (lower.endsWith(NON_ARCHIVE_EXE_EXTS[i])) return true;
    }
    return false;
  }

  function isKnownArchiveUrl(href) {
    try {
      return knownArchiveSet.has(href.toLowerCase().replace(/#.*$/, ''));
    } catch (e) { return false; }
  }

  function hasDownloadIntent(el) {
    var text = (el.textContent || '').toLowerCase().trim();
    var aria = (el.getAttribute('aria-label') || '').toLowerCase();
    var title = (el.getAttribute('title') || '').toLowerCase();
    var combined = text + ' ' + aria + ' ' + title;
    for (var i = 0; i < DOWNLOAD_KEYWORDS.length; i++) {
      if (combined.indexOf(DOWNLOAD_KEYWORDS[i].toLowerCase()) !== -1) return true;
    }
    return false;
  }

  // ══════════════════════════════════════════════════════
  // Part 3: 移除 download 属性 + 视觉禁用下载元素
  // 'lightweight' 模式下跳过（仅 JS hooks + click 拦截，无视觉禁用）
  // ══════════════════════════════════════════════════════

  var disableExistingDownloadButtons = function() {};
  if (mode !== 'lightweight') {

    // 移除所有链接的 download 属性（防止强制下载 + 右键另存为绕过）
    document.querySelectorAll('a[download]').forEach(function(a) { a.removeAttribute('download'); });

    disableExistingDownloadButtons = function() {
      // 3a. 禁用所有带下载文本的交互元素
      var allInteractive = document.querySelectorAll('a, button, [role="button"], input[type="submit"], input[type="button"]');
      for (var j = 0; j < allInteractive.length; j++) {
        var el = allInteractive[j];
        if (hasDownloadIntent(el)) {
          el.style.pointerEvents = 'none';
          el.style.opacity = '0.5';
          el.style.cursor = 'not-allowed';
          el.title = '下载已被安全插件禁用';
          if (el.tagName === 'A') {
            el.removeAttribute('href');
            el.setAttribute('data-original-href', el.href || '');
          };
          el.setAttribute('disabled', 'disabled');
          el.classList.add('virus-detector-blocked');
        }
      }

      // 3b. 禁用常见的下载容器
      var downloadContainers = document.querySelectorAll(
        '[class*="download"], [id*="download"], ' +
        '[class*="btn-dl"], [class*="btn_dl"], ' +
        '[class*="down-btn"], [class*="down_btn"], ' +
        '.dl-btn, .dl_box, .down_url'
      );
      for (var k = 0; k < downloadContainers.length; k++) {
        var container = downloadContainers[k];
        var links = container.querySelectorAll('a, button');
        for (var m = 0; m < links.length; m++) {
          var link = links[m];
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

  }

  // ══════════════════════════════════════════════════════
  // Part 4: 全局点击拦截 — 双层（精准 + 宽泛）
  // ══════════════════════════════════════════════════════

  var _clickHandler = function(e) {
    var target = e.target.closest('a, button, [role="button"], [onclick]');
    if (!target) return;

    var shouldBlock = false;
    var blockReason = '';

    // 检查1（精准）: href 指向已知的压缩包链接
    if (target.tagName === 'A' && target.href) {
      var rawHref = target.href;
      if (isKnownArchiveUrl(rawHref)) {
        shouldBlock = true;
        blockReason = 'known_archive';
      }
    }

    // 检查2: href 指向压缩包（始终）或非压缩包可执行文件（开关控制）
    if (!shouldBlock && target.tagName === 'A' && target.href) {
      var href = target.href;
      if (isArchiveUrl(href)) {
        shouldBlock = true;
        blockReason = 'dangerous_ext';
      } else if (detectNonArchive && isNonArchiveExeUrl(href)) {
        shouldBlock = true;
        blockReason = 'non_archive_exe';
      }
    }

    // 检查3（宽泛）: 元素文本包含下载关键词
    if (!shouldBlock && hasDownloadIntent(target)) {
      shouldBlock = true;
      blockReason = 'download_intent';
    }

    // 检查4（宽泛）: 父级元素在下载容器中
    if (!shouldBlock) {
      var parent = target.closest('[class*="download"], [id*="download"], ' +
        '[class*="btn-dl"], [class*="btn_dl"]');
      if (parent) {
        shouldBlock = true;
        blockReason = 'download_container';
      }
    }

    if (shouldBlock) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      if (blockReason === 'known_archive') {
        alert('⚠️ 该下载链接已被安全插件识别为可疑压缩包。\n如果您需要下载，请通过官方渠道获取文件。');
      } else if (blockReason === 'non_archive_exe') {
        alert('⚠️ 当前网站已被识别为危险网站，可执行文件下载已被拦截。\n请前往官方网站下载安全版本。');
      } else {
        alert('⚠️ 当前网站已被识别为危险网站，下载已被禁用。\n请前往官方网站下载安全版本。');
      }
      return false;
    }
  };
  blockerState.clickHandler = _clickHandler;
  document.addEventListener('click', _clickHandler, true);

  // ══════════════════════════════════════════════════════
  // Part 5: MutationObserver 动态监控
  // ══════════════════════════════════════════════════════
  var observer = new MutationObserver(function() {
    disableExistingDownloadButtons();
  });
  blockerState.observer = observer;

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    // 30 秒后停止观察（避免性能影响）；值经 args 传入（闭包不保留，禁止引用模块常量）
    setTimeout(function() { observer.disconnect(); },
      (extLists && extLists.observerLifetimeMs) || 30000);
  }

  // ══════════════════════════════════════════════════════
  // Part 6: 顶部红色警告横幅（仅 'full' 模式，≥100 分）
  // ══════════════════════════════════════════════════════

  if (!document.getElementById('__virus_detector_overlay')) {
    var overlay = document.createElement('div');
    overlay.id = '__virus_detector_overlay';
    overlay.innerHTML =
      '<div style="position:fixed;top:0;left:0;right:0;z-index:2147483646;' +
      'background:linear-gradient(135deg,#b71c1c,#c62828);color:#fff;' +
      'text-align:center;padding:12px 20px;font-size:14px;font-weight:bold;' +
      'font-family:-apple-system,BlinkMacSystemFont,\'Microsoft YaHei\',sans-serif;' +
      'box-shadow:0 2px 12px rgba(183,28,28,0.5);">' +
      '⚠️ 风险警告：该网站被检测为疑似钓鱼/恶意网站，请勿输入个人信息或下载任何文件！' +
      '</div>';
    document.documentElement.appendChild(overlay);
    blockerState.overlay = overlay;
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
  // 覆盖调用方：webNavigation、PAGE_ANALYSIS_RESULT 消息、REMOVE_FROM_WHITELIST、REMOVE_SITE_BLACKLIST
  if (shouldSkipUrl(url)) {
    console.log('[ServiceWorker] 跳过非 http(s) URL:', url);
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

  // 完全信任域名检查：政府/教育机构域名（.gov.cn / .edu.cn 等）跳过所有检测
  if (isFullyTrusted(domain)) {
    console.log('[ServiceWorker] 完全信任域名，跳过所有检测:', domain);
    tabState.isAnalyzed = true;
    tabState.url = url;
    tabState.domain = domain;
    tabState.score = 0;
    tabState.riskLevel = RISK_LEVEL.SAFE;
    await saveTabState(tabId, tabState);
    setIconGreen(tabId, 0);
    return;
  }

  tabState.isWhitelisted = false;

  // 站点黑名单检查：如果在站点黑名单中，直接赋予高分触发警告流程
  if (await SiteBlacklist.isBlacklisted(domain)) {
    console.log('[ServiceWorker] 站点在黑名单中，直接标记为高风险:', domain);
    // 保存当前分析数据备份（如果存在完整的非黑名单分析结果），以便移除黑名单后恢复
    if (tabState.isAnalyzed && tabState.ruleResults && Object.keys(tabState.ruleResults).length > 0
        && !tabState.ruleResults.siteBlacklist && !tabState._preBlacklistState) {
      tabState._preBlacklistState = {
        domain: tabState.domain,
        score: tabState.score,
        riskLevel: tabState.riskLevel,
        ruleResults: { ...tabState.ruleResults },
        correctUrl: tabState.correctUrl,
        officialName: tabState.officialName
      };
    }
    tabState.score = SCORE_SITE_BLACKLIST;
    tabState.riskLevel = RISK_LEVEL.WARNING;
    tabState.isAnalyzed = true;
    tabState.url = url;
    tabState.domain = domain;
    tabState.ruleResults = {
      siteBlacklist: { triggered: true, score: SCORE_SITE_BLACKLIST, detail: '站点黑名单命中', detailCN: '站点黑名单: 用户标记为恶意网站' }
    };
    await saveTabState(tabId, tabState);
    setIconRed(tabId);
    // 触发完整警告流程
    triggerWarningFlow(tabId, tabState).catch(e =>
      console.error('[ServiceWorker] 黑名单警告流程失败:', e));
    return;
  }

  // 是否有来自 Content Script 的新数据
  const hasFreshData = !!(pageMetrics || linkMetrics);

  // ==================== Gate 预评估阶段（无 Content Script 数据） ====================
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
        await injectDownloadBlocker(tabId, []);  // 无实时 linkMetrics，传空数组
      } else {
        setIconGreen(tabId, cached.score);
      }
      return;
    }

    // 无缓存 + 无 Content Script 数据 → 预评估阶段
    // 仅运行 Rule 1（域名仿冒）+ 发起 Whois 查询（异步不等待）
    console.log('[ServiceWorker] Gate 预评估阶段（等待 Content Script 数据）:', domain);
    const rule1Result = ScoringEngine.evaluateRule1Only(domain);
    const whoisPromise = WhoisClient.lookup(domain).catch(() => null);

    tabState._gatePhase = 'preliminary';
    tabState._rule1Result = rule1Result;
    tabState._preliminaryScore = rule1Result.score;
    tabState.url = url;
    tabState.domain = domain;
    tabState.ruleResults = { rule1: rule1Result };
    tabState.lastAnalyzed = Date.now();
    // Promise 不可序列化到 storage，存入内存 Map
    _whoisPromises.set(tabId, whoisPromise);
    await saveTabState(tabId, tabState);

    setIconNeutral(tabId);
    scheduleGateTimeout(tabId, domain);
    return;
  }

  // ==================== Gate 权威阶段（有 Content Script 数据） ====================
  cancelGateTimeout(tabId);
  tabState._gatePhase = 'resolved';

  // 读取 Gate 判定结果（Content Script 计算）
  let needsDetection = !!(tabState._needsDetection);

  // Resource Resolver 覆盖 Gate：若发现隐藏归档链接，强制视为需要检测
  let resourceGraph = null;
  const resourceData = tabState._resourceData || null;
  if (resourceData) {
    try {
      resourceGraph = await ResourceResolver.resolve(url || tabState.url, resourceData);
      tabState._resourceGraph = resourceGraph;
      if (!needsDetection && resourceGraph && resourceGraph.discoveredArchives &&
          resourceGraph.discoveredArchives.length > 0) {
        console.log('[ServiceWorker] ResourceResolver 发现隐藏归档链接，Gate 覆盖为通过:', domain);
        needsDetection = true;
      }
    } catch (e) {
      console.warn('[ServiceWorker] ResourceResolver 解析失败（不影响检测）:', e.message);
    }
  }

  const settings = await getSettings();

  // ==================== Gate 失败：仅 Rule 1 + Whois（域名年龄完整贡献，无上限） ====================
  if (!needsDetection) {
    console.log('[ServiceWorker] Gate 未通过，跳过完整检测:', domain);

    const savedWhoisPromise = _whoisPromises.get(tabId);
    const whoisResult = await (savedWhoisPromise || WhoisClient.lookup(domain).catch(() => null));
    _whoisPromises.delete(tabId);

    // 合并预评估阶段的 Rule 1 结果；
    // 若已有 Content Script 数据（title），用联动评分重算，补齐「内容声称品牌」信号
    // （Gate 失败路径不跑规则三，ICP 联动保持中性，仅 title/域名年龄联动生效）
    const baseRule1 = tabState._rule1Result || ScoringEngine.evaluateRule1Only(domain);
    let rule1Result = baseRule1;
    if (tabState.title) {
      rule1Result = ScoringEngine.evaluateRule1Only(domain, {
        icpResult: null,
        title: tabState.title,
        linkMetrics: null,
        creationDays: (whoisResult && whoisResult.creationDays >= 0) ? whoisResult.creationDays : -1
      });
    }

    // 复用评分引擎的域名年龄计算（不重复写 S 衰减公式）
    const syncDomainAgeResult = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '域名年龄: 等待查询',
      creationDays: (whoisResult && whoisResult.creationDays >= 0) ? whoisResult.creationDays : -1
    };
    const domainAgePart = await ScoringEngine.evaluateDomainAgePart(
      domain, rule1Result.score, syncDomainAgeResult, false, settings
    );

    // 域名年龄不受 Gate 影响，完整贡献分数（无上限）
    const finalScore = Math.max(0, rule1Result.score +
      domainAgePart.domainAgeResult.score + domainAgePart.ageBonusResult.score);

    const threshold = getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD);
    tabState.score = finalScore;
    tabState.riskLevel = finalScore >= threshold ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;
    tabState.isAnalyzed = true;
    tabState.correctUrl = rule1Result.correctUrl || null;
    tabState.officialName = rule1Result.officialName || null;
    tabState.ruleResults = {
      rule1: rule1Result,
      rule2: { score: 0, triggered: false, status: 'pass', detail: 'Gate 未通过，跳过下载检测', detailCN: '下载检测: 跳过（无下载特征）' },
      rule3: { score: 0, triggered: false, status: 'neutral', detail: 'Gate 未通过，跳过ICP检测', detailCN: 'ICP备案: 跳过（无下载特征）' },
      rule4: { score: 0, triggered: false, status: 'pass', detail: 'Gate 未通过，跳过链接分析', detailCN: '链接分析: 跳过（无下载特征）' },
      rule5: { score: 0, triggered: false, status: 'pass', detail: 'Gate 未通过，跳过代码工程化', detailCN: '代码工程化: 跳过（无下载特征）' },
      domainAge: domainAgePart.domainAgeResult,
      ageBonus: domainAgePart.ageBonusResult,
      downloadLink: { score: 0, triggered: false, status: 'pass', detail: 'Gate 未通过，跳过跨域检测', detailCN: '下载链接: 跳过' }
    };
    tabState.lastAnalyzed = Date.now();
    if (pageMetrics) tabState.pageMetrics = pageMetrics;
    if (linkMetrics) tabState.linkMetrics = linkMetrics;

    await saveTabState(tabId, tabState);
    await CacheManager.set(domain, {
      score: finalScore,
      isMalicious: finalScore >= threshold,
      gateFailed: true,
      correctUrl: rule1Result.correctUrl || null,
      ruleResults: sanitizeRuleResultsForCache(tabState.ruleResults)
    });

    if (finalScore >= threshold) {
      setIconRed(tabId);
      await triggerWarningFlow(tabId, tabState);
      console.log('[ServiceWorker] Gate 失败但域名检测触发警告:', { domain, finalScore });
    } else {
      setIconGreen(tabId, finalScore);
      console.log('[ServiceWorker] Gate 失败，显示绿色图标:', { domain, finalScore });
    }
    return;
  }

  // ==================== Gate 通过：完整检测 ====================
  // 清理预评估阶段保留的 Whois Promise（已缓存到 WhoisClient，不再需要）
  _whoisPromises.delete(tabId);
  console.log('[ServiceWorker] Gate 通过，运行完整检测:', domain);

  const ctx = {
    url: tabState.url || url,
    domain: tabState.domain || domain,
    title: tabState.title || '',
    brandSignals: tabState.brandSignals || null,
    icpStrings: tabState.icpStrings || [],
    textSignals: tabState.textSignals || null,
    hasIcpGovLink: tabState.hasIcpGovLink || false,
    icpApi: null, // ICP API 改为异步核验，同步阶段传 null 走页面文本扫描
    linkMetrics: linkMetrics || tabState.linkMetrics || null,
    downloadState: tabState.downloadState || { hasDownloadedArchive: false },
    pageMetrics: pageMetrics || tabState.pageMetrics || null,
    resourceGraph: resourceGraph
  };

  // 运行评分引擎（两阶段：同步首屏 + Whois异步补充）
  try {
    // 获取当前设置（含阈值覆盖，已在上方 ICP 核验前读取并缓存）

    // ═══ 阶段1：同步评估（规则一~五，不含Whois网络请求）═══
    const syncResult = await ScoringEngine.evaluateSync(ctx, settings);

    tabState.score = syncResult.totalScore;
    tabState.riskLevel = syncResult.riskLevel;
    tabState.ruleResults = syncResult.breakdown;
    tabState.correctUrl = syncResult.correctUrl;
    tabState.officialName = syncResult.officialName;
    tabState.isAnalyzed = true;
    tabState._whoisPending = (syncResult._syncDomainAgeResult.creationDays < 0) &&
      !syncResult.isConfirmedOfficial;
    tabState.lastAnalyzed = Date.now();
    if (pageMetrics) tabState.pageMetrics = pageMetrics;
    if (linkMetrics) tabState.linkMetrics = linkMetrics;

    await saveTabState(tabId, tabState);

    // 写入初始缓存
    await CacheManager.set(domain, {
      score: syncResult.totalScore,
      isMalicious: syncResult.isSuspicious,
      correctUrl: syncResult.correctUrl,
      ruleResults: sanitizeRuleResultsForCache(syncResult.breakdown)
    });

    // ═══ 页面注入仅在 ≥100 时由 triggerWarningFlow 触发 ═══
    // 80~99 分段不做页面注入，仅由下载事件层（chrome.downloads.onCreated）处理
    // <80 分段不干预

    if (syncResult.totalScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD)) {
      await triggerWarningFlow(tabId, tabState);
    } else {
      setIconGreen(tabId, syncResult.totalScore);
    }

    console.log('[ServiceWorker] 阶段1分析完成:', {
      domain, score: syncResult.totalScore,
      riskLevel: syncResult.riskLevel, whoisPending: tabState._whoisPending
    });

    // ═══ 阶段2：异步 Whois 域名年龄补充（不阻塞主流程） ═══
    if (tabState._whoisPending) {
      // 保存上下文用于异步回调中的竞态检查与联动重评
      const ctxSnapshot = {
        domain, tabId, pageUrl: tabState.url || url,
        syncScore: syncResult.totalScore,
        syncBreakdown: syncResult.breakdown,
        correctUrl: syncResult.correctUrl,
        officialName: syncResult.officialName,
        isConfirmedOfficial: syncResult.isConfirmedOfficial,
        preliminaryScore: syncResult.preliminaryScore,
        syncDomainAgeResult: syncResult._syncDomainAgeResult,
        // 完整评分 ctx（供 Whois 返回后的联动重评：规则三/五的老域名降权需要域名年龄）
        title: tabState.title || '',
        brandSignals: tabState.brandSignals || null,
        icpStrings: tabState.icpStrings || [],
        textSignals: tabState.textSignals || null,
        hasIcpGovLink: tabState.hasIcpGovLink || false,
        linkMetrics: tabState.linkMetrics || null,
        downloadState: tabState.downloadState || { hasDownloadedArchive: false },
        pageMetrics: tabState.pageMetrics || null
      };

      ScoringEngine.evaluateDomainAgePart(
        domain,
        syncResult.preliminaryScore,
        syncResult._syncDomainAgeResult,
        syncResult.isConfirmedOfficial,
        settings
      ).then(async (whoisResult) => {
        // 同步阶段域名年龄未知（缓存未命中，规则三/五未做年龄联动）
        // 且 Whois 现已返回年龄 → 用完整 ctx 重评一次，补齐老域名/新域名联动，
        // 避免「首访 50 分、刷新后 30 分」的评分随缓存漂移。
        const ageNowKnown = whoisResult.domainAgeResult &&
          whoisResult.domainAgeResult.creationDays >= 0;
        const ageWasUnknown = ctxSnapshot.syncDomainAgeResult &&
          ctxSnapshot.syncDomainAgeResult.creationDays < 0;
        if (ageNowKnown && ageWasUnknown) {
          try {
            const refreshed = await ScoringEngine.evaluateSync({
              url: ctxSnapshot.pageUrl,
              domain: ctxSnapshot.domain,
              title: ctxSnapshot.title,
              brandSignals: ctxSnapshot.brandSignals,
              icpStrings: ctxSnapshot.icpStrings,
              textSignals: ctxSnapshot.textSignals,
              hasIcpGovLink: ctxSnapshot.hasIcpGovLink,
              linkMetrics: ctxSnapshot.linkMetrics,
              downloadState: ctxSnapshot.downloadState,
              pageMetrics: ctxSnapshot.pageMetrics
            }, settings);
            if (refreshed && typeof refreshed.totalScore === 'number') {
              // 重评结果已含域名年龄与规则三/五联动 → 直接应用（跳过旧 whoisResult 的分数）
              await _applyWhoisUpdate({
                ...ctxSnapshot,
                syncScore: refreshed.totalScore,
                syncBreakdown: refreshed.breakdown,
                correctUrl: refreshed.correctUrl || ctxSnapshot.correctUrl,
                officialName: refreshed.officialName || ctxSnapshot.officialName
              }, {
                ...whoisResult,
                totalScore: refreshed.totalScore,
                isSuspicious: refreshed.isSuspicious,
                riskLevel: refreshed.riskLevel,
                domainAgeResult: refreshed._syncDomainAgeResult,
                ageBonusResult: refreshed.breakdown.ageBonus
              });
              return;
            }
          } catch (e) {
            console.warn('[ServiceWorker] Whois 后联动重评失败，回退原路径:', domain, e.message);
          }
        }
        await _applyWhoisUpdate(ctxSnapshot, whoisResult);
      }).catch(e => {
        console.error('[ServiceWorker] Whois异步补充失败:', domain, e);
      });
    }

    // ═══ 异步 ICP 备案 API 核验（不阻塞主流程） ═══
    // 同步阶段已通过页面文本扫描给出规则三评分；
    // 此处异步调用 API 核验，可能纠正两类情况：
    //   ① 合法备案但页面未展示 → 原 +50 → 修正为 0（消除误报）
    //   ② 页面展示备案号但 API 确认域名无备案 → 原 0 → 修正为 +50（盗用/伪造）
    if (!syncResult.isConfirmedOfficial && !IcpUtils.isIcpExempt(domain)) {
      const rule3Result = syncResult.breakdown.rule3;
      const icpSnapshot = {
        domain, tabId,
        pageUrl: tabState.url || url,
        icpStrings: tabState.icpStrings || [],
        hasIcpGovLink: tabState.hasIcpGovLink || false,
        textSignals: tabState.textSignals || null,   // 同步阶段的中文信号，供异步 ICP 核验复用
        impersonating: syncResult.breakdown.rule1.triggered || false,
        oldRule3: {
          score: rule3Result.score || 0,
          triggered: rule3Result.triggered || false,
          icpFound: rule3Result.icpFound || false,
          icpNumbers: rule3Result.icpNumbers || [],
          icpVerified: rule3Result.icpVerified || false,
          icpBlacklisted: rule3Result.icpBlacklisted || false
        },
        syncScore: syncResult.totalScore,
        syncBreakdown: syncResult.breakdown,
        correctUrl: syncResult.correctUrl,
        officialName: syncResult.officialName
      };
      _launchAsyncIcpCheck(icpSnapshot);
    }

  } catch (error) {
    console.error('[ServiceWorker] 评分失败:', error);
  }
}

/**
 * 应用 Whois 异步查询结果，增量更新标签页状态。
 * 仅在分数跨过阈值时补触发警告流程。
 *
 * @param {Object} ctx - 阶段1的上下文快照
 * @param {Object} whoisResult - evaluateDomainAgePart 的返回结果
 */
async function _applyWhoisUpdate(ctx, whoisResult) {
  const { domain, tabId, syncScore, syncBreakdown, correctUrl, officialName } = ctx;
  let currentUrl = '';

  // 竞态条件检查：用户是否已导航到其他页面
  try {
    const tab = await chrome.tabs.get(tabId);
    currentUrl = tab.url || '';
    const currentDomain = UrlUtils.extractHostname(tab.url || '');
    if (currentDomain !== domain) {
      console.log('[ServiceWorker] Whois结果过期（用户已导航）:', domain, '→', currentDomain);
      return;
    }
  } catch (e) {
    // 标签页已关闭
    console.log('[ServiceWorker] Whois结果过期（标签页已关闭）:', tabId);
    return;
  }

  if (await isWhitelisted(currentUrl)) {
    await removeDownloadBlocker(tabId);
    setIconWhitelist(tabId);
    return;
  }

  // 加载最新 tabState
  const tabState = await loadTabState(tabId);
  if (tabState.domain !== domain) {
    console.log('[ServiceWorker] Whois结果过期（tabState域名不匹配）:', domain);
    return;
  }

  // 合并 breakdown：更新 domainAge 和 ageBonus
  const mergedBreakdown = { ...(tabState.ruleResults || syncBreakdown) };
  mergedBreakdown.domainAge = whoisResult.domainAgeResult;
  mergedBreakdown.ageBonus = whoisResult.ageBonusResult;

  const newScore = whoisResult.totalScore;
  const oldScore = tabState.score || syncScore;

  tabState.score = newScore;
  tabState.riskLevel = whoisResult.riskLevel;
  tabState.ruleResults = mergedBreakdown;
  tabState._whoisPending = false;
  await saveTabState(tabId, tabState);

  // 更新缓存
  await CacheManager.set(domain, {
    score: newScore,
    isMalicious: whoisResult.isSuspicious,
    correctUrl: correctUrl,
    ruleResults: sanitizeRuleResultsForCache(mergedBreakdown)
  });

  // 仅在分数从低于阈值跨到≥阈值时补触发警告（保守策略：不降级）
  if (newScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD) && oldScore < getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD)) {
    console.log('[ServiceWorker] Whois异步补充 → 分数跨过阈值，补触发警告:', {
      domain, oldScore, newScore
    });
    await triggerWarningFlow(tabId, tabState);
  } else {
    // 更新图标（可能分数有变化但不跨阈值）
    if (newScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD)) {
      setIconRed(tabId);
    } else {
      setIconGreen(tabId, newScore);
    }
  }

  console.log('[ServiceWorker] 阶段2 Whois补充完成:', {
    domain, oldScore, newScore,
    creationDays: whoisResult.domainAgeResult.creationDays
  });
}

// ==================== ICP 异步核验 ====================

/**
 * 异步发起 ICP 备案 API 查询（不阻塞主流程）。
 *
 * 设计意图：
 *   同步阶段（evaluateSync）仅依赖页面文本扫描给出规则三评分，
 *   避免 API 网络延迟拖慢整站检测。本函数在同步评分完成后异步调用
 *   IcpApiClient.query()，结果返回后通过 _applyIcpUpdate 增量修正评分。
 *
 * 可以纠正的两类情况：
 *   ① 合法备案但页面未展示备案号 → 原 +50 → 修正为 0（消除误报）
 *   ② 页面展示备案号但 API 确认域名无备案 → 原 0 → 修正为 +50（盗用/伪造）
 *
 * @param {Object} snapshot - 同步阶段的上下文快照
 */
async function _launchAsyncIcpCheck(snapshot) {
  try {
    const settings = await getSettings();

    // 按设置开关覆盖各 provider 的 enabled
    const effProviders = ICP_API_CONFIG.providers.map(p => {
      const clone = { ...p };
      if (p.name === 'uapis') clone.enabled = settings.icpApiProviderUapis !== false;
      if (p.name === 'apihz') clone.enabled = settings.icpApiProviderApihz !== false;
      return clone;
    });
    const icpOpts = {
      enabled: settings.icpApiEnabled !== false,
      providers: effProviders,
      apihzId: settings.icpApiApihzId || undefined,
      apihzKey: settings.icpApiApihzKey || undefined
    };

    const icpApi = await IcpApiClient.query(snapshot.domain, icpOpts);

    // API 未返回有效结果（全部源失败/限流/禁用）→ 保持原评分
    if (!icpApi || !icpApi.queried) {
      console.log('[ServiceWorker] ICP API 异步查询未返回有效结果，保持原评分:', snapshot.domain);
      return;
    }

    await _applyIcpUpdate(snapshot, icpApi);
  } catch (e) {
    console.warn('[ServiceWorker] ICP 异步核验失败:', snapshot.domain, e && e.message);
  }
}

/**
 * 应用 ICP API 异步查询结果，增量更新标签页状态。
 * 仅在分数变化或跨过阈值时更新图标/触发警告流程。
 *
 * @param {Object} snapshot - 同步阶段的上下文快照
 * @param {Object} icpApi - IcpApiClient.query() 的返回结果
 */
async function _applyIcpUpdate(snapshot, icpApi) {
  const { domain, tabId } = snapshot;

  // 竞态条件检查：用户是否已导航到其他页面
  try {
    const tab = await chrome.tabs.get(tabId);
    const currentDomain = UrlUtils.extractHostname(tab.url || '');
    if (currentDomain !== domain) {
      console.log('[ServiceWorker] ICP结果过期（用户已导航）:', domain, '→', currentDomain);
      return;
    }
  } catch (e) {
    console.log('[ServiceWorker] ICP结果过期（标签页已关闭）:', tabId);
    return;
  }

  // 白名单检查
  try {
    const tab = await chrome.tabs.get(tabId);
    if (await isWhitelisted(tab.url || '')) return;
  } catch (e) { return; }

  // 加载最新 tabState
  const tabState = await loadTabState(tabId);
  if (tabState.domain !== domain) {
    console.log('[ServiceWorker] ICP结果过期（tabState域名不匹配）:', domain);
    return;
  }

  // 重新执行规则三（仅注入 API 结果，其余参数与同步阶段一致）
  // pageText 保持 undefined（同步阶段亦未传递）；textSignals 复用快照或标签页中已保存的中文信号
  const settings = await getSettings();
  setActiveSettings(settings);
  const newRule3 = ScoringEngine._evaluateRule3(
    domain,
    undefined,                       // pageText（同步阶段亦未传递）
    snapshot.icpStrings,
    snapshot.hasIcpGovLink,
    snapshot.textSignals || tabState.textSignals || null,
    icpApi,
    snapshot.impersonating
  );
  setActiveSettings(null);

  const oldRule3Score = snapshot.oldRule3.score;
  const newRule3Score = newRule3.score || 0;

  // 分数未变化 → 仅更新 breakdown 中的 API 状态信息（供排查展示）
  if (oldRule3Score === newRule3Score && snapshot.oldRule3.triggered === newRule3.triggered) {
    const mergedBreakdown = { ...(tabState.ruleResults || snapshot.syncBreakdown) };
    mergedBreakdown.rule3 = newRule3;
    tabState.ruleResults = mergedBreakdown;
    await saveTabState(tabId, tabState);
    console.log('[ServiceWorker] ICP异步核验完成（分数未变）:', {
      domain,
      icpApiResult: icpApi.hasIcp ? '有备案' : '无备案',
      rule3Score: newRule3Score
    });
    return;
  }

  // 分数变化 — 重新计算总分并更新所有状态
  const mergedBreakdown = { ...(tabState.ruleResults || snapshot.syncBreakdown) };
  mergedBreakdown.rule3 = newRule3;

  const rawTotalScore = Object.values(mergedBreakdown)
    .reduce((sum, r) => sum + (r && r.score || 0), 0);
  // ageBonus 减分不应使总分低于 0（与 evaluateSync 中 Math.min 的安全地板一致）
  const safeTotalScore = Math.max(0, rawTotalScore);
  const oldTotalScore = tabState.score || snapshot.syncScore;

  tabState.score = safeTotalScore;
  tabState.ruleResults = mergedBreakdown;
  tabState.riskLevel = safeTotalScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD)
    ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;
  await saveTabState(tabId, tabState);

  // 更新缓存
  await CacheManager.set(domain, {
    score: safeTotalScore,
    isMalicious: safeTotalScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD),
    correctUrl: snapshot.correctUrl,
    ruleResults: sanitizeRuleResultsForCache(mergedBreakdown)
  });

  console.log('[ServiceWorker] ICP异步核验完成（分数已更新）:', {
    domain,
    icpApiResult: icpApi.hasIcp ? '有备案' : '无备案',
    rule3: `${oldRule3Score} → ${newRule3Score}`,
    total: `${oldTotalScore} → ${safeTotalScore}`
  });

  const threshold = getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD);
  const wasWarning = oldTotalScore >= threshold;
  const isWarning = safeTotalScore >= threshold;

  if (isWarning && !wasWarning) {
    // 分数从安全跨到危险 → 补触发警告流程
    console.log('[ServiceWorker] ICP异步核验 → 分数跨过阈值，补触发警告:', {
      domain, oldTotalScore, safeTotalScore
    });
    await triggerWarningFlow(tabId, tabState);
  } else if (!isWarning && wasWarning) {
    // 分数从危险降回安全 → 清除警告状态
    console.log('[ServiceWorker] ICP异步核验 → 分数降至阈值以下，清除警告:', {
      domain, oldTotalScore, safeTotalScore
    });
    setIconGreen(tabId, safeTotalScore);
    await removeDownloadBlocker(tabId);
  } else if (isWarning) {
    setIconRed(tabId);
  } else {
    setIconGreen(tabId, safeTotalScore);
  }
}

/**
 * 异步 POST 用户上报数据到 Cloudflare Worker → 创建 GitHub Issue。
 * Fire-and-forget：不阻塞响应，失败不影响本地存储。
 *
 * @param {string} reportType - 'false_positive' | 'confirmed_phish'
 * @param {string} domain - 上报的域名
 * @param {string} note - 用户备注
 */
async function _postReportToWorker(reportType, domain, note) {
  try {
    // Public GitHub Issues must not include page URLs. The Worker renders rule
    // results from an allowlist of non-sensitive fields before publishing them.
    let score = 0;
    let ruleResults = null;
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0) {
        const ts = await loadTabState(tabs[0].id);
        score = ts.score || 0;
        ruleResults = ts.ruleResults || null;
      }
    } catch (e) { /* 获取 tabState 失败，使用默认值 */ }

    const payload = {
      reportType,
      domain,
      score,
      version: VERSION,
      timestamp: Date.now(),
      note: note || '',
      ruleResults
    };

    const response = await fetch(REPORT_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      const result = await response.json().catch(() => ({}));
      console.log('[ServiceWorker] GitHub Issue 已创建:', result.issueUrl || 'success');
    } else {
      console.warn('[ServiceWorker] Worker 返回错误:', response.status, await response.text().catch(() => ''));
    }
  } catch (e) {
    // Worker 不可用时静默失败（本地存储已保存）
    console.warn('[ServiceWorker] 上报 Worker 不可达:', e.message);
  }
}

// ==================== 事件监听 ====================

// 新文档提交后清除上一个页面的认证交互标记；当前页面的 Content Script 会按需重新标记。
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) _authenticationTabs.delete(details.tabId);
});

// 页面导航完成
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;

  // 内部浏览器页面 / 本地文件 / 非 http(s) 协议：直接跳过
  // （一次性清理空域名旧缓存，避免历史恶意缓存影响所有 file:// 页面）
  if (shouldSkipUrl(url)) {
    resetIcon(tabId);
    await clearTabState(tabId);
    return;
  }

  const domain = UrlUtils.extractHostname(url);
  let tabState = await loadTabState(tabId);
  tabState.url = url; tabState.domain = domain;
  // 导航到新页面时重置下载状态，避免旧页面的下载事件污染新页面的检测
  tabState.downloadState = { hasDownloadedArchive: false, archiveFileName: null };
  tabState.isAnalyzed = false;
  await saveTabState(tabId, tabState);

  // 白名单：跳过分析
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

  // 完全信任域名：跳过检测
  if (isFullyTrusted(domain)) {
    tabState.isAnalyzed = true;
    tabState.score = 0;
    tabState.riskLevel = RISK_LEVEL.SAFE;
    await saveTabState(tabId, tabState);
    setIconGreen(tabId, 0);
    console.log('[ServiceWorker] 完全信任域名，跳过检测:', domain);
    return;
  }

  // 启动分析（异步，不阻塞导航事件）
  analyzePage(tabId, url, domain, null, null).catch(e =>
    console.error('[ServiceWorker] analyzePage error:', e));
});

// ==================== 下载确认临时存储 ====================
// 存储被拦截的下载信息，供二次确认弹窗回传时使用
// key: downloadId, value: { downloadUrl, filename, tabId, pageDomain, downloadDomain }
const _pendingDownloads = new Map();

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

    // 白名单网站：不拦截下载
    if (tabState.isWhitelisted) {
      console.log('[ServiceWorker] 白名单网站，跳过下载检测:', tabState.domain);
      return;
    }

    // 完全信任域名：不拦截下载
    if (isFullyTrusted(tabState.domain)) {
      console.log('[ServiceWorker] 完全信任域名，跳过下载检测:', tabState.domain);
      return;
    }

    // 注：下载事件不受 Gate 约束。即使 Gate 判定页面无下载特征，
    // 若用户实际触发了压缩包下载，仍在此处拦截检测——实际下载是比 HTML 分析更强的信号。

    // 官方网站检查：域名+ICP 均通过检测的官网不拦截下载
    if (tabState.isAnalyzed) {
      const r1 = tabState.ruleResults && tabState.ruleResults.rule1;
      const r3 = tabState.ruleResults && tabState.ruleResults.rule3;
      if (r1 && r3 &&
          !r1.triggered && r1.status === 'pass' &&
          !r3.triggered && r3.status === 'pass') {
        console.log('[ServiceWorker] 官方网站，跳过下载检测:', tabState.domain);
        return;
      }
    }

    // 更新下载状态
    const fileName = downloadItem.filename.split(/[\\/]/).pop();
    tabState.downloadState = {
      hasDownloadedArchive: true,
      archiveFileName: fileName,
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
    // 获取规则一的仿冒匹配结果（用于官网劫持检测）
    const matchedEntry = (tabState.ruleResults && tabState.ruleResults.rule1)
      ? tabState.ruleResults.rule1.matchedEntry || null : null;
    const dlSettings = await getSettings();
    setActiveSettings(dlSettings);
    const rule2Result = await ScoringEngine._evaluateRule2(
      tabState.downloadState, tabState.linkMetrics, existingScore, matchedEntry,
      tabState._resourceGraph || null
    );

    tabState.ruleResults.rule2 = rule2Result;

    // 下载链接跨域检测（Whois API + 黑名单）：检查下载链接域名是否跨域及是否为新建域名
    const downloadLinkResult = await ScoringEngine.evaluateDownloadLink(
      downloadItem.url || '', tabState.domain || ''
    );
    tabState.ruleResults.downloadLink = downloadLinkResult;

    // 重新计算总分（包含所有规则 + 下载链接跨域检测）
    const newScore = Object.values(tabState.ruleResults)
      .reduce((sum, r) => sum + (r.score || 0), 0);
    tabState.score = newScore;
    tabState.riskLevel = newScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD) ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE;

    await saveTabState(tabId, tabState);

    // 分数达标 → 取消下载（两层分流）
    if (newScore >= getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD)) {
      // ≥100: 取消下载 + 完整高危流程（警告窗口覆盖下载确认需求，不弹确认窗）
      try {
        await chrome.downloads.cancel(downloadItem.id);
        console.log('[ServiceWorker] 已取消危险下载（≥100）:', downloadItem.filename);
      } catch (e) {
        console.error('[ServiceWorker] 取消下载失败:', e);
      }

      await CacheManager.set(tabState.domain, {
        score: newScore,
        isMalicious: true,
        correctUrl: tabState.correctUrl,
        ruleResults: sanitizeRuleResultsForCache(tabState.ruleResults)
      });

      await triggerWarningFlow(tabId, tabState);

    } else if (newScore >= getEffectiveThreshold('downloadConfirmThreshold', DOWNLOAD_CONFIRM_THRESHOLD)) {
      // 80~99: 取消下载 + 三选项确认弹窗（唯一拦截手段，不做页面注入）
      try {
        await chrome.downloads.cancel(downloadItem.id);
        console.log('[ServiceWorker] 已取消危险下载（80~99）:', downloadItem.filename);
      } catch (e) {
        console.error('[ServiceWorker] 取消下载失败:', e);
      }

      // 提取下载来源域名
      let downloadDomain = '';
      try {
        downloadDomain = new URL(downloadItem.url || '').hostname;
      } catch (e) { downloadDomain = '未知'; }

      // 保存待确认的下载信息（供二次确认弹窗回传）
      _pendingDownloads.set(downloadItem.id, {
        downloadUrl: downloadItem.url || '',
        filename: fileName,
        tabId: tabId,
        pageDomain: tabState.domain || '',
        downloadDomain: downloadDomain,
        timestamp: Date.now()
      });

      // 弹出二次确认弹窗
      openDownloadConfirmation(tabState, downloadItem, fileName, downloadDomain, tabId);

      // 更新缓存
      await CacheManager.set(tabState.domain, {
        score: newScore,
        isMalicious: false,
        correctUrl: tabState.correctUrl,
        ruleResults: sanitizeRuleResultsForCache(tabState.ruleResults)
      });

    } else {
      setIconGreen(tabId, newScore);
    }
    setActiveSettings(null);
  } catch (e) {
    setActiveSettings(null);
    console.error('[ServiceWorker] 下载处理失败:', e);
  }
});

/**
 * 打开下载二次确认弹窗
 * @param {Object} tabState - 标签页状态
 * @param {Object} downloadItem - 下载项
 * @param {string} fileName - 文件名
 * @param {string} downloadDomain - 下载来源域名
 * @param {number} tabId - 来源标签页 ID
 */
function openDownloadConfirmation(tabState, downloadItem, fileName, downloadDomain, tabId) {
  const params = new URLSearchParams({
    domain: tabState.domain || '未知',
    score: String(tabState.score || 0),
    filename: fileName || '未知文件',
    downloadDomain: downloadDomain || '未知',
    downloadUrl: downloadItem.url || '',
    tabId: String(tabId),
    downloadId: String(downloadItem.id),
    correctUrl: tabState.correctUrl || '',
    officialName: tabState.officialName || ''
  });

  chrome.windows.create({
    url: chrome.runtime.getURL('warning/download-confirm.html?' + params.toString()),
    type: 'popup',
    width: 460,
    height: 580,
    focused: true
  }).catch(() => {
    chrome.tabs.create({
      url: chrome.runtime.getURL('warning/download-confirm.html?' + params.toString())
    }).catch(() => {});
  });
}

// 消息路由
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) { sendResponse({ error: 'invalid' }); return false; }

  const type = message.type;

  switch (type) {
    case MSG_TYPES.AUTH_INTERACTION_DETECTED: {
      const tabId = sender.tab ? sender.tab.id : null;
      if (!tabId) { sendResponse({ received: false }); return false; }
      _authenticationTabs.add(tabId);
      removeDownloadBlocker(tabId).then(() => {
        sendResponse({ received: true });
      });
      return true;
    }

    case MSG_TYPES.PAGE_ANALYSIS_RESULT: {
      const tabId = sender.tab ? sender.tab.id : null;
      if (!tabId) { sendResponse({ received: false }); return false; }
      const { url, domain, icpStrings, textSignals, pageMetrics, linkMetrics, hasIcpGovLink, needsDetection, title, brandSignals } = message.payload;

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
        ts.icpStrings = icpStrings || [];
        ts.textSignals = textSignals || null;
        ts.hasIcpGovLink = !!hasIcpGovLink;
        ts.url = url || ts.url;
        ts.domain = domain || ts.domain;
        if (pageMetrics) ts.pageMetrics = pageMetrics;
        if (linkMetrics) ts.linkMetrics = linkMetrics;
        // 存储 Gate 判定结果（Content Script 计算）
        ts._needsDetection = !!(needsDetection);
        // 存储规则一联动信号：页面 title + 下载意图派生指标（仅计数，不含正文）
        if (title) ts.title = String(title).substring(0, 200);
        if (brandSignals) ts.brandSignals = brandSignals;
        // 存储 Resource Resolver 数据
        if (message.payload.resourceData) {
          ts._resourceData = message.payload.resourceData;
        }
        await saveTabState(tabId, ts);
        // 触发完整分析
        analyzePage(tabId, ts.url, ts.domain, pageMetrics, linkMetrics).catch(console.error);
      });
      sendResponse({ received: true });
      break;
    }

    case MSG_TYPES.GET_TAB_STATE: {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const ts = await loadTabState(tabs[0].id);
        // 实时检查白名单状态
        const whitelisted = await isWhitelisted(ts.url || '');
        ts.isWhitelisted = whitelisted;
        // 实时检查站点黑名单状态
        const siteBlacklisted = await SiteBlacklist.isBlacklisted(ts.domain || '');
        sendResponse({
          success: true,
          data: {
            url: ts.url, domain: ts.domain, score: ts.score,
            riskLevel: ts.riskLevel, isAnalyzed: ts.isAnalyzed,
            isWhitelisted: whitelisted, isSiteBlacklisted: siteBlacklisted,
            ruleResults: ts.ruleResults, correctUrl: ts.correctUrl,
            officialName: ts.officialName
          }
        });
      });
      return true;
    }

    case MSG_TYPES.GET_OFFICIAL_LINK: {
      const url = DomainDatabase.getCorrectUrl(message.payload?.name || '');
      sendResponse({ success: true, officialUrl: url });
      break;
    }

    case MSG_TYPES.CLEAR_TAB_STATE: {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length > 0) { await clearTabState(tabs[0].id); resetIcon(tabs[0].id); }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.ADD_TO_WHITELIST: {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const url = message.payload?.url || '';
        if (url) {
          // addToWhitelist 内部已处理黑名单互斥
          await addToWhitelist(url);
          await removeDownloadBlocker(tabs[0].id);
          // 更新当前标签页状态
          const ts = await loadTabState(tabs[0].id);
          // 保存移除白名单后可恢复的分析数据备份（含域名用于防呆校验）
          ts._preWhitelistState = {
            domain: ts.domain,
            score: ts.score,
            riskLevel: ts.riskLevel,
            ruleResults: ts.ruleResults,
            correctUrl: ts.correctUrl,
            officialName: ts.officialName
          };
          ts.isWhitelisted = true;
          ts.score = 0;
          ts.riskLevel = RISK_LEVEL.SAFE;
          ts.isAnalyzed = true;
          await saveTabState(tabs[0].id, ts);
          setIconWhitelist(tabs[0].id);
          // 不删除域名缓存，以便移除白名单后可恢复检测状态
        }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.REMOVE_FROM_WHITELIST: {
      chrome.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
        if (tabs.length === 0) { sendResponse({ success: false, error: 'no tab' }); return; }
        const url = message.payload?.url || '';
        if (url) {
          await removeFromWhitelist(url);
          const ts = await loadTabState(tabs[0].id);
          ts.isWhitelisted = false;

          // 尝试从备份恢复分析数据，避免不必要的重新检测
          // 增加防呆校验：备份域名必须与当前页面域名一致（防止页面导航后恢复过期数据）
          const currentDomain = ts.domain || UrlUtils.extractHostname(url);
          const backup = ts._preWhitelistState;
          if (backup && backup.ruleResults && Object.keys(backup.ruleResults).length > 0
              && backup.domain === currentDomain) {
            ts.score = backup.score;
            ts.riskLevel = backup.riskLevel;
            ts.ruleResults = backup.ruleResults;
            ts.correctUrl = backup.correctUrl;
            ts.officialName = backup.officialName;
            ts.isAnalyzed = true;
            delete ts._preWhitelistState;
            await saveTabState(tabs[0].id, ts);
            // 根据恢复的分数还原图标
            const threshold = getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD);
            if (ts.score >= threshold) {
              setIconRed(tabs[0].id);
            } else {
              setIconGreen(tabs[0].id, ts.score);
            }
          } else {
            // 无备份数据（页面可能已重新加载），需要触发重新分析
            ts.isAnalyzed = false;
            delete ts._preWhitelistState;
            await saveTabState(tabs[0].id, ts);
            analyzePage(tabs[0].id, ts.url || url, ts.domain || UrlUtils.extractHostname(url),
              null, null).catch(console.error);
          }
        }
        sendResponse({ success: true });
      });
      return true;
    }

    case MSG_TYPES.CHECK_WHITELIST: {
      const url = message.payload?.url || '';
      isWhitelisted(url).then(result => {
        sendResponse({ success: true, isWhitelisted: result });
      });
      return true;
    }

    // 下载二次确认：处理用户在确认弹窗中的选择
    case MSG_TYPES.DOWNLOAD_CONFIRMATION: {
      (async () => {
        const { action, downloadUrl, tabId, downloadId, pageDomain, downloadDomain, filename } = message.payload || {};
        console.log('[ServiceWorker] 下载确认:', action, downloadDomain);

        switch (action) {
          case DOWNLOAD_CONFIRM_ACTIONS.ALLOW_ONCE:
            // 仅此次放行：重新发起下载
            if (downloadUrl) {
              try {
                await chrome.downloads.download({
                  url: downloadUrl,
                  filename: filename || undefined,
                  saveAs: false
                });
                console.log('[ServiceWorker] 用户选择放行一次，重新发起下载:', downloadUrl);
              } catch (e) {
                console.error('[ServiceWorker] 重新发起下载失败:', e);
              }
            }
            break;

          case DOWNLOAD_CONFIRM_ACTIONS.TRUST_SITE:
            // 信任网站并放行：将页面域名加入白名单 + 重新发起下载
            if (pageDomain) {
              await addToWhitelist('https://' + pageDomain);
              // 更新标签页状态
              if (tabId) {
                const ts = await loadTabState(tabId);
                ts.isWhitelisted = true;
                ts.score = 0;
                ts.riskLevel = RISK_LEVEL.SAFE;
                ts.isAnalyzed = true;
                await saveTabState(tabId, ts);
                setIconWhitelist(tabId);
                // 清除域名缓存
                if (pageDomain) await CacheManager.remove(pageDomain);
              }
            }
            if (downloadUrl) {
              try {
                await chrome.downloads.download({
                  url: downloadUrl,
                  filename: filename || undefined,
                  saveAs: false
                });
                console.log('[ServiceWorker] 用户信任网站，白名单+放行下载:', pageDomain);
              } catch (e) {
                console.error('[ServiceWorker] 重新发起下载失败:', e);
              }
            }
            break;

          case DOWNLOAD_CONFIRM_ACTIONS.BLOCK_BLACKLIST:
            // 拦截并拉黑：将下载域名加入黑名单
            if (downloadDomain) {
              await DownloadBlacklist.add(downloadDomain, {
                pageDomain: pageDomain || '',
                pageUrl: ''
              }, filename ? '.' + filename.split('.').pop() : null);
              console.log('[ServiceWorker] 用户拉黑下载域名:', downloadDomain);
            }
            // 不重新发起下载
            break;

          default:
            console.warn('[ServiceWorker] 未知的下载确认动作:', action);
        }

        // 清理临时存储
        if (downloadId) {
          _pendingDownloads.delete(downloadId);
        }

        sendResponse({ success: true });
      })();
      return true;
    }

    // 获取下载黑名单列表（供 Popup 管理界面使用）
    case MSG_TYPES.GET_DOWNLOAD_BLACKLIST: {
      DownloadBlacklist.getAll().then(blacklist => {
        sendResponse({ success: true, data: blacklist });
      });
      return true;
    }

    // 移除下载黑名单条目（供 Popup 管理界面使用）
    case MSG_TYPES.REMOVE_DOWNLOAD_BLACKLIST: {
      const targetDomain = message.payload?.domain || '';
      DownloadBlacklist.remove(targetDomain).then(() => {
        sendResponse({ success: true, removed: targetDomain });
      });
      return true;
    }

    // 获取站点黑名单列表
    case MSG_TYPES.GET_SITE_BLACKLIST: {
      SiteBlacklist.getAll().then(blacklist => {
        sendResponse({ success: true, data: blacklist });
      });
      return true;
    }

    // 添加站点黑名单条目
    case MSG_TYPES.ADD_SITE_BLACKLIST: {
      (async () => {
        try {
          const domain = message.payload?.domain || '';
          const addedBy = message.payload?.addedBy || 'manual';
          if (!domain) { sendResponse({ success: false, error: '缺少 domain' }); return; }
          // 白名单与黑名单互斥：加入黑名单时自动移出白名单（精确项或覆盖该域的通配符项）
          const whitelist = await loadWhitelist();
          const filtered = _filterWhitelistOutDomain(whitelist, domain);
          if (filtered.length !== whitelist.length) {
            await saveWhitelist(filtered);
          }
          await SiteBlacklist.add(domain, { addedBy });
          
          // 保存当前标签页的分析数据备份，以便移除黑名单后恢复
          try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs.length > 0) {
              const currentTs = await loadTabState(tabs[0].id);
              if (currentTs.isAnalyzed && currentTs.ruleResults && Object.keys(currentTs.ruleResults).length > 0
                  && !currentTs.ruleResults.siteBlacklist) {
                currentTs._preBlacklistState = {
                  domain: currentTs.domain,
                  score: currentTs.score,
                  riskLevel: currentTs.riskLevel,
                  ruleResults: { ...currentTs.ruleResults },
                  correctUrl: currentTs.correctUrl,
                  officialName: currentTs.officialName
                };
                await saveTabState(tabs[0].id, currentTs);
              }
            }
          } catch (e) { /* 保存备份失败不影响主流程 */ }
          
          sendResponse({ success: true, added: domain });
        } catch (e) { sendResponse({ success: false, error: e.message }); }
      })();
      return true;
    }

    // 移除站点黑名单条目
    case MSG_TYPES.REMOVE_SITE_BLACKLIST: {
      const targetDomain = message.payload?.domain || '';
      SiteBlacklist.remove(targetDomain).then(async (wasRemoved) => {
        // 只有确实移除了条目时才触发恢复/重新分析流程
        // 避免在"加入白名单前先移出黑名单"的互斥操作中，对不在黑名单中的站点触发无意义的重新分析
        if (!wasRemoved) {
          sendResponse({ success: true, removed: targetDomain });
          return;
        }
        try {
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tabs.length > 0) {
            const ts = await loadTabState(tabs[0].id);
            // 如果网站已在白名单中，不修改状态（白名单优先）
            if (await isWhitelisted(ts.url || '')) {
              sendResponse({ success: true, removed: targetDomain });
              return;
            }
            const currentDomain = ts.domain || targetDomain;

            // 尝试从备份恢复分析数据，避免不必要的重新检测
            const backup = ts._preBlacklistState;
            if (backup && backup.ruleResults && Object.keys(backup.ruleResults).length > 0
                && backup.domain === currentDomain) {
              ts.score = backup.score;
              ts.riskLevel = backup.riskLevel;
              ts.ruleResults = backup.ruleResults;
              ts.correctUrl = backup.correctUrl;
              ts.officialName = backup.officialName;
              ts.isAnalyzed = true;
              delete ts._preBlacklistState;
              await saveTabState(tabs[0].id, ts);
              // 根据恢复的分数还原图标
              const threshold = getEffectiveThreshold('scoreThreshold', SCORE_THRESHOLD);
              if (ts.score >= threshold) {
                setIconRed(tabs[0].id);
              } else {
                setIconGreen(tabs[0].id, ts.score);
              }
            } else {
              // 无备份数据，触发重新分析
              ts.isAnalyzed = false;
              delete ts._preBlacklistState;
              await saveTabState(tabs[0].id, ts);
              analyzePage(tabs[0].id, ts.url || '', ts.domain || targetDomain,
                null, null).catch(console.error);
            }
          }
        } catch (e) {
          console.error('[ServiceWorker] 黑名单移除后恢复失败:', e);
        }
        sendResponse({ success: true, removed: targetDomain });
      });
      return true;
    }

    // 清除全部站点黑名单
    case MSG_TYPES.CLEAR_SITE_BLACKLIST: {
      SiteBlacklist.clearAll().then(() => {
        sendResponse({ success: true });
      });
      return true;
    }

    // 用户上报：误报 / 确认钓鱼
    case MSG_TYPES.SUBMIT_REPORT: {
      (async () => {
        try {
          const { reportType, domain, note } = message.payload || {};
          if (!reportType || !domain) {
            sendResponse({ success: false, error: '缺少 reportType 或 domain' });
            return;
          }

          // 加载现有上报记录
          const r = await chrome.storage.local.get(STORAGE_KEYS.USER_REPORTS);
          const reports = r[STORAGE_KEYS.USER_REPORTS] || [];

          // 追加新记录
          reports.push({
            domain,
            type: reportType,  // 'false_positive' | 'confirmed_phish'
            timestamp: Date.now(),
            note: note || '',
            version: VERSION
          });

          // 上限 REPORTS_MAX_ENTRIES 条（constants.js）
          if (reports.length > REPORTS_MAX_ENTRIES) {
            reports.splice(0, reports.length - REPORTS_MAX_ENTRIES);
          }

          await chrome.storage.local.set({ [STORAGE_KEYS.USER_REPORTS]: reports });
          console.log('[ServiceWorker] 用户上报已保存:', reportType, domain);

          // 异步 POST 到 Cloudflare Worker → 创建 GitHub Issue（fire-and-forget，不阻塞响应）
          const reportSettings = await getSettings();
          if (reportSettings.allowAnonymousReporting !== false) {
            _postReportToWorker(reportType, domain, note);
          }

          // 自动操作（reportType 值来自 constants.js REPORT_TYPES 枚举）
          if (reportType === REPORT_TYPES.FALSE_POSITIVE) {
            // 用户认为该网站安全：加入白名单（addToWhitelist 内部已处理黑名单互斥），清除缓存
            await addToWhitelist('https://' + domain);
            await CacheManager.remove(domain);
            console.log('[ServiceWorker] 误报已处理：加入白名单:', domain);
            sendResponse({ success: true, autoAction: 'whitelisted' });
          } else if (reportType === REPORT_TYPES.CONFIRMED_PHISH) {
            // 确认钓鱼：移出白名单（互斥），同时将页面上的跨域下载域名加入下载黑名单
            await removeFromWhitelist('https://' + domain);
            const ts = await loadTabState((await chrome.tabs.query({ active: true, currentWindow: true }))[0]?.id || 0);
            if (ts && ts.linkMetrics && ts.linkMetrics.archiveDownloadLinks) {
              const crossDomainLinks = ts.linkMetrics.archiveDownloadLinks.filter(l => l.isCrossDomain);
              for (const link of crossDomainLinks) {
                try {
                  const dlDomain = new URL(link.href, 'http://placeholder').hostname;
                  await DownloadBlacklist.add(dlDomain, {
                    pageDomain: domain,
                    pageUrl: ''
                  }, link.ext || null);
                } catch (e) { /* ignore */ }
              }
            }
            sendResponse({ success: true, autoAction: 'blacklisted_downloads' });
          } else {
            sendResponse({ success: true });
          }
        } catch (e) {
          console.error('[ServiceWorker] 上报处理失败:', e);
          sendResponse({ success: false, error: e.message });
        }
      })();
      return true;
    }

    case MSG_TYPES.SETTINGS_UPDATED: {
      _settingsCache = null;
      console.log('[ServiceWorker] 设置已更新，缓存已失效');
      sendResponse({ received: true });
      break;
    }
    case MSG_TYPES.BULK_UPDATE_WHITELIST: {
      const domains = (message.payload && message.payload.domains) ? message.payload.domains : [];
      saveWhitelist(domains).then(async () => {
        await removeBlockersFromWhitelistedTabs();
        console.log('[ServiceWorker] 白名单已批量更新:', domains.length, '个域名');
        sendResponse({ success: true, count: domains.length });
      }).catch(e => {
        sendResponse({ success: false, error: e.message });
      });
      return true;
    }
    case MSG_TYPES.CHECK_UPDATE: {
      (async () => {
        await checkForUpdate();
        const r = await chrome.storage.local.get(STORAGE_KEYS.UPDATE_INFO);
        sendResponse({ success: true, data: r[STORAGE_KEYS.UPDATE_INFO] });
      })();
      return true;
    }
    default: { sendResponse({ error: 'unknown type: ' + type }); break; }
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
  _authenticationTabs.delete(tabId);
  cancelGateTimeout(tabId);
  _whoisPromises.delete(tabId);
});

// 标签页替换清理（如 prerender 激活、会话恢复时 tabId 变化）
// 将旧 tabId 的状态迁移到新 tabId（而非直接删除），避免激活页保持"未分析"；
// 旧 tabId 的会话级内存状态仍需清理。
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  (async () => {
    const oldState = await loadTabState(removedTabId);
    if (oldState && oldState.url) {
      await saveTabState(addedTabId, oldState);
    }
    await clearTabState(removedTabId);
  })().catch(() => {});
  _warningCooldown.delete(removedTabId);
  _authenticationTabs.delete(removedTabId);
  cancelGateTimeout(removedTabId);
  _whoisPromises.delete(removedTabId);
});

// 安装/更新
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[ServiceWorker] 扩展已安装/更新:', details.reason);
  if (details.reason === 'update') {
    await CacheManager.clearAll();
    await DownloadBlacklist.cleanup();
    // 一次性清理旧版遗留的 local tab_state（已迁移 chrome.storage.session）
    await cleanupLegacyLocalTabStates();
  }
  // 设置定时更新检查（每 24 小时）
  await chrome.alarms.create(ALARM_NAME_UPDATE_CHECK, { periodInMinutes: UPDATE_CHECK_PERIOD_MINUTES });
  // 设置定时缓存清理（每 6 小时，配额治理）
  await chrome.alarms.create(CACHE_CLEANUP_ALARM_NAME, { periodInMinutes: CACHE_CLEANUP_PERIOD_MINUTES });
  // 首次检查
  checkForUpdate();
});

// 定时 alarm 触发更新检查
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME_UPDATE_CHECK) {
    checkForUpdate();
  } else if (alarm.name === CACHE_CLEANUP_ALARM_NAME) {
    runCacheCleanup();
  }
});

/**
 * 周期缓存清理：删除过期 domain_cache + LRU 裁剪（保留最近 CACHE_LRU_KEEP_COUNT 条）。
 * 同时兼容旧版本升级：清理 local 中遗留的 tab_state_*（仅当当前介质为 session 时，
 * 避免 Firefox 回退路径下误删活跃标签页状态）。
 * 清理统计仅输出日志，不阻塞主流程。
 */
async function runCacheCleanup() {
  try {
    const stats = await CacheManager.cleanup({ keepRecentCount: CACHE_LRU_KEEP_COUNT });
    let legacyCleaned = 0;
    // 仅 session 可用时清理 local 残留（见 cleanupLegacyLocalTabStates 注释）
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
      try {
        const all = await chrome.storage.local.get(null);
        const legacyKeys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.TAB_STATE_PREFIX));
        if (legacyKeys.length > 0) {
          await chrome.storage.local.remove(legacyKeys);
          legacyCleaned = legacyKeys.length;
        }
      } catch (e) { /* 遗留清理失败不影响主清理 */ }
    }
    console.log(`[ServiceWorker] 缓存清理完成: 删除 ${stats.removed} 条(过期/LRU), 保留 ${stats.kept}/${stats.total} 条, 遗留 tab_state ${legacyCleaned} 条`);
  } catch (e) {
    console.error('[ServiceWorker] 缓存清理失败:', e.message);
  }
}

// 存储变更监听：白名单 / 黑名单 / 设置被其他页面修改时使内存缓存失效
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes[STORAGE_KEYS.WHITELIST]) {
      _invalidateWhitelistCache();
    }
    if (changes[STORAGE_KEYS.DOWNLOAD_BLACKLIST]) {
      DownloadBlacklist.invalidateCache();
    }
    if (changes[STORAGE_KEYS.GLOBAL_SETTINGS]) {
      _settingsCache = null;
      // 用户修改 cache_ttlHours 后即时生效（失效 CacheManager 的 TTL 缓存）
      invalidateCacheTtl();
    }
  }
});

console.log(`[ServiceWorker] ✅ 银狐木马检测扩展 v${VERSION} 已就绪`);





