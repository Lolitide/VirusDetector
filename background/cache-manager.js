/**
 * Virus Detector — 缓存管理器 (Cache Manager)
 *
 * 基于 chrome.storage.local 的域名检测结果缓存层。
 * 缓存 TTL = 24 小时（由 constants.js 中的 CACHE_TTL 配置）。
 * 恶意和安全结果均会缓存以减少重复分析。
 *
 * @module cache-manager
 *
 * 缓存条目结构：
 *   {
 *     domain: string,          // 被缓存的域名
 *     score: number,           // 上次检测总分
 *     isMalicious: boolean,    // 是否达到危险阈值
 *     correctUrl: string|null, // 正确官网 URL（若有）
 *     ruleResults: object,     // 五条规则的详细结果
 *     timestamp: number        // 缓存写入时间（毫秒时间戳）
 *   }
 *
 * 缓存失效条件：
 *   1. 超过 CACHE_TTL（24 小时）自动过期删除
 *   2. Content Script 发回新数据时绕过缓存直接重新分析
 *   3. 调用 remove() 方法主动删除（如移出白名单时）
 *   4. 周期清理（cleanup()，每 6 小时 alarm 触发）：删过期 + 按 lastAccess LRU 保留最近 100 条
 *   5. 配额紧急清理：set() 遇 QuotaExceeded 时先清理再重试写入，保证检测结果不丢失
 *   6. 官方/可信域名（DomainDatabase / TrustedPlatforms / isFullyTrusted）跳过读写
 *
 * 条目结构含 lastAccess 字段（get() 命中时限频刷新，供 LRU 裁剪）。
 */

import { STORAGE_KEYS, CACHE_TTL, HOUR_MS, CACHE_LRU_KEEP_COUNT, CACHE_LAST_ACCESS_REFRESH_MS } from '../utils/constants.js';
import { UrlUtils } from '../utils/url-utils.js';
import { DomainDatabase } from './domain-database.js';
import { TrustedPlatforms } from '../utils/trusted-platforms.js';
import { isFullyTrusted } from '../utils/exemptions/index.js';

/** 从用户设置读取缓存 TTL，回退到 CACHE_TTL */
let _cachedTtlMs = null;

/** 失效 TTL 缓存（用户修改 cache_ttlHours 时由 storage.onChanged 调用） */
export function invalidateCacheTtl() {
  _cachedTtlMs = null;
}

async function _getCacheTtlMs() {
  if (_cachedTtlMs !== null) return _cachedTtlMs;
  try {
    const r = await chrome.storage.local.get(STORAGE_KEYS.GLOBAL_SETTINGS);
    const gs = r[STORAGE_KEYS.GLOBAL_SETTINGS] || {};
    _cachedTtlMs = (gs.cache_ttlHours > 0 ? gs.cache_ttlHours * HOUR_MS : CACHE_TTL);
  } catch (e) { _cachedTtlMs = CACHE_TTL; }
  return _cachedTtlMs;
}

/**
 * 判定域名是否属于「无需缓存」的官方/可信范围：
 * 官方域名（DomainDatabase）、可信平台（TrustedPlatforms）、完全信任域（.gov.cn 等）
 * 检测结果恒定（pass），缓存无价值；守卫避免其条目占据宝贵的 storage.local 配额。
 * @param {string} domain - 完整 hostname（可能含子域）
 * @returns {boolean}
 */
function _isOfficialOrTrustedDomain(domain) {
  try {
    const mainDomain = UrlUtils.getMainDomain(domain);
    if (DomainDatabase.findByDomain(mainDomain)) return true;
    if (TrustedPlatforms.isTrusted(mainDomain)) return true;
    if (isFullyTrusted(domain)) return true;
  } catch (e) { /* 判定失败不阻塞缓存 */ }
  return false;
}

export class CacheManager {
  /**
   * 域名有效性检查：拒绝空字符串等无效域名，防止空键污染缓存
   * @param {string} domain
   * @returns {boolean}
   */
  static _isValidDomain(domain) {
    return typeof domain === 'string' && domain.length > 0;
  }

  /**
   * 获取域名的缓存结果
   * @param {string} domain
   * @returns {Object|null} 缓存结果，过期或不存在返回null
   */
  static async get(domain) {
    if (!this._isValidDomain(domain)) return null;
    // 官方/可信域无需缓存：跳过读取（避免旧版本已写入的官方域缓存被命中）
    if (_isOfficialOrTrustedDomain(domain)) return null;
    try {
      const key = STORAGE_KEYS.DOMAIN_CACHE + domain;
      const result = await chrome.storage.local.get(key);
      const entry = result[key];

      if (!entry) return null;

      if (Date.now() - entry.timestamp > await _getCacheTtlMs()) {
        await chrome.storage.local.remove(key);
        return null;
      }

      // 限频刷新 lastAccess（供 LRU 清理按访问热度裁剪；不 await，失败无影响）
      if (!entry.lastAccess || Date.now() - entry.lastAccess > CACHE_LAST_ACCESS_REFRESH_MS) {
        // 读回比对 timestamp：避免与并发 set()（异步 ICP 核验/新检测结果）交错时，
        // 旧快照整键覆盖写回新结果（score/timestamp 回退）。
        chrome.storage.local.get(key).then(r => {
          const cur = r[key];
          if (cur && cur.timestamp === entry.timestamp) {
            chrome.storage.local.set({ [key]: { ...cur, lastAccess: Date.now() } }).catch(() => {});
          }
        }).catch(() => {});
      }

      return entry;
    } catch (e) {
      console.error('[CacheManager] 读取缓存失败:', e);
      return null;
    }
  }

  /**
   * 设置域名缓存（含配额保护：失败时紧急清理后重试一次）
   * @param {string} domain
   * @param {Object} data - { score, isMalicious, correctUrl, ruleResults }
   */
  static async set(domain, data) {
    if (!this._isValidDomain(domain)) return;
    // 官方/可信域检测结果恒定，跳过写入，避免占用配额
    if (_isOfficialOrTrustedDomain(domain)) return;
    const key = STORAGE_KEYS.DOMAIN_CACHE + domain;
    const entry = {
      domain,
      score: data.score,
      isMalicious: data.isMalicious,
      correctUrl: data.correctUrl || null,
      ruleResults: data.ruleResults || {},
      timestamp: Date.now(),
      lastAccess: Date.now()
    };
    try {
      await chrome.storage.local.set({ [key]: entry });
    } catch (e) {
      const isQuotaError = e && (
        /quota/i.test(String(e.message)) || e.message.includes('QUOTA_BYTES')
      );
      if (isQuotaError) {
        // 配额耗尽：紧急清理（过期 + 最旧 LRU 条目）后重试一次（仅一次，避免死循环）；
        // 仍失败则静默丢弃该条缓存（下次访问重新分析，不影响检测正确性）
        try {
          const { removed } = await this.cleanup({ keepRecentCount: CACHE_LRU_KEEP_COUNT });
          await chrome.storage.local.set({ [key]: entry });
          console.warn(`[CacheManager] 配额紧急清理 ${removed} 条后写入成功:`, domain);
        } catch (e2) {
          console.error('[CacheManager] 配额紧急清理后仍写入失败:', e2);
        }
      } else {
        console.error('[CacheManager] 写入缓存失败:', e);
      }
    }
  }

  /**
   * 缓存清理：删除过期条目 + 按 lastAccess LRU 裁剪（保留最近 keepRecentCount 条）。
   * 供周期 alarm 与配额紧急清理共用。
   * @param {Object} [options]
   * @param {number} [options.keepRecentCount] - LRU 保留条数，默认 CACHE_LRU_KEEP_COUNT(100)
   * @returns {Promise<{removed: number, kept: number, total: number}>} 清理统计
   */
  static async cleanup(options = {}) {
    const keepRecentCount = options.keepRecentCount ?? CACHE_LRU_KEEP_COUNT;
    try {
      const all = await chrome.storage.local.get(null);
      const ttl = await _getCacheTtlMs();
      const now = Date.now();
      const cacheKeys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.DOMAIN_CACHE));
      const expired = [];
      const alive = [];
      for (const key of cacheKeys) {
        const entry = all[key];
        if (!entry || !entry.timestamp || now - entry.timestamp > ttl) {
          expired.push(key);
        } else {
          alive.push({ key, entry });
        }
      }
      // LRU：按 lastAccess（回退 timestamp）降序，保留最近 keepRecentCount 条
      alive.sort((a, b) =>
        (b.entry.lastAccess || b.entry.timestamp) - (a.entry.lastAccess || a.entry.timestamp)
      );
      const lruTrimmed = alive.slice(keepRecentCount).map(x => x.key);
      const toRemove = expired.concat(lruTrimmed);
      if (toRemove.length > 0) {
        await chrome.storage.local.remove(toRemove);
      }
      return { removed: toRemove.length, kept: alive.length - lruTrimmed.length, total: cacheKeys.length };
    } catch (e) {
      console.error('[CacheManager] 缓存清理失败:', e);
      return { removed: 0, kept: 0, total: 0 };
    }
  }

  /**
   * 删除指定域名的缓存
   * @param {string} domain
   */
  static async remove(domain) {
    if (!this._isValidDomain(domain)) return;
    try {
      const key = STORAGE_KEYS.DOMAIN_CACHE + domain;
      await chrome.storage.local.remove(key);
    } catch (e) {
      console.error('[CacheManager] 删除缓存失败:', e);
    }
  }

  /**
   * 清除所有域名缓存
   */
  static async clearAll() {
    try {
      const all = await chrome.storage.local.get(null);
      const keys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.DOMAIN_CACHE));
      if (keys.length > 0) {
        await chrome.storage.local.remove(keys);
        console.log(`[CacheManager] 已清除 ${keys.length} 条缓存`);
      }
    } catch (e) {
      console.error('[CacheManager] 清除缓存失败:', e);
    }
  }

  /**
   * 获取缓存统计
   */
  static async getStats() {
    try {
      const all = await chrome.storage.local.get(null);
      const keys = Object.keys(all).filter(k => k.startsWith(STORAGE_KEYS.DOMAIN_CACHE));
      const malicious = keys.filter(k => all[k]?.isMalicious).length;
      const safe = keys.length - malicious;
      return { total: keys.length, malicious, safe };
    } catch (e) {
      return { total: 0, malicious: 0, safe: 0 };
    }
  }
}
