/**
 * Virus Detector — 缓存管理器 (Cache Manager)
 *
 * 基于 chrome.storage.local 的域名检测结果缓存层。
 * 缓存 TTL = 24 小时（由 constants.js 中的 CACHE_TTL 配置）。
 * 恶意和安全结果均会缓存以减少重复分析。
 *
 * @module cache-manager
 * @version 2.2.4
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
 */

import { STORAGE_KEYS, CACHE_TTL } from '../utils/constants.js';

export class CacheManager {
  /**
   * 获取域名的缓存结果
   * @param {string} domain
   * @returns {Object|null} 缓存结果，过期或不存在返回null
   */
  static async get(domain) {
    try {
      const key = STORAGE_KEYS.DOMAIN_CACHE + domain;
      const result = await chrome.storage.local.get(key);
      const entry = result[key];

      if (!entry) return null;

      // 检查是否过期
      if (Date.now() - entry.timestamp > CACHE_TTL) {
        // 过期删除
        await chrome.storage.local.remove(key);
        return null;
      }

      return entry;
    } catch (e) {
      console.error('[CacheManager] 读取缓存失败:', e);
      return null;
    }
  }

  /**
   * 设置域名缓存
   * @param {string} domain
   * @param {Object} data - { score, isMalicious, correctUrl, ruleResults }
   */
  static async set(domain, data) {
    try {
      const key = STORAGE_KEYS.DOMAIN_CACHE + domain;
      await chrome.storage.local.set({
        [key]: {
          domain,
          score: data.score,
          isMalicious: data.isMalicious,
          correctUrl: data.correctUrl || null,
          ruleResults: data.ruleResults || {},
          timestamp: Date.now()
        }
      });
    } catch (e) {
      console.error('[CacheManager] 写入缓存失败:', e);
    }
  }

  /**
   * 删除指定域名的缓存
   * @param {string} domain
   */
  static async remove(domain) {
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
