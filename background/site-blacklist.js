/**
 * Virus Detector — 站点黑名单管理模块
 *
 * 管理用户手动标记的恶意网站域名列表，与下载黑名单（DownloadBlacklist）互补。
 * 站点黑名单标记"网站本身是恶意的"，在分析入口处直接赋予高分触发警告流程。
 *
 * @module site-blacklist
 *
 * 数据结构 (chrome.storage.local key: "site_blacklist"):
 *   {
 *     "phishing-site.com": {
 *       addedAt: 1700000000000,        // 添加时间 (ms)
 *       addedBy: "manual" | "popup",   // 添加来源: 手动输入 或 弹窗添加
 *       note: ""                       // 可选备注
 *     }
 *   }
 *
 * 维护策略：
 *   - 去重：同一域名不重复添加
 *   - 容量上限：500 条（与下载黑名单一致）
 *   - 无自动过期（站点黑名单由用户手动管理）
 */

import { 
  STORAGE_KEYS, DOWNLOAD_BLACKLIST_MAX_ENTRIES
} from '../utils/constants.js';
import { UrlUtils } from '../utils/url-utils.js';

export class SiteBlacklist {

  /** @type {Object|null} 内存缓存 */
  static _cache = null;

  // ==================== 读取操作 ====================

  /**
   * 加载完整站点黑名单（优先返回内存缓存）
   * @returns {Promise<Object>} 域名 → 条目信息的映射
   */
  static async getAll() {
    if (this._cache) return this._cache;
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.SITE_BLACKLIST);
      const data = r[STORAGE_KEYS.SITE_BLACKLIST] || {};
      this._cache = data;
      return data;
    } catch (e) {
      console.error('[SiteBlacklist] 读取失败:', e);
      return {};
    }
  }

  /**
   * 检查指定域名是否在站点黑名单中
   * @param {string} domain - 待检查的域名
   * @returns {Promise<boolean>}
   */
  static async isBlacklisted(domain) {
    if (!domain) return false;
    const normalized = domain.toLowerCase();
    // 精确匹配 + 主域名匹配（防止子域名绕过）
    const mainDomain = UrlUtils.getMainDomain(normalized);
    const blacklist = await this.getAll();
    return blacklist.hasOwnProperty(normalized) || blacklist.hasOwnProperty(mainDomain);
  }

  /**
   * 获取指定域名的黑名单条目
   * @param {string} domain
   * @returns {Promise<Object|null>}
   */
  static async getEntry(domain) {
    if (!domain) return null;
    const blacklist = await this.getAll();
    const normalized = domain.toLowerCase();
    const mainDomain = UrlUtils.getMainDomain(normalized);
    return blacklist[normalized] || blacklist[mainDomain] || null;
  }

  // ==================== 写入操作 ====================

  /**
   * 将域名加入站点黑名单（或更新已有条目）
   *
   * @param {string} domain - 站点域名
   * @param {Object} [info] - 附加信息
   * @param {string} [info.addedBy='manual'] - 添加来源: 'manual' | 'popup'
   * @param {string} [info.note=''] - 可选备注
   */
  static async add(domain, info = {}) {
    if (!domain) return;

    const normalized = domain.toLowerCase();
    const blacklist = await this.getAll();
    const now = Date.now();

    if (blacklist.hasOwnProperty(normalized)) {
      // 已存在：更新来源和备注
      const existing = blacklist[normalized];
      existing.addedBy = info.addedBy || existing.addedBy || 'manual';
      if (info.note) existing.note = info.note;
      console.log('[SiteBlacklist] 域名已存在，更新信息:', normalized);
      await this._save(blacklist);
      return;
    }

    // 新增条目
    this._enforceCapacity(blacklist, normalized);

    blacklist[normalized] = {
      addedAt: now,
      addedBy: info.addedBy || 'manual',
      note: info.note || ''
    };

    await this._save(blacklist);
    console.log('[SiteBlacklist] 已添加:', normalized);
  }

  /**
   * 从站点黑名单中移除指定域名
   * @param {string} domain
   * @returns {Promise<boolean>} true 表示确实移除了条目，false 表示域名不在黑名单中
   */
  static async remove(domain) {
    if (!domain) return false;
    const normalized = domain.toLowerCase();
    const mainDomain = UrlUtils.getMainDomain(normalized);
    const blacklist = await this.getAll();
    let removed = false;

    // 尝试精确匹配，再试主域名匹配
    if (blacklist.hasOwnProperty(normalized)) {
      delete blacklist[normalized];
      removed = true;
    } else if (blacklist.hasOwnProperty(mainDomain)) {
      delete blacklist[mainDomain];
      removed = true;
    }

    if (removed) {
      await this._save(blacklist);
      console.log('[SiteBlacklist] 已移除:', normalized);
    }
    return removed;
  }

  // ==================== 维护操作 ====================

  /**
   * 清空全部站点黑名单
   */
  static async clearAll() {
    this._cache = {};
    await this._save({});
    console.log('[SiteBlacklist] 已清空');
  }

  // ==================== 内部方法 ====================

  /**
   * 容量控制：超过上限时按 addedAt 升序（最早添加的优先）删除旧条目
   * @param {Object} blacklist
   * @param {string} newDomain
   */
  static _enforceCapacity(blacklist, newDomain) {
    const entries = Object.entries(blacklist);
    if (entries.length < DOWNLOAD_BLACKLIST_MAX_ENTRIES) return;

    // 按 addedAt 升序排列（最早添加的在前）
    entries.sort((a, b) => a[1].addedAt - b[1].addedAt);

    const toRemove = entries.slice(0, entries.length - DOWNLOAD_BLACKLIST_MAX_ENTRIES + 1);
    for (const [domain] of toRemove) {
      delete blacklist[domain];
    }
    console.log('[SiteBlacklist] 容量控制：移除', toRemove.length, '条旧记录');
  }

  /**
   * 持久化保存 + 同步内存缓存
   * @param {Object} blacklist
   */
  static async _save(blacklist) {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.SITE_BLACKLIST]: blacklist });
      this._cache = blacklist;
    } catch (e) {
      console.error('[SiteBlacklist] 保存失败:', e);
    }
  }

  /**
   * 使内存缓存失效（供 storage.onChanged 回调调用）
   */
  static invalidateCache() {
    this._cache = null;
  }
}
