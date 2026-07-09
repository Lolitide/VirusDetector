/**
 * Virus Detector — 下载域名黑名单管理模块
 *
 * 管理用户手动标记的恶意下载域名列表，实现跨站情报复用。
 * 当一个钓鱼站在某个下载域名上被用户确认为恶意后，该域名进入黑名单，
 * 此后任何其他网站若有链接指向同一下载域名，都会自动增加风险评分。
 *
 * @module download-blacklist
 *
 * 数据结构 (chrome.storage.local key: "download_blacklist"):
 *   {
 *     "evil-cdn.com": {
 *       addedAt: 1700000000000,        // 首次加入时间 (ms)
 *       addedBy: "user_block",         // 来源标识
 *       sourcePages: [{                // 发现此下载域名的源页面
 *         pageDomain: "phishing-a.com",
 *         pageUrl: "https://phishing-a.com/download",
 *         timestamp: 1700000000000
 *       }],
 *       fileTypes: [".zip", ".rar"],   // 见过的压缩包类型
 *       hitCount: 3,                   // 命中次数
 *       lastHit: 1700000000000         // 最近命中时间
 *     }
 *   }
 *
 * 维护策略：
 *   - 去重：同一域名不重复添加，更新 sourcePages / hitCount / fileTypes
 *   - 过期清理：90 天无命中自动删除（安装/更新时触发）
 *   - 容量上限：最多 500 条
 */

import { STORAGE_KEYS, DOWNLOAD_BLACKLIST_CLEANUP_DAYS, DOWNLOAD_BLACKLIST_MAX_ENTRIES } from '../utils/constants.js';
import { UrlUtils } from '../utils/url-utils.js';

export class DownloadBlacklist {

  /** @type {Object|null} 内存缓存 */
  static _cache = null;

  // ==================== 读取操作 ====================

  /**
   * 加载完整黑名单（优先返回内存缓存）
   * @returns {Promise<Object>} 域名 → 条目信息的映射
   */
  static async getAll() {
    if (this._cache) return this._cache;
    try {
      const r = await chrome.storage.local.get(STORAGE_KEYS.DOWNLOAD_BLACKLIST);
      const data = r[STORAGE_KEYS.DOWNLOAD_BLACKLIST] || {};
      this._cache = data;
      return data;
    } catch (e) {
      return {};
    }
  }

  /**
   * 检查指定域名是否在黑名单中
   * @param {string} domain - 待检查的域名（如 "evil-cdn.com"）
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
   * 获取指定域名的黑名单条目（含命中统计）
   * @param {string} domain
   * @returns {Promise<Object|null>} 条目对象，不存在时返回 null
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
   * 将下载域名加入黑名单（或更新已有条目）
   *
   * @param {string} domain - 下载来源域名
   * @param {Object} sourcePageInfo - 触发标记的源页面信息
   * @param {string} sourcePageInfo.pageDomain - 源页面域名
   * @param {string} sourcePageInfo.pageUrl - 源页面完整 URL
   * @param {string} [fileType] - 下载文件扩展名（如 ".zip"）
   */
  static async add(domain, sourcePageInfo, fileType) {
    if (!domain) return;

    const normalized = domain.toLowerCase();
    const blacklist = await this.getAll();
    const now = Date.now();
    const existing = blacklist[normalized];

    if (existing) {
      // 更新已有条目
      existing.hitCount += 1;
      existing.lastHit = now;
      // 追加源页面（去重，最多保留 20 条）
      const isDuplicate = existing.sourcePages.some(
        p => p.pageDomain === sourcePageInfo.pageDomain
      );
      if (!isDuplicate) {
        existing.sourcePages.push({
          pageDomain: sourcePageInfo.pageDomain,
          pageUrl: sourcePageInfo.pageUrl || '',
          timestamp: now
        });
        if (existing.sourcePages.length > 20) {
          existing.sourcePages = existing.sourcePages.slice(-20);
        }
      }
      // 追加文件类型
      if (fileType && !existing.fileTypes.includes(fileType)) {
        existing.fileTypes.push(fileType);
      }
    } else {
      // 新增条目
      this._enforceCapacity(blacklist, normalized);

      blacklist[normalized] = {
        addedAt: now,
        addedBy: 'user_block',
        sourcePages: [{
          pageDomain: sourcePageInfo.pageDomain,
          pageUrl: sourcePageInfo.pageUrl || '',
          timestamp: now
        }],
        fileTypes: fileType ? [fileType] : [],
        hitCount: 1,
        lastHit: now
      };
    }

    await this._save(blacklist);
    console.log('[DownloadBlacklist] 已更新黑名单:', normalized, blacklist[normalized].hitCount);
  }

  /**
   * 从黑名单中移除指定域名
   * @param {string} domain
   */
  static async remove(domain) {
    if (!domain) return;
    const normalized = domain.toLowerCase();
    const blacklist = await this.getAll();
    if (blacklist.hasOwnProperty(normalized)) {
      delete blacklist[normalized];
      await this._save(blacklist);
      console.log('[DownloadBlacklist] 已从黑名单移除:', normalized);
    }
  }

  // ==================== 维护操作 ====================

  /**
   * 清理过期条目（最后命中时间距今超过 CLEANUP_DAYS 天）
   * 在扩展安装/更新时由 Service Worker 调用
   */
  static async cleanup() {
    const blacklist = await this.getAll();
    const now = Date.now();
    const threshold = DOWNLOAD_BLACKLIST_CLEANUP_DAYS * 24 * 60 * 60 * 1000;
    let removedCount = 0;

    for (const [domain, entry] of Object.entries(blacklist)) {
      if (now - entry.lastHit > threshold) {
        delete blacklist[domain];
        removedCount++;
      }
    }

    if (removedCount > 0) {
      await this._save(blacklist);
      console.log('[DownloadBlacklist] 过期清理:', removedCount, '条');
    }
  }

  /**
   * 清空全部黑名单
   */
  static async clearAll() {
    this._cache = {};
    await this._save({});
    console.log('[DownloadBlacklist] 已清空');
  }

  // ==================== 内部方法 ====================

  /**
   * 容量控制：黑名单条目数超过上限时，按 lastHit 升序（最久未命中的优先）删除旧条目
   * @param {Object} blacklist - 当前黑名单对象（会被原地修改）
   * @param {string} newDomain - 即将新增的域名（用于判断是否需要腾出空间）
   */
  static _enforceCapacity(blacklist, newDomain) {
    const entries = Object.entries(blacklist);
    // 为即将新增的条目预留空间
    if (entries.length < DOWNLOAD_BLACKLIST_MAX_ENTRIES) return;

    // 按 lastHit 升序排列（最久未命中的在前）
    entries.sort((a, b) => a[1].lastHit - b[1].lastHit);

    // 删除最旧的条目直到在容量限制内
    const toRemove = entries.slice(0, entries.length - DOWNLOAD_BLACKLIST_MAX_ENTRIES + 1);
    for (const [domain] of toRemove) {
      delete blacklist[domain];
    }
    console.log('[DownloadBlacklist] 容量控制：移除', toRemove.length, '条旧记录');
  }

  /**
   * 持久化保存黑名单 + 同步内存缓存
   * @param {Object} blacklist
   */
  static async _save(blacklist) {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.DOWNLOAD_BLACKLIST]: blacklist });
      this._cache = blacklist;
    } catch (e) {
      console.error('[DownloadBlacklist] 保存失败:', e);
    }
  }

  /**
   * 使内存缓存失效（供 storage.onChanged 回调调用）
   */
  static invalidateCache() {
    this._cache = null;
  }
}
