/**
 * 统一管理站点白名单与黑名单，负责主机名规范化、冲突消解、持久化和串行写入。
 * 名单按精确 hostname 匹配，避免共享托管域下的不同站点互相影响。
 *
 * @module site-access-manager
 */

import { SITE_BLACKLIST_MAX_ENTRIES, STORAGE_KEYS } from '../utils/constants.js';

export class SiteAccessManager {
  static _whitelist = null;
  static _blacklist = null;
  static _mutations = Promise.resolve();

  /**
   * 将 URL 或主机名转换为可用于名单匹配的 hostname。
   * @param {string} value URL 或主机名
   * @returns {string} 规范化主机名；无效输入返回空字符串
   */
  static normalizeDomain(value) {
    if (typeof value !== 'string' || !value.trim()) return '';
    try {
      const input = value.trim();
      const url = new URL(input.includes('://') ? input : `https://${input}`);
      const domain = url.hostname.toLowerCase().replace(/\.$/, '');
      if (!domain) return '';
      return domain;
    } catch {
      return '';
    }
  }

  /**
   * 查询一个站点当前的统一名单状态。
   * @param {string} value URL 或主机名
   * @returns {Promise<{domain:string,isWhitelisted:boolean,isBlacklisted:boolean}>}
   */
  static async getState(value) {
    const domain = this.normalizeDomain(value);
    if (!domain) return { domain: '', isWhitelisted: false, isBlacklisted: false };
    await this._load();
    return {
      domain,
      isWhitelisted: this._isCoveredBy(domain, this._whitelist),
      isBlacklisted: this._isCoveredBy(domain, new Set(Object.keys(this._blacklist)))
    };
  }

  /** @returns {Promise<string[]>} 当前白名单主机名 */
  static async getWhitelist() {
    await this._load();
    return [...this._whitelist];
  }

  /** @returns {Promise<Object<string, Object>>} 当前站点黑名单 */
  static async getSiteBlacklist() {
    await this._load();
    return Object.fromEntries(
      Object.entries(this._blacklist).map(([domain, entry]) => [domain, { ...entry }])
    );
  }

  /**
   * @param {string} value URL 或主机名
   * @returns {Promise<boolean>} 是否在白名单中
   */
  static async isWhitelisted(value) {
    return (await this.getState(value)).isWhitelisted;
  }

  /**
   * @param {string} value URL 或主机名
   * @returns {Promise<boolean>} 是否在黑名单中
   */
  static async isBlacklisted(value) {
    return (await this.getState(value)).isBlacklisted;
  }

  /**
   * 加入白名单，并删除同主机名的黑名单条目。
   * @param {string} value URL 或主机名
   * @returns {Promise<{domain:string,isWhitelisted:boolean,isBlacklisted:boolean}>}
   */
  static addToWhitelist(value) {
    return this._mutate(async () => {
      const domain = this._requireDomain(value);
      await this._load();

      const whitelist = new Set(this._whitelist);
      const blacklist = { ...this._blacklist };
      whitelist.add(domain);
      this._removeOverlappingEntries(blacklist, domain);

      await this._save(whitelist, blacklist);
      return { domain, isWhitelisted: true, isBlacklisted: false };
    });
  }

  /**
   * @param {string} value URL 或主机名
   * @returns {Promise<{domain:string,isWhitelisted:boolean,isBlacklisted:boolean}>} 更新后的状态
   */
  static removeFromWhitelist(value) {
    return this._mutate(async () => {
      const domain = this._requireDomain(value);
      await this._load();

      const whitelist = new Set(
        [...this._whitelist].filter(entry => !this._covers(entry, domain))
      );
      await this._save(whitelist, this._blacklist);
      return this.getState(domain);
    });
  }

  /**
   * 用给定列表整体替换白名单。
   * @param {string[]} values URL 或主机名列表
   * @returns {Promise<string[]>} 规范化后的白名单
   */
  static replaceWhitelist(values) {
    return this._mutate(async () => {
      await this._load();
      const whitelist = new Set(
        (Array.isArray(values) ? values : [])
          .map(value => this.normalizeDomain(value))
          .filter(Boolean)
      );
      const blacklist = { ...this._blacklist };

      for (const domain of whitelist) this._removeOverlappingEntries(blacklist, domain);
      await this._save(whitelist, blacklist);
      return [...whitelist];
    });
  }

  /**
   * 加入站点黑名单，并删除同主机名的白名单条目。
   * @param {string} value URL 或主机名
   * @param {{addedBy?:string,note?:string}} [info] 条目来源与备注
   * @returns {Promise<{domain:string,isWhitelisted:boolean,isBlacklisted:boolean}>}
   */
  static addToBlacklist(value, info = {}) {
    return this._mutate(async () => {
      const domain = this._requireDomain(value);
      await this._load();

      const whitelist = new Set(
        [...this._whitelist].filter(entry => !this._domainsOverlap(entry, domain))
      );
      const blacklist = {
        ...this._blacklist,
        [domain]: {
          ...this._blacklist[domain],
          addedAt: this._blacklist[domain]?.addedAt || Date.now(),
          addedBy: info.addedBy || this._blacklist[domain]?.addedBy || 'manual',
          note: info.note || this._blacklist[domain]?.note || ''
        }
      };

      this._trimBlacklist(blacklist);
      await this._save(whitelist, blacklist);
      return { domain, isWhitelisted: false, isBlacklisted: true };
    });
  }

  /**
   * @param {string} value URL 或主机名
   * @returns {Promise<{domain:string,removed:boolean}>} 删除结果
   */
  static removeFromBlacklist(value) {
    return this._mutate(async () => {
      const domain = this._requireDomain(value);
      await this._load();

      const blacklist = { ...this._blacklist };
      const removed = this._removeCoveredEntries(blacklist, domain);
      if (removed) await this._save(this._whitelist, blacklist);
      return { domain, removed };
    });
  }

  /** @returns {Promise<void>} */
  static clearSiteBlacklist() {
    return this._mutate(async () => {
      await this._load();
      await this._save(this._whitelist, {});
    });
  }

  /**
   * 使受 storage.onChanged 影响的内存缓存失效。
   * @param {Object<string, chrome.storage.StorageChange>} [changes] 存储变更
   * @returns {void}
   */
  static invalidate(changes = {}) {
    if (!Object.keys(changes).length || changes[STORAGE_KEYS.WHITELIST]) this._whitelist = null;
    if (!Object.keys(changes).length || changes[STORAGE_KEYS.SITE_BLACKLIST]) this._blacklist = null;
  }

  static async _load() {
    if (this._whitelist && this._blacklist) return;

    let stored = {};
    try {
      stored = await chrome.storage.local.get([
        STORAGE_KEYS.WHITELIST,
        STORAGE_KEYS.SITE_BLACKLIST
      ]);
    } catch {}

    if (!this._whitelist) {
      this._whitelist = new Set(
        (stored[STORAGE_KEYS.WHITELIST] || [])
          .map(value => this.normalizeDomain(value))
          .filter(Boolean)
      );
    }

    if (!this._blacklist) {
      this._blacklist = {};
      for (const [value, entry] of Object.entries(stored[STORAGE_KEYS.SITE_BLACKLIST] || {})) {
        const domain = this.normalizeDomain(value);
        if (domain) this._blacklist[domain] = { ...entry };
      }
    }

    const conflictingDomains = Object.keys(this._blacklist)
      .filter(domain => this._whitelist.has(domain));
    if (conflictingDomains.length) {
      const whitelist = new Set(this._whitelist);
      for (const domain of conflictingDomains) whitelist.delete(domain);
      await this._save(whitelist, this._blacklist);
    }
  }

  static async _save(whitelist, blacklist) {
    const nextWhitelist = new Set(whitelist);
    const nextBlacklist = Object.fromEntries(
      Object.entries(blacklist).map(([domain, entry]) => [domain, { ...entry }])
    );

    await chrome.storage.local.set({
      [STORAGE_KEYS.WHITELIST]: [...nextWhitelist].sort(),
      [STORAGE_KEYS.SITE_BLACKLIST]: nextBlacklist
    });

    this._whitelist = nextWhitelist;
    this._blacklist = nextBlacklist;
  }

  static _mutate(task) {
    const operation = this._mutations.then(task, task);
    this._mutations = operation.catch(() => {});
    return operation;
  }

  static _requireDomain(value) {
    const domain = this.normalizeDomain(value);
    if (!domain) throw new Error('invalid_domain');
    return domain;
  }

  static _covers(entry, domain) {
    return entry === domain;
  }

  static _domainsOverlap(left, right) {
    return this._covers(left, right) || this._covers(right, left);
  }

  static _isCoveredBy(domain, entries) {
    for (const entry of entries) {
      if (this._covers(entry, domain)) return true;
    }
    return false;
  }

  static _removeOverlappingEntries(entries, domain) {
    for (const entry of Object.keys(entries)) {
      if (this._domainsOverlap(entry, domain)) delete entries[entry];
    }
  }

  static _removeCoveredEntries(entries, domain) {
    let removed = false;
    for (const entry of Object.keys(entries)) {
      if (!this._covers(entry, domain)) continue;
      delete entries[entry];
      removed = true;
    }
    return removed;
  }

  static _trimBlacklist(blacklist) {
    const entries = Object.entries(blacklist);
    if (entries.length <= SITE_BLACKLIST_MAX_ENTRIES) return;
    entries.sort((left, right) => (left[1].addedAt || 0) - (right[1].addedAt || 0));
    for (const [domain] of entries.slice(0, entries.length - SITE_BLACKLIST_MAX_ENTRIES)) {
      delete blacklist[domain];
    }
  }
}
