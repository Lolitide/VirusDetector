import { SITE_BLACKLIST_MAX_ENTRIES, STORAGE_KEYS } from '../utils/constants.js';

export class SiteAccessManager {
  static _whitelist = null;
  static _blacklist = null;
  static _mutations = Promise.resolve();

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

  static async getWhitelist() {
    await this._load();
    return [...this._whitelist];
  }

  static async getSiteBlacklist() {
    await this._load();
    return Object.fromEntries(
      Object.entries(this._blacklist).map(([domain, entry]) => [domain, { ...entry }])
    );
  }

  static async isWhitelisted(value) {
    return (await this.getState(value)).isWhitelisted;
  }

  static async isBlacklisted(value) {
    return (await this.getState(value)).isBlacklisted;
  }

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

  static clearSiteBlacklist() {
    return this._mutate(async () => {
      await this._load();
      await this._save(this._whitelist, {});
    });
  }

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
