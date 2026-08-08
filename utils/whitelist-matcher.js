/**
 * Virus Detector — 白名单域名匹配工具
 *
 * 支持三类白名单条目：
 *   1. 精确域名：example.com            → 仅匹配该主机名
 *   2. 通配符域名：*.example.com        → 匹配 example.com 及其所有子域名（任意层级）
 *   3. 全匹配：*                         → 匹配所有域名（完全跳过检测，请谨慎使用）
 *
 * 主机名比较大小写不敏感：所有入参统一小写、去除首尾空白与多余点号后再比较
 *
 * 该模块为纯函数、无 chrome 依赖，便于在 node 单元测试中直接 import
 *
 * @module whitelist-matcher
 */

/**
 * 规范化白名单条目：
 *   - 去除首尾空白
 *   - 转小写（域名大小写不敏感）
 *   - 去除误粘贴的协议（https://）、路径、端口，仅保留主机名或通配符模式
 *   - 去除尾随点号
 * @param {string} raw
 * @returns {string} 规范化后的条目，无效空串返回 ''
 */
export function normalizeWhitelistEntry(raw) {
  if (raw === null || raw === undefined) return '';
  let s = String(raw).trim().toLowerCase();
  if (!s) return '';

  // 去除协议前缀（http:// 或 https://）
  s = s.replace(/^https?:\/\//, '');
  // 去除路径与查询（取第一个 / 之前的部分）
  s = s.split('/')[0];
  // 去除端口（取第一个 : 之前的部分）
  s = s.split(':')[0];

  // 通配符条目处理：
  //   - 单独的 "*"            → 合法的全匹配
  //   - "*.example.com"      → 合法通配符（后缀非空）
  //   - "*.", "*.." 等后缀为空 → 视为无效条目（返回 ''）
  if (s.startsWith('*')) {
    if (s === '*') return '*';
    const rest = s.slice(1).replace(/^\.+/, '').replace(/\.+$/, '');
    if (rest === '') return '';
  }

  // 去除尾随点号（*.example.com. -> *.example.com）
  s = s.replace(/\.+$/, '');

  return s;
}

/**
 * 判断条目是否为通配符模式（含 *）
 * @param {string} entry
 * @returns {boolean}
 */
export function isWildcardPattern(entry) {
  return typeof entry === 'string' && entry.includes('*');
}

/**
 * 判断单个主机名是否匹配单个白名单条目（支持通配符）
 * @param {string} hostname 待匹配主机名（任意大小写均可）
 * @param {string} entry 白名单条目（精确域名 / *.domain / *）
 * @returns {boolean}
 */
export function matchWhitelistEntry(hostname, entry) {
  const h = normalizeWhitelistEntry(hostname);
  const e = normalizeWhitelistEntry(entry);
  if (!h || !e) return false;

  // 全匹配：* 命中任意主机名
  if (e === '*') return true;

  // 通配符前缀：*.example.com 匹配 example.com 及其所有子域名（任意层级）
  if (e.startsWith('*.')) {
    const suffix = e.slice(2);          // example.com
    if (!suffix) return false;          // 形如 "*." 或 "*.." 视为无效，不匹配
    return h === suffix || h.endsWith('.' + suffix);
  }

  // 精确匹配（其余含 * 的位置不作特殊处理，按字面比较，通常不会命中真实主机名）
  return h === e;
}

/**
 * 判断主机名是否被白名单命中（遍历所有条目，支持通配符）
 * @param {string} hostname 待匹配主机名
 * @param {string[]} whitelist 白名单条目数组
 * @returns {boolean}
 */
export function isWhitelistedDomain(hostname, whitelist) {
  if (!Array.isArray(whitelist) || whitelist.length === 0) return false;
  for (const entry of whitelist) {
    if (matchWhitelistEntry(hostname, entry)) return true;
  }
  return false;
}
