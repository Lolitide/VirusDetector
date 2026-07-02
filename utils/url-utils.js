/**
 * Virus Detector — URL 解析工具
 *
 * 提供域名提取、主域解析（基于 publicsuffix.zone DNS PSL）、HTTPS 检测等 URL 处理能力。
 *
 * @module url-utils
 * @version 2.2.4
 *
 * PSL 查询策略：
 *   - 通过 DNS-over-HTTPS 查询 publicsuffix.zone 获取域名的公共后缀
 *   - 查询结果缓存于内存 Map，服务 worker 生命周期内有效
 *   - DNS 不可用时回退到最小 TLD 集
 */

// ==================== PSL 缓存与回退 ====================

/** @type {Map<string, string>} hostname -> public suffix 缓存（由 DoH 异步查询填充） */
const _pslCache = new Map();

/**
 * 回退 TLD 集：仅包含全球顶级域。
 * 当 DNS 查询不可用时使用，覆盖最基础的 .com / .cn / .org 等。
 */
const _FALLBACK_TLD = new Set([
  // 单级 TLD
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
  'info', 'biz', 'name', 'pro', 'mobi', 'tel', 'asia',
  'xxx', 'shop', 'online', 'site', 'app', 'dev', 'blog', 'tech',
  'store', 'cloud', 'xyz', 'top', 'work', 'click', 'link',
  'download', 'zip', 'review', 'country', 'kim', 'gq', 'ml',
  'cf', 'ga', 'tk', 'io', 'ai', 'me', 'tv', 'cc', 'ws', 'fm',
  'co', 'so', 'vc', 'pw', 'cn', 'uk', 'jp', 'kr', 'tw', 'hk',
  'sg', 'in', 'au', 'nz', 'de', 'fr', 'it', 'es', 'nl', 'be',
  'ch', 'at', 'se', 'no', 'dk', 'fi', 'ie', 'pt', 'ru', 'br',
  'mx', 'ca', 'us', 'th', 'vn', 'ph', 'my', 'id', 'pk', 'bd',
  // 常见多级公共后缀（DNS 不可用时的回退，覆盖最常用的场景）
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'org.tw', 'net.tw', 'gov.tw', 'edu.tw',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx',
  'co.za', 'web.za', 'org.za', 'net.za', 'gov.za',
]);

/**
 * 同步获取域名的公共后缀
 * 优先查 DNS 缓存，其次用回退 TLD 集匹配，最后返回末段
 * @param {string} hostname
 * @returns {string} 公共后缀
 */
function getPublicSuffix(hostname) {
  // 1. DNS 缓存命中（由 refreshPublicSuffixDNS 异步填充）
  const cached = _pslCache.get(hostname);
  // 二次验证：缓存的 suffix 必须是 hostname 的有效后缀，防止无效数据污染
  if (cached && (hostname.endsWith('.' + cached) || hostname === cached)) {
    // 额外验证：缓存的后缀必须能让 extractRegistrableDomain 提取出比 hostname 更短的域名
    // 防止多级公共后缀（如 github.io、herokuapp.com）导致可注册域名等于原始域名，
    // 使后续 WHOIS/RDAP 查询失败（GitHub Pages 子域名没有独立注册信息）
    const cachedParts = cached.split('.');
    const hostParts = hostname.split('.');
    if (cachedParts.length < hostParts.length - 1) {
      return cached;
    }
    // 若后缀长度 >= hostname-1，则 registrable = hostname，对 WHOIS 无意义
    // 回退到 fallback（不淘汰缓存，不影响未来的查询策略变化）
  }

  // 2. 回退匹配：从最右段开始逐级向左扩展，找到 PSL 中最长的连续匹配
  //    例如 xxx.com.cn: cn✓ → com.cn✗(不在回退集) → 返回 cn
  //    若回退集包含 com.cn 则: cn✓ → com.cn✓ → xxx.com.cn✗ → 返回 com.cn
  const parts = hostname.split('.');
  let publicSuffix = parts[parts.length - 1] || ''; // 起始至少匹配 TLD
  for (let len = 2; len <= parts.length; len++) {
    const candidate = parts.slice(-len).join('.');
    if (_FALLBACK_TLD.has(candidate)) {
      publicSuffix = candidate; // 扩展为更长匹配
    } else {
      break; // 不再存在于 PSL，停止扩展
    }
  }
  return publicSuffix;
}

/**
 * 基于公共后缀提取可注册域名 (Registrable Domain)。
 *
 * 算法：获取公共后缀 -> 取后缀 + 前面一段
 *
 * 示例：
 *   roms.lian86.top     + PSL="top"    -> lian86.top
 *   www.baidu.com       + PSL="com"    -> baidu.com
 *   www.pc-sysceo.hl.cn + PSL="hl.cn"  -> pc-sysceo.hl.cn
 *   sub.example.co.uk   + PSL="co.uk"  -> example.co.uk
 *
 * @param {string} hostname - 完整主机名
 * @returns {string} 可注册域名
 */
function extractRegistrableDomain(hostname) {
  if (!hostname || !hostname.includes('.')) return hostname;

  const parts = hostname.toLowerCase().split('.');
  if (parts.length < 2) return hostname;

  const publicSuffix = getPublicSuffix(hostname);
  const suffixParts = publicSuffix.split('.');
  const source = _pslCache.has(hostname) ? 'dns-cache' : 'fallback';

  if (suffixParts.length >= parts.length) {
    console.log(`[UrlUtils] PSL extract: ${hostname} -> suffix="${publicSuffix}" (${source}) -> no registrable label, keep original`);
    return hostname;
  }

  const registrable = parts.slice(-(suffixParts.length + 1)).join('.');

  if (!registrable.includes('.')) {
    console.log(`[UrlUtils] PSL extract: ${hostname} -> suffix="${publicSuffix}" (${source}) -> would be "${registrable}", keeping original`);
    return hostname;
  }

  console.log(`[UrlUtils] PSL extract: ${hostname} -> suffix="${publicSuffix}" (${source}) -> "${registrable}"`);
  return registrable;
}

/**
 * 通过 DoH 异步查询域名的公共后缀（基于 publicsuffix.zone）
 * 由 WhoisClient 调用以预热缓存，不阻塞当前请求
 * @param {string} hostname - 待查询域名
 * @returns {Promise<string|null>} 公共后缀（如 "top"），失败返回 null
 */
export async function refreshPublicSuffixDNS(hostname) {
  const queryName = `${hostname}.query.publicsuffix.zone`;
  const url = `https://dns.google/resolve?name=${encodeURIComponent(queryName)}&type=PTR`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) return null;

    const json = await response.json();
    if (json.Status !== 0 || !json.Answer || json.Answer.length === 0) return null;

    const raw = json.Answer[0].data;
    if (!raw || typeof raw !== 'string') return null;

    // publicsuffix.zone PTR 响应返回的是完整路径（如 "xyz.query.publicsuffix.zone."），
    // 需要剥离 ".query.publicsuffix.zone" 得到纯后缀（如 "xyz"）
    let suffix = raw.replace(/\.$/, '');
    if (suffix.endsWith('.query.publicsuffix.zone')) {
      suffix = suffix.replace(/\.query\.publicsuffix\.zone$/, '');
    }

    // 验证：后缀必须是 hostname 的合法后缀，防止无效数据污染缓存
    if (!hostname.endsWith('.' + suffix) && hostname !== suffix) {
      console.warn(`[UrlUtils] DoH PSL 返回无效后缀 "${suffix}" for ${hostname}，忽略`);
      return null;
    }

    // 验证：缓存后缀必须能让 extractRegistrableDomain 提取出比 hostname 更短的域名
    // 防止多级公共后缀（如 github.io）投毒缓存，导致查询结果不一致
    const _suffixParts = suffix.split('.');
    const _hostParts = hostname.split('.');
    if (_suffixParts.length >= _hostParts.length - 1) {
      console.log(`[UrlUtils] DoH PSL suffix "${suffix}" for ${hostname} 不会缩短域名，跳过缓存`);
      return suffix;
    }

    _pslCache.set(hostname, suffix);
    console.log(`[UrlUtils] DNS PSL cache updated: ${hostname} -> "${suffix}"`);
    return suffix;
  } catch (e) {
    console.warn(`[UrlUtils] DoH PSL query failed (${hostname}):`, e.message);
    return null;
  }
}

// ==================== UrlUtils 类 ====================

export class UrlUtils {
  /**
   * 从完整URL中提取主机名（域名）
   * @param {string} url - 完整URL
   * @returns {string} 主机名
   */
  static extractHostname(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (e) {
      if (!url.startsWith('http')) {
        try {
          const fixed = new URL('https://' + url);
          return fixed.hostname;
        } catch (e2) {
          return url;
        }
      }
      return url;
    }
  }

  /**
   * 获取可注册域名（基于 PSL）
   * 替代原来的 "取最后两段" 简化逻辑，支持多级公共后缀（co.uk / com.cn 等）
   * @param {string} hostname - 主机名
   * @returns {string} 可注册域名
   */
  static getMainDomain(hostname) {
    return extractRegistrableDomain(hostname);
  }

  /**
   * 检查两个域名是否属于同一主域名
   * @param {string} hostname1
   * @param {string} hostname2
   * @returns {boolean}
   */
  static isSameMainDomain(hostname1, hostname2) {
    return this.getMainDomain(hostname1) === this.getMainDomain(hostname2);
  }

  /**
   * 检查URL是否使用HTTPS
   * @param {string} url
   * @returns {boolean}
   */
  static isHttps(url) {
    try {
      return new URL(url).protocol === 'https:';
    } catch (e) {
      return url.toLowerCase().startsWith('https://');
    }
  }

  /**
   * 获取URL的完整来源（协议+主机名）
   * @param {string} url
   * @returns {string}
   */
  static getOrigin(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.origin;
    } catch (e) {
      return url;
    }
  }

  /**
   * 从主机名中移除开头的 www
   * @param {string} hostname
   * @returns {string}
   */
  static removeWWW(hostname) {
    return hostname.replace(/^www\./i, '');
  }
}
