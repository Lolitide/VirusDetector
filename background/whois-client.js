/**
 * Virus Detector — 域名注册信息查询客户端 (Whois Client)
 *
 * 统一的域名查询入口：RDAP（主）→ WhoisCX API（回退），双查询架构。
 * RDAP 基于 RFC 9082/9083 协议，WhoisCX 作为全球覆盖的备用查询。
 *
 * @module whois-client
 * @version 2.2.4
 *
 * 查询链路：
 *   WhoisClient.lookup(domain)
 *     → PSL 域名标准化 (UrlUtils.getMainDomain)
 *     → 缓存检查
 *     → 1st: RdapClient.lookup(domain)    // RDAP 协议（主查询）
 *     → 2nd: WhoisCX API                   // HTTP 回退（备用）
 *     → 写入缓存 → 返回 WhoisResult
 *
 * 缓存策略：
 *   - 内存 Map 缓存，TTL = 24 小时（由 constants.js 中的 WHOIS_CACHE_TTL 配置）
 *   - RDAP 和 WhoisCX 共享同一缓存
 *   - 缓存命中直接返回，不发起任何网络请求
 *   - 查询失败（网络错误、超时、HTTP 异常）不缓存，下次请求重试
 *   - RDAP 404（域名未注册）不缓存
 *
 * WhoisCX API 规范：
 *   - 接口地址：GET http://api.whoiscx.com/whois/?domain={domain}
 *   - ⚠️ 仅支持 HTTP（不支持 HTTPS）
 *   - 响应格式：application/json
 *   - 频率限制：2 秒/次（通过串行化请求保证）
 */

import {
  WHOIS_API_URL, WHOIS_CACHE_TTL, WHOIS_API_TIMEOUT
} from '../utils/constants.js';
import { RdapClient } from './rdap-client.js';
import { refreshPublicSuffixDNS } from '../utils/url-utils.js';
import { UrlUtils } from '../utils/url-utils.js';

// ==================== 内存缓存 ====================

/**
 * @typedef {Object} WhoisCacheEntry
 * @property {WhoisResult} result    - 缓存的查询结果
 * @property {number}      timestamp - 缓存时间戳
 */

/** @type {Map<string, WhoisCacheEntry>} */
const _cache = new Map();

// ==================== WhoisCX 速率限制 ====================

/** 上次 WhoisCX API 请求完成的时间戳（用于速率限制） */
let _lastWhoisRequestTime = 0;

/** WhoisCX API 最小请求间隔（毫秒），保护免费 API 不被封禁 */
const MIN_WHOIS_INTERVAL = 2100; // 略大于 2 秒

/**
 * 等待直到满足 WhoisCX 速率限制要求
 * @returns {Promise<void>}
 */
async function _waitForWhoisRateLimit() {
  const now = Date.now();
  const elapsed = now - _lastWhoisRequestTime;
  if (elapsed < MIN_WHOIS_INTERVAL) {
    await new Promise(resolve => setTimeout(resolve, MIN_WHOIS_INTERVAL - elapsed));
  }
  _lastWhoisRequestTime = Date.now();
}

// ==================== 错误信息记录 ====================

/** @type {WhoisErrorInfo|null} 最近一次查询失败的错误详情 */
let _lastError = null;

/**
 * 记录错误信息并输出到控制台
 * @param {string} domain     - 查询的域名
 * @param {string} phase      - 失败阶段
 * @param {string} message    - 错误描述
 * @param {Object} [extra={}] - 附加调试信息
 */
function _recordError(domain, phase, message, extra = {}) {
  _lastError = {
    domain,
    phase,
    message,
    timestamp: Date.now(),
    ...extra
  };

  const phaseLabel = {
    'bootstrap':  'RDAP 引导文件错误',
    'connect':    '网络连接失败',
    'http_status': 'HTTP 状态异常',
    'parse':      '响应解析失败',
    'timeout':    '请求超时',
    'not_found':  '域名未注册',
    'invalid':    '参数无效'
  }[phase] || phase;

  const extraSummary = Object.keys(extra).length ? JSON.stringify(extra) : '';
  console.error(`[WhoisClient] ${phaseLabel} (${domain}): ${message}${extraSummary ? ' | ' + extraSummary : ''}`);
}

// ==================== 辅助函数 ====================

/**
 * 从 creation_time 日期字符串计算已注册天数
 * WhoisCX API 返回格式如 "2012-04-25 12:36:40" 或 "2012-04-25"
 * @param {string} timeStr - 创建时间字符串
 * @returns {number} 天数，解析失败返回 -1
 */
function _parseDaysFromWhoisCxTime(timeStr) {
  if (!timeStr || typeof timeStr !== 'string') return -1;
  try {
    const match = timeStr.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return -1;
    const creationDate = new Date(
      parseInt(match[1], 10),
      parseInt(match[2], 10) - 1,
      parseInt(match[3], 10)
    );
    if (isNaN(creationDate.getTime())) return -1;
    const diffMs = Date.now() - creationDate.getTime();
    if (diffMs < 0) return -1;
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  } catch (e) {
    return -1;
  }
}

// ==================== 父域名回退查询（防御加固）====================

/**
 * 当标准查询路径失败时，逐级向上回退父域名。
 * 处理多级公共后缀子域名（如 a.b.github.io）等，
 * 子域名没有独立 WHOIS 记录时回退到父域名的注册信息。
 *
 * @param {string} failedDomain - 已查询失败的标准域名
 * @returns {Promise<WhoisResult|null>}
 */
async function _lookupParentDomains(failedDomain) {
  const parts = failedDomain.split('.');
  // 至少保留两级才能视为域名（如 example.com）
  if (parts.length <= 2) return null;

  console.log(`[WhoisClient] 尝试父域名回退: ${failedDomain}`);
  for (let i = 1; i < parts.length - 1; i++) {
    const parentDomain = parts.slice(i).join('.');
    if (!parentDomain.includes('.')) continue;

    // 先查 WhoisClient 缓存
    const cached = _cache.get(parentDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      console.log(`[WhoisClient] 父域名缓存命中: ${parentDomain}`);
      return cached.result;
    }

    // 尝试 RDAP 查询父域名
    console.log(`[WhoisClient] 回退 RDAP 查询父域名: ${parentDomain}`);
    const rdapResult = await RdapClient.lookup(parentDomain);
    if (rdapResult && !rdapResult._rdap?.unsupported && !rdapResult._rdap?.notFound) {
      const result = {
        domain: rdapResult.domain || parentDomain,
        domainSuffix: rdapResult.domainSuffix || '',
        creationDays: rdapResult.creationDays,
        validDays: rdapResult.validDays,
        creationTime: rdapResult.creationTime || '',
        expirationTime: rdapResult.expirationTime || '',
        isExpire: rdapResult.isExpire || false,
        registrarName: rdapResult.registrarName || '',
        domainStatus: rdapResult.domainStatus || [],
        nameServer: rdapResult.nameServer || [],
        queryTime: rdapResult.queryTime || new Date().toISOString()
      };
      if (result.creationDays > 0) {
        _cache.set(parentDomain, { result, timestamp: Date.now() });
      }
      console.log(`[WhoisClient] 父域名 RDAP 查询成功: ${parentDomain} (注册 ${result.creationDays}d)`);
      return result;
    }

    // 尝试 WhoisCX 查询父域名
    console.log(`[WhoisClient] 回退 WhoisCX 查询父域名: ${parentDomain}`);
    const whoisResult = await _lookupViaWhoisCx(parentDomain);
    if (whoisResult) {
      if (whoisResult.creationDays > 0) {
        _cache.set(parentDomain, { result: whoisResult, timestamp: Date.now() });
      }
      console.log(`[WhoisClient] 父域名 WhoisCX 查询成功: ${parentDomain} (注册 ${whoisResult.creationDays}d)`);
      return whoisResult;
    }
  }

  console.warn(`[WhoisClient] 父域名回退完全失败: ${failedDomain}`);
  return null;
}

// ==================== WhoisCX API 回退查询 ====================

/**
 * 通过 WhoisCX API 查询域名信息（备用路径）
 * @param {string} normalizedDomain - PSL 标准化后的域名
 * @returns {Promise<WhoisResult|null>}
 */
async function _lookupViaWhoisCx(normalizedDomain) {
  // 速率限制等待
  await _waitForWhoisRateLimit();

  const url = `${WHOIS_API_URL}?domain=${encodeURIComponent(normalizedDomain)}`;
  console.log(`[WhoisClient] WhoisCX 回退查询: ${url}`);

  let response;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), WHOIS_API_TIMEOUT);

    response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Accept': '*/*',
        'User-Agent': 'VirusDetector/2.2.4 (Browser Extension; RDAP+WhoisCX)'
      }
    });

    clearTimeout(timeoutId);
  } catch (error) {
    if (error.name === 'AbortError') {
      _recordError(normalizedDomain, 'timeout',
        `WhoisCX 请求超过 ${WHOIS_API_TIMEOUT}ms 超时`,
        { url, timeoutMs: WHOIS_API_TIMEOUT });
    } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
      _recordError(normalizedDomain, 'connect',
        `WhoisCX 网络连接失败: ${error.message}`,
        { url, errorName: error.name });
    } else {
      _recordError(normalizedDomain, 'connect',
        `WhoisCX 请求异常: ${error.message}`,
        { url, errorName: error.name, errorStack: error.stack });
    }
    return null;
  }

  if (!response.ok) {
    let responseBody = '';
    try { responseBody = await response.text(); } catch (e) { /* ignore */ }
    _recordError(normalizedDomain, 'http_status',
      `WhoisCX 返回 HTTP ${response.status} ${response.statusText}`,
      { url, statusCode: response.status, statusText: response.statusText, responseBody: responseBody.substring(0, 500) });
    return null;
  }

  // 一次性读取响应体，避免多次 clone
  let responseText = '';
  try { responseText = await response.clone().text(); } catch (e) { /* ignore */ }

  // 检查是否为 HTML（WhoisCX API 可能已废弃）
  const trimmed = responseText.trim();
  if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html')) {
    _recordError(normalizedDomain, 'parse',
      'WhoisCX API 可能已废弃（返回 HTML 而非 JSON），建议移除或替换此回退路径',
      { url, responseBody: responseText.substring(0, 200) });
    return null;
  }

  let json;
  try {
    json = JSON.parse(responseText);
  } catch (parseError) {
    _recordError(normalizedDomain, 'parse',
      `WhoisCX JSON 解析失败: ${parseError.message}`,
      { url, responseBody: responseText.substring(0, 500) });
    return null;
  }

  // WhoisCX 业务状态码校验
  if (json.status !== 1) {
    _recordError(normalizedDomain, 'parse',
      `WhoisCX 业务状态码异常 (status=${json.status})，预期 status=1`,
      { url, responseJson: json });
    return null;
  }

  if (!json.data) {
    _recordError(normalizedDomain, 'parse',
      'WhoisCX 响应缺少 data 字段',
      { url, responseKeys: Object.keys(json) });
    return null;
  }

  // 字段提取
  const info = json.data.info || {};
  const domainSuffix = json.data.domain_suffix || '';
  const creationTime = info.creation_time || info.registration_time || json.data.creation_time || json.data.registration_time || '';
  const expirationTime = info.expiration_time || info.registration_expiration_time || json.data.expiration_time || '';

  // creation_days 多层回退
  let creationDaysRaw = info.creation_days;
  if (creationDaysRaw === undefined || creationDaysRaw === null) {
    creationDaysRaw = json.data.creation_days;
  }

  let creationDays = -1;
  if (typeof creationDaysRaw === 'number' && creationDaysRaw > 0) {
    creationDays = creationDaysRaw;
  } else if (typeof creationDaysRaw === 'number' && creationDaysRaw === 0) {
    // API 返回 0，尝试从 creation_time 计算
    const calculated = _parseDaysFromWhoisCxTime(creationTime);
    creationDays = calculated > 0 ? calculated : -1;
  } else {
    // 没有 creation_days，尝试从 creation_time 计算
    const calculated = _parseDaysFromWhoisCxTime(creationTime);
    creationDays = calculated > 0 ? calculated : -1;
  }

  // valid_days 多层回退
  let validDaysRaw = info.valid_days;
  if (validDaysRaw === undefined || validDaysRaw === null) {
    validDaysRaw = json.data.valid_days;
  }

  return {
    domain: json.data.domain || normalizedDomain,
    domainSuffix,
    creationDays,
    validDays: typeof validDaysRaw === 'number' ? validDaysRaw : -1,
    creationTime,
    expirationTime,
    isExpire: info.is_expire === 1,
    registrarName: info.registrar_name || '',
    domainStatus: Array.isArray(info.domain_status) ? info.domain_status : [],
    nameServer: Array.isArray(info.name_server) ? info.name_server : [],
    queryTime: json.data.query_time || ''
  };
}

// ==================== 公开接口 ====================

export class WhoisClient {
  /**
   * 查询域名的注册信息（RDAP 主 → WhoisCX 回退）
   *
   * @param {string} domain - 要查询的域名（如 "example.com" 或 "www.baidu.com"）
   * @returns {Promise<WhoisResult|null>} 查询结果，失败时返回 null
   *   （可通过 WhoisClient.lastError 获取失败详情）
   */
  static async lookup(domain) {
    // 1. 参数校验
    if (!domain || typeof domain !== 'string') {
      _recordError(String(domain || ''), 'invalid', 'domain 参数为空或类型错误', { domain });
      return null;
    }

    // 2. PSL 域名标准化：提取可注册域名
    const rawDomain = domain.toLowerCase().trim();
    const normalizedDomain = UrlUtils.getMainDomain(rawDomain);

    if (!normalizedDomain || !normalizedDomain.includes('.')) {
      _recordError(normalizedDomain || domain, 'invalid', '域名格式无效', { domain });
      return null;
    }

    if (normalizedDomain !== rawDomain) {
      console.log(`[WhoisClient] PSL 域名提取: ${rawDomain} -> ${normalizedDomain}`);
    }

    // 异步触发 DoH PSL 查询（不阻塞当前请求，预填充缓存供后续使用）
    refreshPublicSuffixDNS(rawDomain).catch(() => {});

    // 3. 检查缓存
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      const ageLabel = cached.result.creationDays >= 0 ? `注册${cached.result.creationDays}天` : '注册天数未知';
      console.log(`[WhoisClient] 缓存命中: ${normalizedDomain} (${ageLabel})`);
      return cached.result;
    }

    // 4. 主查询：RDAP 协议
    console.log(`[WhoisClient] 发起 RDAP 查询: ${normalizedDomain}`);
    const rdapResult = await RdapClient.lookup(normalizedDomain);

    // 5. RDAP 成功 → 缓存并返回
    if (rdapResult && !rdapResult._rdap?.unsupported && !rdapResult._rdap?.notFound) {
      const result = {
        domain: rdapResult.domain || normalizedDomain,
        domainSuffix: rdapResult.domainSuffix || '',
        creationDays: rdapResult.creationDays,
        validDays: rdapResult.validDays,
        creationTime: rdapResult.creationTime || '',
        expirationTime: rdapResult.expirationTime || '',
        isExpire: rdapResult.isExpire || false,
        registrarName: rdapResult.registrarName || '',
        domainStatus: rdapResult.domainStatus || [],
        nameServer: rdapResult.nameServer || [],
        queryTime: rdapResult.queryTime || new Date().toISOString()
      };

      if (result.creationDays > 0) {
        _cache.set(normalizedDomain, { result, timestamp: Date.now() });
        console.log(`[WhoisClient] RDAP 缓存写入: ${normalizedDomain} (creationDays=${result.creationDays})`);
      }

      _lastError = null;
      const ageLabel = result.creationDays >= 0 ? `注册 ${result.creationDays}d` : '注册时间未知';
      const validLabel = result.validDays >= 0 ? `到期 ${result.validDays}d` : '有效期未知';
      console.log(`[WhoisClient] RDAP 查询成功: ${normalizedDomain} (${ageLabel}, ${validLabel}, 注册商: ${result.registrarName || '未知'})`);
      return result;
    }

    // 6. RDAP 返回 "不支持"（如 .cn 无公开 RDAP）→ 不视为错误，直接走 WhoisCX 回退
    if (rdapResult?._rdap?.unsupported) {
      console.log(`[WhoisClient] RDAP 不支持此 TLD (.${normalizedDomain.split('.').pop()})，回退 WhoisCX`);
    } else if (rdapResult?._rdap?.notFound) {
      console.warn(`[WhoisClient] RDAP 未找到域名，尝试 WhoisCX 回退: ${normalizedDomain}`);
    } else {
      // RDAP 完全失败（返回 null）
      const errInfo = RdapClient.lastError;
      console.warn(`[WhoisClient] RDAP 查询失败${errInfo ? ' (' + errInfo.phase + ')' : ''}，回退 WhoisCX: ${normalizedDomain}`);
    }

    // 7. 回退：WhoisCX API
    const whoisResult = await _lookupViaWhoisCx(normalizedDomain);
    if (whoisResult) {
      if (whoisResult.creationDays > 0) {
        _cache.set(normalizedDomain, { result: whoisResult, timestamp: Date.now() });
        console.log(`[WhoisClient] WhoisCX 缓存写入: ${normalizedDomain} (creationDays=${whoisResult.creationDays})`);
      }

      _lastError = null;
      const ageLabel = whoisResult.creationDays >= 0 ? `注册 ${whoisResult.creationDays}d` : '注册时间未知';
      console.log(`[WhoisClient] WhoisCX 查询成功: ${normalizedDomain} (${ageLabel}, 注册商: ${whoisResult.registrarName || '未知'})`);
      return whoisResult;
    }

    // 8. 两条路径均失败 → 尝试逐级向上回退父域名
    //    处理多级公共后缀子域名（如 a.b.github.io 等），逐级剥离标签查找父域名的注册信息
    const fallbackResult = await _lookupParentDomains(normalizedDomain);
    if (fallbackResult) return fallbackResult;

    console.error(`[WhoisClient] RDAP 和 WhoisCX 均查询失败: ${normalizedDomain}`);
    return null;
  }

  /**
   * 从缓存中获取查询结果（不发起网络请求）
   * @param {string} domain - 域名
   * @returns {WhoisResult|null}
   */
  static getCached(domain) {
    if (!domain) return null;
    const normalizedDomain = UrlUtils.getMainDomain(domain.toLowerCase().trim());
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      return cached.result;
    }
    return null;
  }

  /**
   * 获取上次查询失败的错误详情
   * @returns {WhoisErrorInfo|null}
   */
  static get lastError() {
    return _lastError;
  }

  /**
   * 清空错误信息
   */
  static clearLastError() {
    _lastError = null;
  }

  /**
   * 清除指定域名的缓存
   * @param {string} domain
   */
  static clearCache(domain) {
    if (domain) {
      _cache.delete(UrlUtils.getMainDomain(domain.toLowerCase().trim()));
    }
  }

  /**
   * 清空所有缓存
   */
  static clearAllCache() {
    _cache.clear();
  }
}

// ==================== 类型定义 ====================

/**
 * @typedef {Object} WhoisResult
 * @property {string}   domain        - 查询的域名
 * @property {string}   domainSuffix  - 域名后缀（如 com, cn）
 * @property {number}   creationDays  - 域名已注册天数（-1 表示未知）
 * @property {number}   validDays     - 域名距离到期剩余天数（-1 表示未知）
 * @property {string}   creationTime  - 域名创建时间（ISO 8601 格式）
 * @property {string}   expirationTime - 域名到期时间
 * @property {boolean}  isExpire      - 是否已过期
 * @property {string}   registrarName - 注册商名称
 * @property {string[]} domainStatus  - 域名状态列表
 * @property {string[]} nameServer    - DNS 服务器列表
 * @property {string}   queryTime     - 查询时间
 */

/**
 * @typedef {Object} WhoisErrorInfo
 * @property {string} domain    - 查询的域名
 * @property {string} phase     - 失败阶段
 * @property {string} message   - 错误描述
 * @property {number} timestamp - 错误发生时间戳
 * @property {string} [url]     - 请求的完整 URL
 * @property {number} [statusCode]     - HTTP 状态码
 * @property {string} [statusText]     - HTTP 状态文本
 * @property {string} [responseBody]   - 响应体（截取前 500 字符）
 * @property {Object} [responseJson]   - 已解析的 JSON 响应
 * @property {string} [errorName]      - 异常类型名称
 * @property {string} [errorStack]     - 异常堆栈
 * @property {number} [timeoutMs]      - 超时毫秒数
 */
