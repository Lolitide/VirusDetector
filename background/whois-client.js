/**
 * Virus Detector — 域名注册信息查询客户端 (Whois Client)
 *
 * 统一的域名查询入口：RDAP（主）→ WhoisCX API（回退），双查询架构。
 * RDAP 基于 RFC 9082/9083 协议，WhoisCX 作为全球覆盖的备用查询。
 *
 * @module whois-client
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
 *   - 接口地址：POST https://whoiscx.com/api/whois/info/
 *   - 请求体：domain=example.com（application/x-www-form-urlencoded）
 *   - 响应格式：application/json
 *   - 频率限制：2 秒/次（通过串行化请求保证）
 */

import {
  WHOIS_API_URL, WHOIS_CACHE_TTL, WHOIS_API_TIMEOUT,
  VERSION
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

/** @type {Map<string, Promise<WhoisResult|null>>} 并发去重（按标准化域名） */
const _pendingLookups = new Map();

/** @type {Map<string, Promise<WhoisResult|null>>} 并发去重（按原始域名，防 PSL 缓存竞态） */
const _pendingRawLookups = new Map();

// ==================== WhoisCX 速率限制 ====================

/** 上次 WhoisCX API 请求完成的时间戳（用于速率限制） */
let _lastWhoisRequestTime = 0;

/** WhoisCX API 最小请求间隔（毫秒），保护免费 API 不被封禁 */
const MIN_WHOIS_INTERVAL_DEFAULT = 2100;

/** 缓存的请求间隔，避免每次请求都读 chrome.storage */
let _cachedWhoisInterval = null;

/** 从用户设置读取速率限制间隔，回退到默认值 */
async function _getWhoisInterval() {
  if (_cachedWhoisInterval !== null) return _cachedWhoisInterval;
  try {
    const r = await chrome.storage.local.get('global_settings');
    const gs = r.global_settings || {};
    if (gs.whois_apiIntervalMs && gs.whois_apiIntervalMs >= 1000) {
      _cachedWhoisInterval = gs.whois_apiIntervalMs;
      return _cachedWhoisInterval;
    }
  } catch (e) { /* ignore */ }
  _cachedWhoisInterval = MIN_WHOIS_INTERVAL_DEFAULT;
  return _cachedWhoisInterval;
}

/**
 * 等待直到满足 WhoisCX 速率限制要求
 * @returns {Promise<void>}
 */
async function _waitForWhoisRateLimit() {
  const now = Date.now();
  const elapsed = now - _lastWhoisRequestTime;
  const interval = await _getWhoisInterval();
  if (elapsed < interval) {
    await new Promise(resolve => setTimeout(resolve, interval - elapsed));
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

/**
 * 从 RDAP 查询结果构建统一的 WhoisResult 对象
 * @param {Object} source - RDAP 查询结果
 * @param {string} fallbackDomain - 回退域名
 * @returns {WhoisResult}
 */
function _buildWhoisResult(source, fallbackDomain) {
  return {
    domain: source.domain || fallbackDomain,
    domainSuffix: source.domainSuffix || '',
    creationDays: source.creationDays,
    validDays: source.validDays,
    creationTime: source.creationTime || '',
    expirationTime: source.expirationTime || '',
    isExpire: source.isExpire || false,
    registrarName: source.registrarName || '',
    domainStatus: source.domainStatus || [],
    nameServer: source.nameServer || [],
    queryTime: source.queryTime || new Date().toISOString()
  };
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
      const result = _buildWhoisResult(rdapResult, parentDomain);
      if (result.creationDays > 0) {
        _cache.set(parentDomain, { result, timestamp: Date.now() });
        console.log(`[WhoisClient] 父域名 RDAP 查询成功: ${parentDomain} (注册 ${result.creationDays}d)`);
        return result;
      }
      console.log(`[WhoisClient] 父域名 RDAP 无注册时间，继续: ${parentDomain}`);
    }

    // 尝试 WhoisCX 查询父域名
    console.log(`[WhoisClient] 回退 WhoisCX 查询父域名: ${parentDomain}`);
    const whoisResult = await _lookupViaWhoisCx(parentDomain);
    if (whoisResult) {
      if (whoisResult.creationDays > 0) {
        _cache.set(parentDomain, { result: whoisResult, timestamp: Date.now() });
        console.log(`[WhoisClient] 父域名 WhoisCX 查询成功: ${parentDomain} (注册 ${whoisResult.creationDays}d)`);
        return whoisResult;
      }
      console.log(`[WhoisClient] 父域名 WhoisCX 无注册时间，继续: ${parentDomain}`);
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

  const url = WHOIS_API_URL;
  const requestBody = `domain=${encodeURIComponent(normalizedDomain)}`;
  console.log(`[WhoisClient] WhoisCX 回退查询: ${url} (domain=${normalizedDomain})`);

  let response;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), WHOIS_API_TIMEOUT);

    response = await fetch(url, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': `VirusDetector/${VERSION} (Browser Extension; RDAP+WhoisCX)`
      },
      body: requestBody
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

  let responseText = '';
  try { responseText = await response.text(); } catch (e) { /* ignore */ }

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
    let normalizedDomain = UrlUtils.getMainDomain(rawDomain);

    if (!normalizedDomain || !normalizedDomain.includes('.')) {
      _recordError(normalizedDomain || domain, 'invalid', '域名格式无效', { domain });
      return null;
    }

    // 2.5 PSL 冷启动检测：若 PSL 未缓存，等待 DoH 就绪后再重新标准化
    //    避免回退 TLD 遗漏多级后缀（如 hl.cn 不在回退集）导致拿错注册域
    if (!UrlUtils.hasPslCache(rawDomain)) {
      console.log(`[WhoisClient] PSL 冷启动，等待 DoH 就绪: ${rawDomain}`);
      const dohStart = Date.now();
      try {
        await refreshPublicSuffixDNS(rawDomain);
        console.log(`[WhoisClient] DoH 完成 (${Date.now() - dohStart}ms)，重新标准化`);
        const warmDomain = UrlUtils.getMainDomain(rawDomain);
        if (warmDomain !== normalizedDomain && warmDomain !== rawDomain) {
          console.log(`[WhoisClient] PSL 预热后域名修正: ${normalizedDomain} -> ${warmDomain}`);
          normalizedDomain = warmDomain;
        }
      } catch (e) {
        console.warn(`[WhoisClient] DoH 超时/失败，使用回退PSL结果: ${e.message}`);
      }
    } else {
      // PSL 已缓存，异步刷新（不阻塞当前请求）
      refreshPublicSuffixDNS(rawDomain).catch(() => {});
    }

    if (normalizedDomain !== rawDomain) {
      console.log(`[WhoisClient] PSL 域名提取: ${rawDomain} -> ${normalizedDomain}`);
    }

    // 3. 检查缓存
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      const ageLabel = cached.result.creationDays >= 0 ? `注册${cached.result.creationDays}天` : '注册天数未知';
      console.log(`[WhoisClient] 缓存命中: ${normalizedDomain} (${ageLabel})`);
      return cached.result;
    }

    // 3.5 并发去重：同一域名正在查询中，复用已有 Promise
    const pending = _pendingLookups.get(normalizedDomain);
    if (pending) {
      console.log(`[WhoisClient] 复用进行中的查询(按标准化): ${normalizedDomain}`);
      return pending;
    }

    // 3.6 二级去重：相同原始域名（防 PSL 缓存竞态导致标准化结果不一致）
    const rawPending = _pendingRawLookups.get(rawDomain);
    if (rawPending) {
      console.log(`[WhoisClient] 复用进行中的查询(按原始域名): ${rawDomain} (当前标准化为 ${normalizedDomain})`);
      return rawPending;
    }

    const lookupPromise = (async () => {

    // 4. 主查询：RDAP 协议
    console.log(`[WhoisClient] 发起 RDAP 查询: ${normalizedDomain}`);
    const rdapResult = await RdapClient.lookup(normalizedDomain);

    // 5. RDAP 查询结果处理
    //    有 creationDays → 直接返回（完整数据）
    //    无 creationDays → 保存部分结果，继续走 WhoisCX / 子域名回退
    let rdapPartialResult = null;
    if (rdapResult && !rdapResult._rdap?.unsupported && !rdapResult._rdap?.notFound) {
      const result = _buildWhoisResult(rdapResult, normalizedDomain);

      if (result.creationDays > 0) {
        _cache.set(normalizedDomain, { result, timestamp: Date.now() });
        console.log(`[WhoisClient] RDAP 缓存写入: ${normalizedDomain} (creationDays=${result.creationDays})`);
        _lastError = null;
        const validLabel = result.validDays >= 0 ? `到期 ${result.validDays}d` : '有效期未知';
        console.log(`[WhoisClient] RDAP 查询成功: ${normalizedDomain} (注册 ${result.creationDays}d, ${validLabel}, 注册商: ${result.registrarName || '未知'})`);
        return result;
      }

      // creationDays 未知 → 保留部分结果，继续回退
      rdapPartialResult = result;
      console.log(`[WhoisClient] RDAP 查询成功但无注册时间，保留部分结果继续回退: ${normalizedDomain}`);
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

    // 7. 回退：WhoisCX API（仅在仍有希望时查询——若 RDAP 已有结果但无 creationDays
    //    且存在更具体的原始域名，则跳过此步直接进子域名回退，避免浪费请求）
    const hasSubDomainFallback = rawDomain !== normalizedDomain &&
      rawDomain.split('.').length > normalizedDomain.split('.').length;
    const skipWhoisCxForShortDomain = rdapPartialResult && hasSubDomainFallback;

    if (!skipWhoisCxForShortDomain) {
      const whoisResult = await _lookupViaWhoisCx(normalizedDomain);
      if (whoisResult) {
        if (whoisResult.creationDays > 0) {
          _cache.set(normalizedDomain, { result: whoisResult, timestamp: Date.now() });
          console.log(`[WhoisClient] WhoisCX 缓存写入: ${normalizedDomain} (creationDays=${whoisResult.creationDays})`);
          _lastError = null;
          console.log(`[WhoisClient] WhoisCX 查询成功: ${normalizedDomain} (注册 ${whoisResult.creationDays}d, 注册商: ${whoisResult.registrarName || '未知'})`);
          return whoisResult;
        } else if (!rdapPartialResult) {
          rdapPartialResult = whoisResult;
        }
        console.log(`[WhoisClient] WhoisCX 返回但无注册时间，继续回退: ${normalizedDomain}`);
      }
    } else {
      console.log(`[WhoisClient] 跳过 WhoisCX(${normalizedDomain})，直接进入子域名回退`);
    }

    // 8. 子域名回退：PSL 标准化域名（二级域名）查询失败时，回退到原始域名（三级域名）
    //    例如 a.nl.cn：getMainDomain 返回 nl.cn，但 nl.cn 无 WHOIS 记录时尝试查 a.nl.cn
    if (rawDomain !== normalizedDomain && rawDomain.split('.').length > normalizedDomain.split('.').length) {
      console.log(`[WhoisClient] 二级域名查询失败，回退三级域名: ${rawDomain}`);

      // 检查缓存
      const subCached = _cache.get(rawDomain);
      if (subCached && (Date.now() - subCached.timestamp) < WHOIS_CACHE_TTL) {
        console.log(`[WhoisClient] 三级域名缓存命中: ${rawDomain}`);
        return subCached.result;
      }

      // 尝试 RDAP 查询原始域名
      const subRdapResult = await RdapClient.lookup(rawDomain);
      if (subRdapResult && !subRdapResult._rdap?.unsupported && !subRdapResult._rdap?.notFound) {
        const result = _buildWhoisResult(subRdapResult, rawDomain);
        if (result.creationDays > 0) {
          _cache.set(rawDomain, { result, timestamp: Date.now() });
          _lastError = null;
          console.log(`[WhoisClient] 三级域名 RDAP 查询成功: ${rawDomain} (注册 ${result.creationDays}d)`);
          return result;
        } else if (!rdapPartialResult) {
          rdapPartialResult = result;
        }
        console.log(`[WhoisClient] 三级域名 RDAP 无注册时间，继续: ${rawDomain}`);
      }

      // 尝试 WhoisCX 查询原始域名
      const subWhoisResult = await _lookupViaWhoisCx(rawDomain);
      if (subWhoisResult) {
        if (subWhoisResult.creationDays > 0) {
          _cache.set(rawDomain, { result: subWhoisResult, timestamp: Date.now() });
          _lastError = null;
          console.log(`[WhoisClient] 三级域名 WhoisCX 查询成功: ${rawDomain} (注册 ${subWhoisResult.creationDays}d)`);
          return subWhoisResult;
        } else if (!rdapPartialResult) {
          rdapPartialResult = subWhoisResult;
        }
        console.log(`[WhoisClient] 三级域名 WhoisCX 无注册时间，继续: ${rawDomain}`);
      }
    }

    // 9. 以上均失败 → 尝试逐级向上回退父域名
    //    处理多级公共后缀子域名（如 a.b.github.io 等），逐级剥离标签查找父域名的注册信息
    const fallbackResult = await _lookupParentDomains(normalizedDomain);
    if (fallbackResult) return fallbackResult;

    // 10. 全部回退失败，但有 RDAP 部分结果（creationDays 未知）→ 兜底返回
    if (rdapPartialResult) {
      console.log(`[WhoisClient] 回退均失败，返回 RDAP 部分结果: ${normalizedDomain} (creationDays 未知)`);
      return rdapPartialResult;
    }

    console.error(`[WhoisClient] RDAP 和 WhoisCX 均查询失败: ${normalizedDomain}`);
    return null;

    })();
    _pendingLookups.set(normalizedDomain, lookupPromise);
    _pendingRawLookups.set(rawDomain, lookupPromise);
    lookupPromise.finally(() => {
      _pendingLookups.delete(normalizedDomain);
      _pendingRawLookups.delete(rawDomain);
    });
    return lookupPromise;
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
