/**
 * ICP 备案查询 API 客户端
 *
 * 背景：原规则三（ICP 检测）只扫描「页面文本/页脚」里的备案号。
 * 但大量合法国内站点（含政府/企业/工具站，见 issues #92 apihz.cn、#93 uapis.cn）
 * 并不在页面上展示备案号，导致误判为「无备案」而加分。
 * 反之，钓鱼站盗用他人备案号写在页面上，又会被误判「通过」。
 *
 * 本模块改为「按域名调用备案查询 API」核验备案（端点集中在 utils/constants.js 的
 * ICP_API_CONFIG）。页面文本扫描降级为兜底。
 *
 * 数据源（按 ICP_API_CONFIG.providers 顺序尝试）：
 *   - uapis : https://uapis.cn/api/v1/network/icp?domain=<domain>（稳定，免 key）
 *   - apihz : https://cn.apihz.cn/api/wangzhan/icp.php?id=<id>&key=<key>&domain=<domain>
 *            公开接口，约 10 次/分钟限流（见 issue #93 暴露端点 + #92 文档）
 *
 * 设计原则：
 *   - 多源备援：主源失败自动切换下一源
 *   - 限流：每源独立令牌桶（rateLimitPerMin），超限本周期内跳过该源
 *   - 缓存：域名级缓存（默认 24h），避免重复请求
 *   - 失败安全：所有源失败/超时 → 返回 queried:false，调用方回退页面文本扫描
 *   - 仅「确认有备案」时改变判定；其余情况（无备案/失败）一律交回原逻辑，
 *     不引入新的误报或漏报
 *
 * @module icp-api
 */

import { UrlUtils } from '../utils/url-utils.js';
import { ICP_API_CONFIG, VERSION } from '../utils/constants.js';

// ==================== 缓存与限流 ====================

const ICP_API_CACHE_PREFIX = 'icp_api_v1_';
const _memCache = new Map();
// per-provider 限流窗口：name -> 最近请求时间戳数组
const _rateWindows = new Map();

/**
 * 检查并占用某 provider 的限流额度（60s 滑动窗口）。
 * @param {Object} provider
 * @returns {boolean} true=允许本次请求
 */
function _acquireRateLimit(provider) {
  const limit = provider.rateLimitPerMin || 0;
  if (!limit) return true;
  const now = Date.now();
  const arr = _rateWindows.get(provider.name) || [];
  const recent = arr.filter((t) => now - t < 60000);
  _rateWindows.set(provider.name, recent);
  if (recent.length >= limit) return false; // 已超限，本周期跳过
  recent.push(now);
  return true;
}

// ==================== 缓存读写 ====================

async function readCache(domain) {
  // 1. 内存热层
  if (_memCache.has(domain)) {
    const cached = _memCache.get(domain);
    if (Date.now() - cached._ts < ICP_API_CONFIG.cacheTtlMs) return cached;
  }
  // 2. 持久层
  try {
    const key = ICP_API_CACHE_PREFIX + domain;
    const store = await chrome.storage.local.get(key);
    const entry = store[key];
    if (entry && Date.now() - entry._ts < ICP_API_CONFIG.cacheTtlMs) {
      _memCache.set(domain, entry);
      return entry;
    }
  } catch (e) {
    /* storage 不可用时忽略 */
  }
  return null;
}

async function writeCache(domain, result) {
  const entry = { ...result, _ts: Date.now() };
  _memCache.set(domain, entry);
  try {
    const key = ICP_API_CACHE_PREFIX + domain;
    await chrome.storage.local.set({ [key]: entry });
  } catch (e) {
    /* storage 不可用时仅保留内存缓存 */
  }
}

// ==================== ICP API 客户端 ====================

export class IcpApiClient {
  /**
   * 按域名查询 ICP 备案信息。
   * @param {string} hostname - 完整主机名（如 www.baidu.com）
   * @param {Object} [opts] - 可选覆盖，如 { apihzId, apihzKey }
   * @returns {Promise<{ queried:boolean, hasIcp:boolean, icpNumber:?string, unitName:?string, service:?string, error:?string }>}
   *   - queried:true  表示 API 成功返回了结论（无论有无备案）
   *   - queried:false 表示所有源失败/超时/限流，调用方应回退页面文本扫描
   */
  static async query(hostname, opts = {}) {
    if (!hostname) return { queried: false, hasIcp: false, error: 'empty hostname' };

    // 总开关：设置中关闭 API 核验时直接跳过（调用方回退页面文本扫描）
    if (opts.enabled === false) return { queried: false, hasIcp: false, error: 'api disabled' };

    const domain = UrlUtils.getMainDomain(hostname) || hostname.toLowerCase();

    // 命中缓存直接返回
    const cached = await readCache(domain);
    if (cached) return cached;

    // 支持通过 opts.providers 覆盖数据源（如设置页关闭某个 provider 后的有效列表）
    const providers = Array.isArray(opts.providers) ? opts.providers : ICP_API_CONFIG.providers;

    for (const provider of providers) {
      if (!provider.enabled) continue;                 // 未启用
      if (provider.needKey) continue;                  // 需 key 且未提供则跳过
      if (!_acquireRateLimit(provider)) continue;      // 限流：本周期跳过该源

      try {
        // 合并凭据覆盖（如 apihz 自定义 id/key）
        const cfg = { ...provider };
        if (provider.name === 'apihz') {
          if (opts.apihzId) cfg.id = opts.apihzId;
          if (opts.apihzKey) cfg.key = opts.apihzKey;
        }

        const url = provider.buildUrl(domain, cfg);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), ICP_API_CONFIG.timeoutMs);

        const resp = await fetch(url, {
          signal: controller.signal,
          headers: { 'User-Agent': `VirusDetector/${VERSION}` }
        });
        clearTimeout(timer);

        if (!resp.ok) continue; // 该源不可用，尝试下一个

        const text = await resp.text();
        if (!text) continue;

        let data;
        try {
          data = JSON.parse(text);
        } catch (e) {
          continue; // 非 JSON 响应，跳过
        }

        const parsed = provider.parse(data);
        const result = {
          queried: true,
          hasIcp: !!parsed.hasIcp,
          icpNumber: parsed.icpNumber || null,
          unitName: parsed.unitName || null,
          service: provider.name
        };
        await writeCache(domain, result);
        return result;
      } catch (e) {
        // 超时/网络错误：尝试下一个源
        continue;
      }
    }

    // 所有源失败/限流
    const failed = { queried: false, hasIcp: false, error: 'all providers failed or rate-limited' };
    // 失败也短时缓存，避免同一域名高频重试打爆接口
    const entry = { ...failed, _ts: Date.now() - (ICP_API_CONFIG.cacheTtlMs - ICP_API_CONFIG.failCacheMs) };
    _memCache.set(domain, entry);
    return failed;
  }

  /**
   * 供设置面板/动态注入额外 provider（如用户自有备案查询接口）。
   * @param {Object} provider - 符合 ICP_API_CONFIG.providers 元素的对象
   */
  static registerProvider(provider) {
    if (provider && typeof provider.buildUrl === 'function' && typeof provider.parse === 'function') {
      ICP_API_CONFIG.providers.push(provider);
    }
  }
}
