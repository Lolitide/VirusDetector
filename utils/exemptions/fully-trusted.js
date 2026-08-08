/**
 * Virus Detector — 完全信任域名 (Fully Trusted Domains)
 * ─────────────────────────────────────────────────────────────────────────
 * 豁免层级：**完全跳过所有 8 条检测规则**（等同于用户白名单）。
 *
 * 匹配方式：后缀匹配（子域名自动继承信任）。
 *   例如 isFullyTrusted('www.moe.gov.cn') → true
 *        isFullyTrusted('sub.cas.ac.cn')  → true
 *
 * @module fully-trusted
 */

// ==================== 完全信任域名后缀 ====================
export const FULLY_TRUSTED_DOMAIN_SUFFIXES = new Set([
  // —— 政府机构 ——
  'gov.cn',       // 中国政府（严格审批，攻击者无法注册）
  'gov.hk',       // 香港政府
  'gov.tw',       // 台湾政府

  // —— 教育机构 ——
  'edu.cn',       // 中国教育机构（CERNET 管理）

  // —— 科研机构 ——
  'ac.cn',        // 中国科研机构（如中国科学院 cas.ac.cn）
]);

/**
 * 判断域名是否属于完全信任域（应跳过所有检测）。
 *
 * 通过后缀匹配实现子域名自动继承：
 *   1. 去掉 www. 前缀后转小写
 *   2. 在 FULLY_TRUSTED_DOMAIN_SUFFIXES 中精确匹配
 *   3. 若未匹配，逐级去掉左侧子域名段后重试
 *
 * @param {string} domain - 主机名（如 "www.moe.gov.cn" 或 "moe.gov.cn"）
 * @returns {boolean} 是否完全信任
 */
export function isFullyTrusted(domain) {
  if (!domain) return false;
  const normalized = domain.replace(/^www\./i, '').toLowerCase();

  // 精确匹配
  if (FULLY_TRUSTED_DOMAIN_SUFFIXES.has(normalized)) return true;

  // 后缀匹配：子域名也继承信任
  // 例如 www.moe.gov.cn → parts = ['www', 'moe', 'gov', 'cn']
  //   i=1: parent = 'moe.gov.cn' → 不在集合
  //   i=2: parent = 'gov.cn'     → 在集合 → 返回 true
  const parts = normalized.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    if (FULLY_TRUSTED_DOMAIN_SUFFIXES.has(parent)) return true;
  }

  return false;
}
