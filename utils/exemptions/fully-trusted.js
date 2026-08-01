/**
 * Virus Detector — 完全信任域名 (Fully Trusted Domains)
 * ─────────────────────────────────────────────────────────────────────────
 * 豁免层级：**完全跳过所有 8 条检测规则**（等同于用户白名单）。
 *
 * 匹配方式：精确匹配或已知子域名匹配。
 *   例如 isFullyTrusted('www.moe.gov.cn') → true
 *        isFullyTrusted('moe.gov.cn')     → true
 *
 * @module fully-trusted
 */

// ==================== 完全信任域名 ====================
export const FULLY_TRUSTED_DOMAINS = new Set([
  // —— 政府机构 ——
  'gov.cn',       // 中国政府
  'gov.hk',       // 香港政府
  'gov.tw',       // 台湾政府
  'moe.gov.cn',   // 中华人民共和国教育部
  'cas.ac.cn',    // 中国科学院
  'ustc.ac.cn',   // 中国科学技术大学
  'tsinghua.edu.cn', // 清华大学
  'pku.edu.cn',   // 北京大学
  'fudan.edu.cn', // 复旦大学
  'sjtu.edu.cn',  // 上海交通大学
  'zju.edu.cn',   // 浙江大学
  'nthu.edu.tw',  // 台湾清华大学
  'ntu.edu.tw',   // 台湾大学
]);

/**
 * 判断域名是否属于完全信任域（应跳过所有检测）。
 *
 * 通过精确匹配或已知子域名匹配：
 *   1. 去掉 www. 前缀后转小写
 *   2. 在 FULLY_TRUSTED_DOMAINS 中精确匹配
 *
 * @param {string} domain - 主机名（如 "www.moe.gov.cn" 或 "moe.gov.cn"）
 * @returns {boolean} 是否完全信任
 */
export function isFullyTrusted(domain) {
  if (!domain) return false;
  const normalized = domain.replace(/^www\./i, '').toLowerCase();

  // 精确匹配
  if (FULLY_TRUSTED_DOMAINS.has(normalized)) return true;

  // 已知子域名匹配：仅对顶级信任域（gov.cn 等）允许 www 子域名
  const parts = normalized.split('.');
  if (parts.length > 2) {
    const parent = parts.slice(1).join('.');
    if (FULLY_TRUSTED_DOMAINS.has(parent)) return true;
  }

  return false;
}
