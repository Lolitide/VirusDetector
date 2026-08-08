/**
 * Virus Detector — 统一豁免名单 (Unified Exemptions)
 * ─────────────────────────────────────────────────────────────────────────
 * 本文件为 barrel re-export，集中导出全部豁免名单，保持向后兼容。
 *
 * 三种豁免层级（按信任程度递增）：
 *   1. ICP_EXEMPT_DOMAINS（icp-exempt.js）→ 仅跳过规则三（ICP 备案）
 *   2. TRUSTED_PLATFORMS（trusted-platforms.js）→ 仅跳过规则一（域名仿冒）
 *   3. FULLY_TRUSTED_DOMAIN_SUFFIXES（fully-trusted.js）→ 完全跳过全部检测
 *
 * 各名单的具体成员、动态并入与运行时白名单说明见对应子文件头部。
 */

export { ICP_EXEMPT_DOMAINS } from './icp-exempt.js';
export { TRUSTED_PLATFORMS } from './trusted-platforms.js';
export { FULLY_TRUSTED_DOMAIN_SUFFIXES, isFullyTrusted } from './fully-trusted.js';
