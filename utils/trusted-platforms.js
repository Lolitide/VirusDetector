/**
 * Virus Detector — 可信平台白名单工具类 (Trusted Platforms Whitelist)
 *
 * 针对 Wiki / 代码托管 / 博客 / 文档 / 建站等 UGC 平台，提供 eTLD+1
 * 粒度的 O(1) 白名单查找，避免其子页面被误判为仿冒官网。
 * 仅跳过仿冒官网检测（规则一），其他安全规则仍正常运行。
 * 名单本体统一维护于 utils/exemptions/index.js（导出 TRUSTED_PLATFORMS），
 * 本文件只提供 TrustedPlatforms 工具类，不再单独维护域名列表。
 *
 * @module trusted-platforms
 */

// ==================== 可信平台域名集合 ====================
// Wiki / 代码托管 / 博客 / 文档 / 建站等 UGC 平台，规则一(仿冒官网)跳过。
// 名单已统一迁移至 utils/exemptions/index.js（导出 TRUSTED_PLATFORMS），便于集中维护。
import { TRUSTED_PLATFORMS } from './exemptions/index.js';

// ==================== TrustedPlatforms 工具类 ====================

export class TrustedPlatforms {
  /**
   * 检查给定注册域（eTLD+1）是否在可信平台白名单中。
   *
   * 调用方应先通过 UrlUtils.getMainDomain() 提取注册域再传入。
   *
   * @param {string} mainDomain - eTLD+1 格式的注册域，如 "fandom.com"、"github.io"
   * @returns {boolean} 是否命中白名单
   */
  static isTrusted(mainDomain) {
    if (!mainDomain) return false;
    return TRUSTED_PLATFORMS.has(mainDomain.toLowerCase());
  }

  /**
   * 获取当前白名单的排序副本（用于调试、日志或设置面板展示）。
   * @returns {string[]} 排序后的可信平台域名列表
   */
  static getList() {
    return [...TRUSTED_PLATFORMS].sort();
  }
}
