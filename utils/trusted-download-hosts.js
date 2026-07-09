/**
 * Virus Detector — 可信下载平台列表 (Trusted Download Hosts)
 *
 * 维护知名文件分发平台的域名列表，用于在规则二（下载检测）中对
 * 指向这些平台的跨域下载链接进行降权计分。
 *
 * 与 TrustedPlatforms（UGC 内容平台，跳过规则一）职责不同：
 * 本模块专门针对文件下载分发场景，不跳过规则一，仅在评分时降低权重。
 *
 * @module trusted-download-hosts
 *
 * 设计原则：
 *   - 不完全豁免，仅降权（GitHub 等也可托管恶意文件）
 *   - 匹配粒度为 eTLD+1（注册域），使用 UrlUtils.getMainDomain() 提取
 *   - 检查顺序：黑名单 > 可信平台 > 常规判断（黑名单不可绕过）
 *
 * 覆盖类别：
 *   - 代码托管 Releases：GitHub, GitLab, Gitee, Bitbucket, Codeberg
 *   - 包管理器：npm, PyPI
 *   - 开源托管：SourceForge, FossHub
 *   - 大型厂商 CDN：Microsoft, Google, Apple, Mozilla, Adobe
 *   - 操作系统官方源：Ubuntu, Debian, Docker, AppImage
 */

import { UrlUtils } from './url-utils.js';

// ==================== 可信下载平台域名集合 ====================

const TRUSTED_DOWNLOAD_HOSTS = new Set([
  // ---- 代码托管 Releases ----
  'github.com',
  'gitlab.com',
  'gitee.com',
  'bitbucket.org',
  'codeberg.org',

  // ---- 包管理器 ----
  'npmjs.com',
  'pypi.org',
  'files.pythonhosted.org',

  // ---- 开源托管 ----
  'sourceforge.net',
  'fosshub.com',

  // ---- 大型厂商 CDN / 官方下载 ----
  'microsoft.com',
  'google.com',
  'apple.com',
  'mozilla.org',
  'adobe.com',
  'oracle.com',
  'ibm.com',
  'amazon.com',

  // ---- 操作系统官方源 ----
  'ubuntu.com',
  'debian.org',
  'archlinux.org',
  'fedoraproject.org',
  'centos.org',
  'opensuse.org',
  'docker.com',
  'appimage.org',

  // ---- 知名免费软件官方 ----
  'videolan.org',         // VLC
  'libreoffice.org',
  'gnu.org',
  'apache.org',
  'python.org',
  'nodejs.org',
  'rust-lang.org',
  'golang.org',
  'nginx.org',
  'mysql.com',
  'postgresql.org',
]);

// ==================== TrustedDownloadHosts 工具类 ====================

export class TrustedDownloadHosts {
  /**
   * 检查给定主机名是否指向可信下载平台。
   * 调用方可直接传入完整 hostname，内部会提取注册域（eTLD+1）再匹配。
   *
   * @param {string} hostname - 下载链接的主机名（如 "github.com" 或 "objects.githubusercontent.com"）
   * @returns {boolean} 是否命中可信平台
   */
  static isTrusted(hostname) {
    if (!hostname) return false;
    const mainDomain = UrlUtils.getMainDomain(hostname.toLowerCase());
    if (!mainDomain) return false;
    return TRUSTED_DOWNLOAD_HOSTS.has(mainDomain);
  }

  /**
   * 获取当前可信平台列表的排序副本（用于调试或设置面板展示）。
   * @returns {string[]} 排序后的可信平台域名列表
   */
  static getList() {
    return [...TRUSTED_DOWNLOAD_HOSTS].sort();
  }
}
