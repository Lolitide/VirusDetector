/**
 * Virus Detector — 可信平台白名单 (Trusted Platforms Whitelist)
 *
 * 用于避免将合法 Wiki、代码托管、博客、文档等 UGC 平台的子页面
 * 误判为仿冒官网。匹配逻辑：提取 URL 的注册域（eTLD+1），
 * 与白名单进行 O(1) 查找比对。
 *
 * @module trusted-platforms
 * @version 2.2.4
 *
 * 设计原则：
 *   - 白名单为可配置、可扩展的 Set，新增/移除平台只需修改数组
 *   - 匹配粒度是 eTLD+1（注册域），匹配后该域下所有子页面均受信任
 *   - 仅跳过仿冒官网检测（规则一），其他安全规则仍正常运行
 *
 * 覆盖类别：
 *   - Wiki 农场：Fandom, Wikia, Miraheze, wiki.gg 等
 *   - 代码托管 Pages：GitHub Pages, GitLab Pages, Codeberg Pages 等
 *   - PaaS 部署：Netlify, Vercel, Heroku, Cloudflare Pages 等
 *   - 博客平台：Medium, WordPress.com, Blogger, Substack 等
 *   - 文档/知识库：Read the Docs, Notion, GitBook 等
 *   - 建站/个人页：Wix, Weebly, Carrd, About.me 等
 */

// ==================== 可信平台域名集合 ====================

const TRUSTED_PLATFORMS = new Set([
  // ---- Wiki 平台 ----
  'fandom.com',
  'wikia.com',
  'wikimedia.org',
  'miraheze.org',
  'wiki.gg',
  'gamepedia.com',

  // ---- 代码托管 Pages ----
  'github.io',
  'gitlab.io',
  'bitbucket.io',
  'sourceforge.io',
  'codeberg.page',

  // ---- PaaS / 静态站点托管 ----
  'netlify.app',
  'vercel.app',
  'herokuapp.com',
  'pages.dev',          // Cloudflare Pages
  'surge.sh',
  'glitch.me',
  'onrender.com',
  'fly.dev',
  'workers.dev',        // Cloudflare Workers
  'deno.dev',

  // ---- 博客与内容平台 ----
  'medium.com',
  'wordpress.com',
  'blogger.com',
  'blogspot.com',
  'tumblr.com',
  'hatenablog.com',
  'fc2.com',
  'livejournal.com',
  'typepad.com',
  'substack.com',
  'ghost.io',
  'hashnode.dev',
  'dev.to',

  // ---- 文档与知识库 ----
  'readthedocs.io',
  'notion.site',
  'gitbook.io',

  // ---- 建站 / 个人页 ----
  'weebly.com',
  'wixsite.com',
  'jimdo.com',
  'strikingly.com',
  'carrd.co',
  'about.me',
  'linktr.ee',
]);

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
