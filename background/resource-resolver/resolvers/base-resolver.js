/**
 * Virus Detector — 解析器基类
 *
 * 定义所有资源解析器的统一接口。
 * 每个具体解析器继承此基类，实现 canHandle() 和 resolve() 方法。
 *
 * @module resource-resolver/resolvers/base-resolver
 */

/**
 * 解析器上下文 — 在解析过程中传递的共享状态
 *
 * @typedef {Object} ResolverContext
 * @property {import('../resource-graph.js').ResourceGraph} graph — 正在构建的资源树
 * @property {Object} config                  — 配置常量（来自 config.js）
 * @property {Function} fetchFn              — 带超时的 fetch 函数
 * @property {number} startTime              — 解析开始时间戳（用于总超时检测）
 * @property {Set<string>} visited           — 已访问的 URL 集合
 * @property {string} pageUrl                — 页面 URL（用于相对路径转换）
 * @property {string} pageDomain             — 页面域名
 */

export class BaseResolver {
  /**
   * 判断是否能处理指定的资源节点
   * @param {import('../resource-graph.js').ResourceNode} node
   * @returns {boolean}
   */
  canHandle(node) {
    throw new Error('canHandle() must be implemented by subclass');
  }

  /**
   * 解析资源节点，返回新发现的子节点列表
   * @param {import('../resource-graph.js').ResourceNode} node
   * @param {ResolverContext} context
   * @returns {Promise<import('../resource-graph.js').ResourceNode[]>}
   */
  async resolve(node, context) {
    throw new Error('resolve() must be implemented by subclass');
  }

  /**
   * 辅助方法：解析相对 URL 为绝对 URL
   * @param {string} rawUrl    — 原始 URL（可能是相对路径）
   * @param {string} baseUrl   — 基准 URL
   * @returns {string|null} 绝对 URL，解析失败返回 null
   */
  resolveUrl(rawUrl, baseUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return null;
    const trimmed = rawUrl.trim();
    if (!trimmed) return null;

    // 跳过 javascript:、data:、mailto: 等非 http 协议
    if (/^(javascript|data|mailto|tel|file|vbscript):/i.test(trimmed)) {
      return null;
    }

    // 跳过纯锚点
    if (/^#/.test(trimmed)) {
      return null;
    }

    try {
      const resolved = new URL(trimmed, baseUrl);
      // 只接受 http/https
      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
        return null;
      }
      return resolved.href;
    } catch (e) {
      return null;
    }
  }

  /**
   * 辅助方法：判断 URL 指向的文件类型
   * @param {string} url
   * @returns {{ext: string, isArchive: boolean, isExecutable: boolean, isTxt: boolean, isJson: boolean}}
   */
  classifyUrl(url) {
    const pathname = (() => {
      try { return new URL(url).pathname.toLowerCase(); } catch (e) { return url.toLowerCase(); }
    })();

    const ARCHIVE_EXTS = [
      '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
      '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
      '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
    ];
    const EXECUTABLE_EXTS = [
      '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
      '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
      '.bin', '.run', '.sh', '.dmg'
    ];

    let ext = '';
    if (pathname.endsWith('.tar.gz')) ext = '.tar.gz';
    else if (pathname.endsWith('.tar.bz2')) ext = '.tar.bz2';
    else if (pathname.endsWith('.tar.xz')) ext = '.tar.xz';
    else {
      const m = pathname.match(/\.([a-z0-9]+)$/i);
      ext = m ? '.' + m[1].toLowerCase() : '';
    }

    const isArchive = ARCHIVE_EXTS.some(e => ext === e || pathname.endsWith(e));
    const isExecutable = EXECUTABLE_EXTS.some(e => ext === e || pathname.endsWith(e));
    const isTxt = /\.(txt|text|log|csv)$/i.test(pathname);
    const isJson = /\.json$/i.test(pathname);

    return { ext, isArchive, isExecutable, isTxt, isJson };
  }

  /**
   * 辅助方法：检查两个 URL 是否跨域
   * @param {string} url1
   * @param {string} url2
   * @returns {boolean}
   */
  isCrossDomain(url1, url2) {
    try {
      const h1 = new URL(url1).hostname;
      const h2 = new URL(url2).hostname;
      return h1 !== h2;
    } catch (e) {
      return true; // 解析失败视为跨域
    }
  }
}
