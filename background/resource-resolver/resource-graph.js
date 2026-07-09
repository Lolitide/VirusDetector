/**
 * Virus Detector — Resource Graph 数据结构
 *
 * 定义 ResourceNode（资源节点）和 ResourceGraph（资源树），
 * 为 Resource Resolver 和 Scoring Engine Rule2 提供统一的数据交换格式。
 *
 * @module resource-resolver/resource-graph
 */

import { UrlUtils } from '../../utils/url-utils.js';

// ==================== ResourceNode ====================

/**
 * 资源节点 — 表示解析树中的一个资源
 *
 * @typedef {Object} ResourceNode
 * @property {string} type          — 资源类型（html/txt/archive/executable/script_inline/...）
 * @property {string} url           — 绝对 URL
 * @property {string|null} parentUrl — 父资源 URL（根为 null）
 * @property {number} depth         — 在树中的深度（0 = 页面本身）
 * @property {string} sourceType    — 提取来源（a_href/inline_script/txt_content/...）
 * @property {string|null} mime     — Content-Type（如果 fetch 过）
 * @property {number|null} sizeBytes — 资源大小（如果 fetch 过）
 * @property {string[]} children    — 子节点 URL 列表
 * @property {Object} metadata      — 附加元数据
 */
export function createResourceNode(type, url, parentUrl, depth, sourceType, metadata = {}) {
  return {
    type,
    url: normalizeUrl(url),
    parentUrl: parentUrl ? normalizeUrl(parentUrl) : null,
    depth: depth || 0,
    sourceType,
    mime: metadata.mime || null,
    sizeBytes: metadata.sizeBytes || null,
    children: [],
    metadata: {
      ext: metadata.ext || extractExtension(url),
      isCrossDomain: metadata.isCrossDomain !== undefined ? metadata.isCrossDomain : null,
      statusCode: metadata.statusCode || null,
      extractedFrom: metadata.extractedFrom || '',
      isExternal: metadata.isExternal || false,
      textSnippet: metadata.textSnippet || ''
    }
  };
}

// ==================== ResourceGraph ====================

/**
 * 资源树 — 页面及其所有递归发现的资源构成的树形结构
 *
 * @typedef {Object} ResourceGraph
 * @property {string} pageUrl         — 页面 URL
 * @property {string} pageDomain      — 页面域名
 * @property {Map<string, ResourceNode>} nodes — URL → Node 映射
 * @property {string} rootUrl         — 根节点 URL（= pageUrl）
 * @property {ResourceNode[]} discoveredArchives    — 发现的所有归档文件节点
 * @property {ResourceNode[]} discoveredExecutables — 发现的所有可执行文件节点
 * @property {Object[]} redirectChain — 重定向链 [{from, to, statusCode}]
 * @property {number} maxDepth        — 树的最大深度
 * @property {number} totalResources  — 资源总数
 * @property {number} txtDepth        — TXT 链的最大深度
 */
export class ResourceGraph {
  /**
   * @param {string} pageUrl — 页面完整 URL
   */
  constructor(pageUrl) {
    /** @type {string} */
    this.pageUrl = normalizeUrl(pageUrl);
    /** @type {string} */
    this.pageDomain = extractHostname(this.pageUrl);
    /** @type {Map<string, ResourceNode>} */
    this.nodes = new Map();
    /** @type {string} */
    this.rootUrl = this.pageUrl;
    /** @type {ResourceNode[]} */
    this.discoveredArchives = [];
    /** @type {ResourceNode[]} */
    this.discoveredExecutables = [];
    /** @type {Object[]} */
    this.redirectChain = [];
    /** @type {number} */
    this.maxDepth = 0;
    /** @type {number} */
    this.totalResources = 0;
    /** @type {number} */
    this.txtDepth = 0;
  }

  /**
   * 添加一个资源节点到图中
   * @param {ResourceNode} node
   * @returns {ResourceNode} 已添加的节点
   */
  addNode(node) {
    const key = normalizeUrl(node.url);
    if (this.nodes.has(key)) {
      return this.nodes.get(key);
    }

    this.nodes.set(key, node);
    this.totalResources = this.nodes.size;
    this.maxDepth = Math.max(this.maxDepth, node.depth);

    // 自动分类索引
    const ext = (node.metadata.ext || '').toLowerCase();
    const { ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS } = requireConfig();

    if (ARCHIVE_EXTENSIONS.some(e => ext === e || ext.endsWith(e))) {
      this.discoveredArchives.push(node);
    }
    if (EXECUTABLE_EXTENSIONS.some(e => ext === e || ext.endsWith(e))) {
      this.discoveredExecutables.push(node);
    }

    // 跟踪 TXT 深度
    if (node.type === 'txt') {
      this.txtDepth = Math.max(this.txtDepth, node.depth);
    }

    return node;
  }

  /**
   * 添加父子关系
   * @param {string} parentUrl — 父节点 URL
   * @param {string} childUrl  — 子节点 URL
   */
  addEdge(parentUrl, childUrl) {
    const parentKey = normalizeUrl(parentUrl);
    const parent = this.nodes.get(parentKey);
    if (parent) {
      const childKey = normalizeUrl(childUrl);
      if (!parent.children.includes(childKey)) {
        parent.children.push(childKey);
      }
    }
  }

  /**
   * 记录一个重定向跳转
   * @param {string} from        — 源 URL
   * @param {string} to          — 目标 URL
   * @param {number} statusCode  — HTTP 状态码
   */
  addRedirect(from, to, statusCode) {
    this.redirectChain.push({
      from: normalizeUrl(from),
      to: normalizeUrl(to),
      statusCode
    });
  }

  /**
   * 获取某个节点（按 URL）
   * @param {string} url
   * @returns {ResourceNode|undefined}
   */
  getNode(url) {
    return this.nodes.get(normalizeUrl(url));
  }

  /**
   * 遍历所有节点（BFS）
   * @param {Function} callback — (node: ResourceNode) => void
   */
  forEachNode(callback) {
    for (const node of this.nodes.values()) {
      callback(node);
    }
  }

  /**
   * 获取根节点下的直接子节点 URL 列表
   * @returns {string[]}
   */
  getRootChildren() {
    const root = this.nodes.get(this.rootUrl);
    return root ? [...root.children] : [];
  }

  /**
   * 序列化为 JSON（用于缓存和消息传递）
   * @returns {Object}
   */
  toJSON() {
    const nodesArray = [];
    for (const node of this.nodes.values()) {
      nodesArray.push({ ...node });
    }
    return {
      pageUrl: this.pageUrl,
      pageDomain: this.pageDomain,
      rootUrl: this.rootUrl,
      nodes: nodesArray,
      discoveredArchives: this.discoveredArchives.map(n => ({ ...n })),
      discoveredExecutables: this.discoveredExecutables.map(n => ({ ...n })),
      redirectChain: [...this.redirectChain],
      maxDepth: this.maxDepth,
      totalResources: this.totalResources,
      txtDepth: this.txtDepth
    };
  }

  /**
   * 从 JSON 反序列化
   * @param {Object} json
   * @returns {ResourceGraph}
   */
  static fromJSON(json) {
    const graph = new ResourceGraph(json.pageUrl);
    graph.pageDomain = json.pageDomain;
    graph.rootUrl = json.rootUrl;
    graph.maxDepth = json.maxDepth;
    graph.totalResources = json.totalResources;
    graph.txtDepth = json.txtDepth;
    graph.redirectChain = json.redirectChain || [];

    if (json.nodes) {
      for (const n of json.nodes) {
        graph.nodes.set(normalizeUrl(n.url), n);
      }
    }

    // 恢复索引
    if (json.discoveredArchives) {
      for (const n of json.discoveredArchives) {
        const existing = graph.nodes.get(normalizeUrl(n.url));
        graph.discoveredArchives.push(existing || n);
      }
    }
    if (json.discoveredExecutables) {
      for (const n of json.discoveredExecutables) {
        const existing = graph.nodes.get(normalizeUrl(n.url));
        graph.discoveredExecutables.push(existing || n);
      }
    }

    return graph;
  }

  /**
   * 获取简要摘要（用于日志）
   * @returns {Object}
   */
  getSummary() {
    return {
      pageUrl: this.pageUrl,
      totalResources: this.totalResources,
      maxDepth: this.maxDepth,
      txtDepth: this.txtDepth,
      archivesFound: this.discoveredArchives.length,
      executablesFound: this.discoveredExecutables.length,
      redirectCount: this.redirectChain.length,
      archiveUrls: this.discoveredArchives.map(n => n.url),
      executableUrls: this.discoveredExecutables.map(n => n.url)
    };
  }
}

// ==================== 内部工具函数 ====================

/**
 * URL 归一化：去除 hash 和尾部斜杠，统一小写
 * @param {string} url
 * @returns {string}
 */
function normalizeUrl(url) {
  if (!url) return '';
  try {
    const u = new URL(url);
    u.hash = '';
    let result = u.href;
    if (result.endsWith('/') && !u.pathname.endsWith('/')) {
      // pathname 本身不以 / 结尾但 href 以 / 结尾 → 去掉尾部斜杠
    }
    return result;
  } catch (e) {
    return url.replace(/#.*$/, '');
  }
}

/**
 * 从 URL 提取主机名
 * @param {string} url
 * @returns {string}
 */
function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return '';
  }
}

/**
 * 从 URL 提取文件扩展名
 * @param {string} url
 * @returns {string}
 */
function extractExtension(url) {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    // 处理复合扩展名 .tar.gz
    if (pathname.endsWith('.tar.gz')) return '.tar.gz';
    if (pathname.endsWith('.tar.bz2')) return '.tar.bz2';
    if (pathname.endsWith('.tar.xz')) return '.tar.xz';
    const match = pathname.match(/\.([a-z0-9]+)$/i);
    return match ? '.' + match[1].toLowerCase() : '';
  } catch (e) {
    return '';
  }
}

/**
 * 懒加载 config 模块，避免循环依赖
 */
let _config = null;
function requireConfig() {
  if (!_config) {
    // 使用动态 import 的同构替代：直接内联需要的常量
    _config = {
      ARCHIVE_EXTENSIONS: [
        '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
        '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
        '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
      ],
      EXECUTABLE_EXTENSIONS: [
        '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
        '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
        '.bin', '.run', '.sh', '.dmg'
      ]
    };
  }
  return _config;
}
