/**
 * Virus Detector — Resource Resolver 主调度器
 *
 * 负责：
 *   1. 注册所有解析器（可插拔架构）
 *   2. 接收 Content Script 采集的资源数据
 *   3. BFS 遍历资源树，递归解析（受深度/数量/超时限制）
 *   4. 输出统一的 ResourceGraph 供 ScoringEngine Rule2 消费
 *
 * 设计原则：
 *   - 任何解析失败 → 返回中性结果，不影响其他模块
 *   - 总超时 5s → 超时后立即返回已构建的部分 Graph
 *   - 同一 URL 整个生命周期最多解析一次（Visited Set）
 *
 * @module resource-resolver
 */

import { ResourceGraph, createResourceNode } from './resource-graph.js';
import { BaseResolver } from './resolvers/base-resolver.js';
import { HtmlResolver } from './resolvers/html-resolver.js';
import { ScriptResolver } from './resolvers/script-resolver.js';
import { MetaRefreshResolver } from './resolvers/meta-resolver.js';
import { TxtResolver } from './resolvers/txt-resolver.js';
import { RedirectResolver } from './resolvers/redirect-resolver.js';
import { JsonResolver } from './resolvers/json-resolver.js';
import { IframeResolver } from './resolvers/iframe-resolver.js';
import { ExternalScriptResolver } from './resolvers/external-script-resolver.js';
import {
  MAX_DEPTH, MAX_TOTAL_RESOURCES, MAX_TXT_SIZE,
  PER_RESOURCE_TIMEOUT, TOTAL_TIMEOUT,
  FETCH_INTERMEDIATE_PAGES, MAX_INTERMEDIATE_PAGES, MAX_INTERMEDIATE_PAGE_SIZE,
  ENABLED_RESOLVERS, RESOURCE_TYPES, SOURCE_TYPES
} from './config.js';

// ==================== 解析器注册表 ====================

/** @type {Map<string, BaseResolver>} */
const resolverRegistry = new Map();

/**
 * 注册所有解析器（按 ENABLED_RESOLVERS 顺序）
 */
function registerResolvers() {
  const allResolvers = {
    HtmlResolver,
    ScriptResolver,
    MetaRefreshResolver,
    TxtResolver,
    RedirectResolver,
    JsonResolver,
    IframeResolver,
    ExternalScriptResolver
  };

  for (const name of ENABLED_RESOLVERS) {
    const ResolverClass = allResolvers[name];
    if (ResolverClass) {
      resolverRegistry.set(name, new ResolverClass());
    }
  }
}

// 初始化时注册
registerResolvers();

// ==================== Fetch 封装 ====================

/**
 * 带超时和大小的 fetch 封装
 * @param {string} url
 * @param {Object} options
 * @param {number} options.sizeLimit  — 最大下载字节
 * @param {string} options.method     — HTTP 方法
 * @param {boolean} options.followRedirects — 是否跟随重定向
 * @returns {Promise<{ok: boolean, status: number, headers: Object|null, text: Function}>}
 */
async function fetchWithLimits(url, options = {}) {
  const { sizeLimit, method = 'GET', followRedirects = true } = options;
  const timeoutMs = PER_RESOURCE_TIMEOUT;

  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
      reject(new Error('timeout'));
    }, timeoutMs);

    const fetchOptions = {
      method,
      signal: controller.signal,
      redirect: followRedirects ? 'follow' : 'manual'
    };

    fetch(url, fetchOptions)
      .then(async (response) => {
        clearTimeout(timeoutId);

        // 处理重定向（manual 模式）
        if (!followRedirects && response.status >= 300 && response.status < 400) {
          resolve({
            ok: response.ok,
            status: response.status,
            headers: response.headers,
            text: async () => ''
          });
          return;
        }

        // HEAD 请求不读 body
        if (method === 'HEAD') {
          resolve({
            ok: response.ok,
            status: response.status,
            headers: response.headers,
            text: async () => ''
          });
          return;
        }

        // 检查 Content-Length
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength) > (sizeLimit || MAX_TXT_SIZE)) {
          controller.abort();
          reject(new Error('size_exceeded'));
          return;
        }

        // 读取文本（带大小限制）
        try {
          const text = await response.text();
          if (text.length > (sizeLimit || MAX_TXT_SIZE)) {
            reject(new Error('size_exceeded'));
          } else {
            resolve({
              ok: response.ok,
              status: response.status,
              headers: response.headers,
              text: async () => text
            });
          }
        } catch (e) {
          reject(new Error('read_error: ' + e.message));
        }
      })
      .catch((err) => {
        clearTimeout(timeoutId);
        reject(err);
      });
  });
}

// ==================== Resource Resolver ====================

export class ResourceResolver {
  /**
   * 主入口：解析页面资源树
   *
   * @param {string} pageUrl     — 页面完整 URL
   * @param {Object} initialData — Content Script 发送的 resourceData
   * @param {Object} [options]   — 可选的配置覆盖
   * @returns {Promise<ResourceGraph>}
   */
  static async resolve(pageUrl, initialData, options = {}) {
    const startTime = Date.now();
    const config = {
      maxDepth: options.maxDepth || MAX_DEPTH,
      maxTotalResources: options.maxTotalResources || MAX_TOTAL_RESOURCES,
      maxTxtSize: options.maxTxtSize || MAX_TXT_SIZE,
      perResourceTimeout: options.perResourceTimeout || PER_RESOURCE_TIMEOUT,
      totalTimeout: options.totalTimeout || TOTAL_TIMEOUT,
      fetchIntermediatePages: options.fetchIntermediatePages !== undefined ?
        options.fetchIntermediatePages : FETCH_INTERMEDIATE_PAGES,
      maxIntermediatePages: options.maxIntermediatePages || MAX_INTERMEDIATE_PAGES,
      maxIntermediatePageSize: options.maxIntermediatePageSize || MAX_INTERMEDIATE_PAGE_SIZE
    };

    // 创建 ResourceGraph
    const graph = new ResourceGraph(pageUrl);

    // 创建根节点（页面本身）
    const rootNode = createResourceNode(
      RESOURCE_TYPES.HTML,
      pageUrl,
      null,
      0,
      SOURCE_TYPES.PAGE_ROOT,
      {
        htmlUrls: initialData.htmlUrls || [],
        pageText: initialData.pageText || ''
      }
    );
    graph.addNode(rootNode);

    // 访问集合
    const visited = new Set();
    visited.add(normalizeUrlKey(pageUrl));

    // 解析上下文
    const context = {
      graph,
      config,
      fetchFn: fetchWithLimits,
      startTime,
      visited,
      pageUrl,
      pageDomain: graph.pageDomain
    };

    // BFS 队列：[{ url, parentUrl, depth, type, sourceType, metadata }]
    const queue = [];

    // 将 Content Script 采集的资源数据作为初始种子加入队列
    _enqueueInitialData(queue, initialData, pageUrl, visited, graph);

    // BFS 主循环
    while (queue.length > 0 && graph.totalResources < config.maxTotalResources) {
      // 总超时检查
      if (Date.now() - startTime > config.totalTimeout) {
        console.log('[ResourceResolver] 总超时，停止解析（已处理 ' + graph.totalResources + ' 个资源）');
        break;
      }

      const current = queue.shift();
      const normalizedUrl = normalizeUrlKey(current.url);

      // 去重
      if (visited.has(normalizedUrl)) continue;
      visited.add(normalizedUrl);

      // 深度限制
      if (current.depth > config.maxDepth) continue;

      // 数量限制
      if (graph.totalResources >= config.maxTotalResources) break;

      // 创建节点
      const node = createResourceNode(
        current.type || RESOURCE_TYPES.UNKNOWN,
        current.url,
        current.parentUrl,
        current.depth,
        current.sourceType || SOURCE_TYPES.A_HREF,
        current.metadata || {}
      );
      graph.addNode(node);

      // 添加父子关系
      if (current.parentUrl) {
        graph.addEdge(current.parentUrl, current.url);
      }

      // 查找匹配的解析器
      const children = await _resolveWithResolvers(node, context);

      // 将子节点加入队列
      for (const child of children) {
        const childNormalized = normalizeUrlKey(child.url);
        if (!visited.has(childNormalized)) {
          queue.push(child);
        }
      }
    }

    // 如果有 pageText，从中提取额外的归档 URL
    if (initialData.pageText && graph.totalResources < config.maxTotalResources) {
      _extractFromPageText(graph, initialData.pageText, pageUrl, visited, config);
    }

    // ═══ 中间页抓取（可选，默认关闭） ═══
    // 对标记为 intermediate_page 的 HTML 链接，fetch 内容提取 ZIP
    if (initialData.intermediatePages && initialData.intermediatePages.length > 0 &&
        config.fetchIntermediatePages && graph.totalResources < config.maxTotalResources) {
      await _fetchIntermediatePages(graph, initialData.intermediatePages, pageUrl, graph.pageDomain, visited, config, context);
    }

    console.log('[ResourceResolver] 解析完成:', graph.getSummary());
    return graph;
  }
}

// ==================== 内部函数 ====================

/**
 * 将 Content Script 采集的初始资源数据加入 BFS 队列
 */
function _enqueueInitialData(queue, initialData, pageUrl, visited, graph) {
  if (!initialData) return;

  // 1. HTML URL 列表
  if (initialData.htmlUrls && initialData.htmlUrls.length > 0) {
    for (const item of initialData.htmlUrls) {
      const rawUrl = typeof item === 'string' ? item : item.rawUrl || item.url || '';
      if (!rawUrl) continue;

      try {
        const absoluteUrl = new URL(rawUrl, pageUrl).href;
        if (absoluteUrl === pageUrl) continue; // 跳过自身

        const tagName = typeof item === 'object' ? (item.tagName || '') : '';
        const attrName = typeof item === 'object' ? (item.attrName || '') : '';

        queue.push({
          url: absoluteUrl,
          parentUrl: pageUrl,
          depth: 1,
          type: _classifyByUrl(absoluteUrl, tagName),
          sourceType: _sourceTypeFromTag(tagName, attrName),
          metadata: {
            ext: _extractExt(absoluteUrl),
            isCrossDomain: _isCrossDomain(absoluteUrl, pageUrl),
            tagName,
            attrName
          }
        });
      } catch (e) { /* 跳过无效 URL */ }
    }
  }

  // 2. Inline Scripts
  if (initialData.inlineScripts && initialData.inlineScripts.length > 0) {
    for (let i = 0; i < initialData.inlineScripts.length; i++) {
      const script = initialData.inlineScripts[i];
      const scriptText = script.text || '';
      if (!scriptText || scriptText.length < 3) continue;

      // 为每个 inline script 创建一个虚拟节点
      const scriptUrl = pageUrl + '#__inline_script_' + i;
      queue.push({
        url: scriptUrl,
        parentUrl: pageUrl,
        depth: 1,
        type: RESOURCE_TYPES.SCRIPT_INLINE,
        sourceType: SOURCE_TYPES.INLINE_SCRIPT,
        metadata: {
          scriptText,
          isExternal: false
        }
      });
    }
  }

  // 3. Meta Refresh
  if (initialData.metaRefreshUrls && initialData.metaRefreshUrls.length > 0) {
    for (let i = 0; i < initialData.metaRefreshUrls.length; i++) {
      const meta = initialData.metaRefreshUrls[i];
      const metaUrl = meta.url || '';
      if (!metaUrl) continue;

      try {
        const absoluteUrl = new URL(metaUrl, pageUrl).href;

        const metaVirtualUrl = pageUrl + '#__meta_refresh_' + i;
        queue.push({
          url: metaVirtualUrl,
          parentUrl: pageUrl,
          depth: 1,
          type: RESOURCE_TYPES.META_REFRESH,
          sourceType: SOURCE_TYPES.META_REFRESH,
          metadata: {
            metaUrls: [{
              url: absoluteUrl,
              delay: meta.delay || 0,
              originalContent: meta.originalContent || ''
            }]
          }
        });
      } catch (e) { /* 跳过 */ }
    }
  }

  // 4. iframe srcs
  if (initialData.iframeSrcs && initialData.iframeSrcs.length > 0) {
    for (const src of initialData.iframeSrcs) {
      if (!src) continue;
      try {
        const absoluteUrl = new URL(src, pageUrl).href;
        queue.push({
          url: absoluteUrl,
          parentUrl: pageUrl,
          depth: 1,
          type: RESOURCE_TYPES.IFRAME,
          sourceType: SOURCE_TYPES.IFRAME_SRC,
          metadata: {
            ext: _extractExt(absoluteUrl),
            isCrossDomain: _isCrossDomain(absoluteUrl, pageUrl)
          }
        });
      } catch (e) { /* 跳过 */ }
    }
  }
}

/**
 * 使用注册的解析器处理节点
 */
async function _resolveWithResolvers(node, context) {
  const allChildren = [];

  for (const [name, resolver] of resolverRegistry) {
    if (!resolver.canHandle(node)) continue;

    try {
      // 单资源超时保护
      const result = await Promise.race([
        resolver.resolve(node, context),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('per_resource_timeout')), context.config.perResourceTimeout)
        )
      ]);

      if (result && result.length > 0) {
        for (const child of result) {
          allChildren.push(child);
        }
      }
    } catch (e) {
      // 任何失败 → 记录日志，继续处理其他解析器
      console.debug('[ResourceResolver] 解析器 ' + name + ' 失败:', node.url, e.message);
    }

    // 一个节点通常只有一个匹配的解析器，找到后即可退出
    break;
  }

  return allChildren;
}

/**
 * 从 pageText 中提取归档 URL（兜底）
 */
function _extractFromPageText(graph, pageText, pageUrl, visited, config) {
  const foundUrls = new Set();

  ARCHIVE_URL_PATTERN.lastIndex = 0;
  let match;
  while ((match = ARCHIVE_URL_PATTERN.exec(pageText)) !== null) {
    try {
      const absoluteUrl = new URL(match[0], pageUrl).href;
      if (!visited.has(normalizeUrlKey(absoluteUrl))) {
        foundUrls.add(absoluteUrl);
      }
    } catch (e) { /* skip */ }
  }

  for (const url of foundUrls) {
    if (graph.totalResources >= config.maxTotalResources) break;

    const node = createResourceNode(
      RESOURCE_TYPES.ARCHIVE,
      url,
      pageUrl,
      1,
      SOURCE_TYPES.HTML_TEXT,
      {
        ext: _extractExt(url),
        isCrossDomain: _isCrossDomain(url, pageUrl)
      }
    );
    graph.addNode(node);
    graph.addEdge(pageUrl, url);
    visited.add(normalizeUrlKey(url));
  }
}

/**
 * 抓取中间下载页，提取其中的归档 URL。
 * 解决"页面 A → 下载页 B → ZIP"的发现链问题。
 */
async function _fetchIntermediatePages(graph, intermediatePages, pageUrl, pageDomain, visited, config, context) {
  const limit = Math.min(intermediatePages.length, config.maxIntermediatePages);
  let processed = 0;

  for (let i = 0; i < limit; i++) {
    if (graph.totalResources >= config.maxTotalResources) break;
    if (Date.now() - context.startTime > config.totalTimeout) break;

    const ip = intermediatePages[i];
    const targetUrl = ip.url;
    if (!targetUrl || visited.has(normalizeUrlKey(targetUrl))) continue;

    processed++;
    visited.add(normalizeUrlKey(targetUrl));

    try {
      // HEAD 请求确认可达性
      const headResp = await context.fetchFn(targetUrl, {
        method: 'HEAD',
        followRedirects: false
      });

      let finalUrl = targetUrl;
      // 跟踪重定向
      if (headResp.status >= 300 && headResp.status < 400) {
        const location = _getHeader(headResp, 'location');
        if (location) {
          try {
            finalUrl = new URL(location, targetUrl).href;
          } catch (e) { /* keep original */ }
          graph.addRedirect(targetUrl, finalUrl, headResp.status);
        }

        // 如果最终 URL 是归档 → 直接记录
        const finalExt = _extractExt(finalUrl);
        const archExts = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.iso', '.cab', '.exe', '.msi', '.apk'];
        if (archExts.some(e => finalExt === e || finalExt.endsWith(e))) {
          const node = createResourceNode(RESOURCE_TYPES.ARCHIVE, finalUrl, pageUrl, 1, SOURCE_TYPES.REDIRECT, {
            ext: finalExt,
            isCrossDomain: _isCrossDomain(finalUrl, pageUrl),
            statusCode: headResp.status
          });
          graph.addNode(node);
          graph.addEdge(pageUrl, finalUrl);
          continue;
        }
      }

      // GET 请求获取中间页 HTML（仅非归档页面）
      if (headResp.ok !== false) {
        const fetchResult = await context.fetchFn(finalUrl, {
          sizeLimit: config.maxIntermediatePageSize
        });
        const html = await fetchResult.text();

        if (html && html.length > 0) {
          // 正则提取所有归档 URL
          const { ARCHIVE_URL_PATTERN: urlPattern } = await import('./config.js');
          urlPattern.lastIndex = 0;
          let match;
          while ((match = urlPattern.exec(html)) !== null) {
            try {
              const absoluteUrl = new URL(match[0], finalUrl).href;
              if (!visited.has(normalizeUrlKey(absoluteUrl)) &&
                  graph.totalResources < config.maxTotalResources) {
                const ext = _extractExt(absoluteUrl);
                const node = createResourceNode(
                  RESOURCE_TYPES.ARCHIVE,
                  absoluteUrl,
                  pageUrl,
                  2, // depth = 2: page → intermediate page → archive
                  SOURCE_TYPES.HTML_TEXT,
                  {
                    ext,
                    isCrossDomain: _isCrossDomain(absoluteUrl, pageUrl),
                    textSnippet: html.substring(
                      Math.max(0, html.indexOf(match[0]) - 20),
                      Math.min(html.length, html.indexOf(match[0]) + match[0].length + 20)
                    )
                  }
                );
                graph.addNode(node);
                graph.addEdge(pageUrl, absoluteUrl);
                visited.add(normalizeUrlKey(absoluteUrl));
              }
            } catch (e) { /* skip */ }
          }
        }
      }
    } catch (e) {
      console.debug('[ResourceResolver] 中间页抓取失败:', targetUrl, e.message);
      // 失败不影响其他页面的抓取
    }
  }
}

/**
 * 从响应对象中提取 header 值
 */
function _getHeader(response, name) {
  if (!response || !response.headers) return null;
  if (typeof response.headers.get === 'function') {
    return response.headers.get(name);
  }
  return response.headers[name] || null;
}

// ==================== 工具函数 ====================

function normalizeUrlKey(url) {
  try {
    const u = new URL(url);
    u.hash = '';
    return u.href.toLowerCase();
  } catch (e) {
    return (url || '').replace(/#.*$/, '').toLowerCase();
  }
}

function _extractExt(url) {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    if (pathname.endsWith('.tar.gz')) return '.tar.gz';
    if (pathname.endsWith('.tar.bz2')) return '.tar.bz2';
    if (pathname.endsWith('.tar.xz')) return '.tar.xz';
    const m = pathname.match(/\.([a-z0-9]+)$/i);
    return m ? '.' + m[1].toLowerCase() : '';
  } catch (e) { return ''; }
}

function _isCrossDomain(url1, url2) {
  try {
    return new URL(url1).hostname !== new URL(url2).hostname;
  } catch (e) { return true; }
}

function _classifyByUrl(url, tagName) {
  const ext = _extractExt(url);
  const ARCHIVE_EXTS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz', '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh', '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'];
  const EXECUTABLE_EXTS = ['.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar', '.bin', '.run', '.sh', '.dmg'];

  if (ARCHIVE_EXTS.some(e => ext === e || ext.endsWith(e))) return RESOURCE_TYPES.ARCHIVE;
  if (EXECUTABLE_EXTS.some(e => ext === e || ext.endsWith(e))) return RESOURCE_TYPES.EXECUTABLE;
  if (/\.(txt|text|log|csv)$/i.test(url)) return RESOURCE_TYPES.TXT;
  if (/\.json$/i.test(url)) return RESOURCE_TYPES.JSON;
  if (tagName === 'iframe') return RESOURCE_TYPES.IFRAME;
  return RESOURCE_TYPES.UNKNOWN;
}

function _sourceTypeFromTag(tagName, attrName) {
  const tag = (tagName || '').toLowerCase();
  const attr = (attrName || '').toLowerCase();
  if (tag === 'a' && attr === 'href') return SOURCE_TYPES.A_HREF;
  if (tag === 'link' && attr === 'href') return SOURCE_TYPES.LINK_HREF;
  if (tag === 'script' && attr === 'src') return SOURCE_TYPES.SCRIPT_SRC;
  if (tag === 'img' && attr === 'src') return SOURCE_TYPES.IMG_SRC;
  if (tag === 'iframe' && attr === 'src') return SOURCE_TYPES.IFRAME_SRC;
  if (tag === 'form' && attr === 'action') return SOURCE_TYPES.FORM_ACTION;
  return SOURCE_TYPES.A_HREF;
}

// 在 Node.js 环境下 require 不可用，改用静态 import
import { ARCHIVE_URL_PATTERN, URL_PATTERN } from './config.js';
