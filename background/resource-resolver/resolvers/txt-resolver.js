/**
 * Virus Detector — TXT 解析器
 *
 * Fetch .txt 文件内容，正则提取其中的所有 URL。
 * 支持 TXT → TXT → ZIP 多级递归（受深度限制）。
 *
 * 限制：
 *   - 最大 256KB（超过立即停止）
 *   - 单资源超时 2s
 *   - 深度 ≤ MAX_DEPTH
 *
 * @module resource-resolver/resolvers/txt-resolver
 */

import { BaseResolver } from './base-resolver.js';
import {
  RESOURCE_TYPES, SOURCE_TYPES,
  URL_PATTERN, ARCHIVE_URL_PATTERN,
  MAX_TXT_SIZE
} from '../config.js';

export class TxtResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.TXT && !node.metadata._resolved;
  }

  async resolve(node, context) {
    const discovered = [];

    // 检查深度
    if (node.depth >= context.config.maxDepth) {
      return discovered;
    }

    // 标记已解析
    node.metadata._resolved = true;

    let content;
    try {
      content = await context.fetchFn(node.url, { sizeLimit: MAX_TXT_SIZE });
    } catch (e) {
      // 网络错误或超时 → 返回空结果（不影响其他解析）
      console.debug('[TxtResolver] Fetch 失败:', node.url, e.message);
      return discovered;
    }

    if (!content || content.length === 0) {
      return discovered;
    }

    const pageUrl = node.parentUrl || context.pageUrl;
    const foundUrls = new Set();

    // ========== 1. 归档 URL（优先级最高） ==========
    ARCHIVE_URL_PATTERN.lastIndex = 0;
    let aMatch;
    while ((aMatch = ARCHIVE_URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(aMatch[0], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // ========== 2. 通用 URL ==========
    URL_PATTERN.lastIndex = 0;
    let uMatch;
    while ((uMatch = URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(uMatch[0], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // 创建子节点
    for (const url of foundUrls) {
      const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(url);
      const isCrossDomain = this.isCrossDomain(url, context.pageUrl);

      let nodeType;
      if (isArchive) {
        nodeType = RESOURCE_TYPES.ARCHIVE;
      } else if (isExecutable) {
        nodeType = RESOURCE_TYPES.EXECUTABLE;
      } else if (isTxt) {
        // 如果 TXT 指向另一个 TXT → 允许继续递归（只要深度未超限）
        nodeType = RESOURCE_TYPES.TXT;
      } else if (isJson) {
        nodeType = RESOURCE_TYPES.JSON;
      } else {
        nodeType = RESOURCE_TYPES.UNKNOWN;
      }

      discovered.push({
        url,
        type: nodeType,
        sourceType: SOURCE_TYPES.TXT_CONTENT,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          isExternal: isCrossDomain,
          textSnippet: content.substring(
            Math.max(0, content.indexOf(url) - 40),
            Math.min(content.length, content.indexOf(url) + url.length + 40)
          )
        }
      });
    }

    return discovered;
  }
}
