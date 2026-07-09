/**
 * Virus Detector — JSON 解析器
 *
 * Fetch JSON 内容，递归遍历所有值，提取包含归档/可执行文件扩展名的 URL 字符串。
 *
 * @module resource-resolver/resolvers/json-resolver
 */

import { BaseResolver } from './base-resolver.js';
import {
  RESOURCE_TYPES, SOURCE_TYPES,
  ARCHIVE_URL_PATTERN, URL_PATTERN,
  MAX_JSON_SIZE
} from '../config.js';

export class JsonResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.JSON && !node.metadata._resolved;
  }

  async resolve(node, context) {
    const discovered = [];

    if (node.depth >= context.config.maxDepth) {
      return discovered;
    }

    node.metadata._resolved = true;

    let content;
    try {
      content = await context.fetchFn(node.url, { sizeLimit: MAX_JSON_SIZE });
    } catch (e) {
      console.debug('[JsonResolver] Fetch 失败:', node.url, e.message);
      return discovered;
    }

    if (!content || content.length === 0) return discovered;

    // 先直接从原始文本中匹配归档 URL（无需 JSON.parse）
    const rawPageUrl = node.parentUrl || context.pageUrl;
    const foundUrls = new Set();

    // 从原始文本匹配
    ARCHIVE_URL_PATTERN.lastIndex = 0;
    let aMatch;
    while ((aMatch = ARCHIVE_URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(aMatch[0], rawPageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // 尝试 JSON.parse 并递归遍历值
    try {
      const parsed = JSON.parse(content);
      this._extractUrlsFromValue(parsed, foundUrls, rawPageUrl);
    } catch (e) {
      // JSON 解析失败 → 仅使用原始文本匹配结果
    }

    // 额外：从原始文本匹配所有 URL
    URL_PATTERN.lastIndex = 0;
    let uMatch;
    while ((uMatch = URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(uMatch[0], rawPageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    for (const url of foundUrls) {
      const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(url);
      const isCrossDomain = this.isCrossDomain(url, context.pageUrl);

      let nodeType;
      if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
      else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
      else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
      else if (isJson) nodeType = RESOURCE_TYPES.JSON;
      else nodeType = RESOURCE_TYPES.UNKNOWN;

      discovered.push({
        url,
        type: nodeType,
        sourceType: SOURCE_TYPES.JSON_CONTENT,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          isExternal: isCrossDomain
        }
      });
    }

    return discovered;
  }

  /**
   * 递归遍历 JSON 值，提取 URL 字符串
   */
  _extractUrlsFromValue(value, urlSet, baseUrl, depth = 0) {
    if (depth > 10) return; // 防止深层嵌套

    if (typeof value === 'string') {
      // 检查是否像 URL
      if (value.length > 10 && /^https?:\/\//.test(value)) {
        const absoluteUrl = this.resolveUrl(value, baseUrl);
        if (absoluteUrl) {
          const { isArchive, isExecutable } = this.classifyUrl(absoluteUrl);
          if (isArchive || isExecutable) {
            urlSet.add(absoluteUrl);
          }
        }
      }
      // 字符串中可能嵌入了 URL
      ARCHIVE_URL_PATTERN.lastIndex = 0;
      let match;
      while ((match = ARCHIVE_URL_PATTERN.exec(value)) !== null) {
        const absoluteUrl = this.resolveUrl(match[0], baseUrl);
        if (absoluteUrl) urlSet.add(absoluteUrl);
      }
    } else if (Array.isArray(value)) {
      for (const item of value) {
        this._extractUrlsFromValue(item, urlSet, baseUrl, depth + 1);
      }
    } else if (value && typeof value === 'object') {
      const keys = Object.keys(value);
      // 限制：最多遍历 50 个 key
      for (let i = 0; i < Math.min(keys.length, 50); i++) {
        this._extractUrlsFromValue(value[keys[i]], urlSet, baseUrl, depth + 1);
      }
    }
  }
}
