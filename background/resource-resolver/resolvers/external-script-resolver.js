/**
 * Virus Detector — 外部 Script 解析器（预留，默认关闭）
 *
 * 解析外部 JS 文件内容，提取 URL 模式。
 * 默认关闭：fetch 所有外部 JS 代价过高，误报风险大；
 * 当前未注册进 ENABLED_RESOLVERS，canHandle 恒返回 false。
 *
 * @module resource-resolver/resolvers/external-script-resolver
 */

import { BaseResolver } from './base-resolver.js';
import {
  RESOURCE_TYPES, SOURCE_TYPES,
  LOCATION_PATTERNS, WINDOW_OPEN_PATTERN, FETCH_PATTERNS,
  STRING_URL_PATTERN, URL_PATTERN, MIN_SCRIPT_LENGTH, MAX_JSON_SIZE
} from '../config.js';

export class ExternalScriptResolver extends BaseResolver {
  canHandle(node) {
    return false;   // 未启用：不处理任何节点（注册进 ENABLED_RESOLVERS 后方可生效）
  }

  async resolve(node, context) {
    const discovered = [];

    if (node.depth >= context.config.maxDepth) {
      return discovered;
    }

    // 获取外部 JS 内容（大小限制 = config.js MAX_JSON_SIZE，语义独立于 JSON 解析）
    let content;
    try {
      content = await context.fetchFn(node.url, { sizeLimit: MAX_JSON_SIZE });
    } catch (e) {
      console.debug('[ExternalScriptResolver] Fetch 失败:', node.url, e.message);
      return discovered;
    }

    if (!content || content.length < MIN_SCRIPT_LENGTH) return discovered;

    const pageUrl = node.parentUrl || context.pageUrl;
    const foundUrls = new Set();

    // 复用与 ScriptResolver 相同的正则模式
    // location 赋值
    for (const pattern of LOCATION_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const absoluteUrl = this.resolveUrl(match[1], pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // window.open
    WINDOW_OPEN_PATTERN.lastIndex = 0;
    let woMatch;
    while ((woMatch = WINDOW_OPEN_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(woMatch[1], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // fetch/XHR
    for (const pattern of FETCH_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const absoluteUrl = this.resolveUrl(match[1], pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // 归档/可执行 URL
    STRING_URL_PATTERN.lastIndex = 0;
    let strMatch;
    while ((strMatch = STRING_URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(strMatch[1], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // 通用 URL
    URL_PATTERN.lastIndex = 0;
    let uMatch;
    while ((uMatch = URL_PATTERN.exec(content)) !== null) {
      const absoluteUrl = this.resolveUrl(uMatch[0], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    for (const url of foundUrls) {
      const { ext, isArchive, isExecutable, isTxt } = this.classifyUrl(url);
      const isCrossDomain = this.isCrossDomain(url, context.pageUrl);

      let nodeType;
      if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
      else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
      else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
      else nodeType = RESOURCE_TYPES.UNKNOWN;

      discovered.push({
        url,
        type: nodeType,
        sourceType: SOURCE_TYPES.SCRIPT_SRC,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          isExternal: true
        }
      });
    }

    return discovered;
  }
}
