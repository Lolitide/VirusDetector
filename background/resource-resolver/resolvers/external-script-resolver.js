/**
 * Virus Detector — 外部 Script 解析器（第二阶段预留）
 *
 * 解析外部 JS 文件内容，提取 URL 模式。
 * 默认关闭：fetch 所有外部 JS 代价过高，误报风险大。
 * 仅在用户通过设置显式启用后生效。
 *
 * @module resource-resolver/resolvers/external-script-resolver
 */

import { BaseResolver } from './base-resolver.js';
import {
  RESOURCE_TYPES, SOURCE_TYPES,
  LOCATION_PATTERNS, WINDOW_OPEN_PATTERN, FETCH_PATTERNS,
  STRING_URL_PATTERN, URL_PATTERN
} from '../config.js';

export class ExternalScriptResolver extends BaseResolver {
  canHandle(node) {
    // 默认返回 false（由主调度器通过 enabledResolvers 控制）
    // 如果被启用：处理外部脚本
    return false;
  }

  async resolve(node, context) {
    const discovered = [];

    if (node.depth >= context.config.maxDepth) {
      return discovered;
    }

    // 获取外部 JS 内容
    let content;
    try {
      content = await context.fetchFn(node.url, { sizeLimit: 128 * 1024 }); // 128KB
    } catch (e) {
      console.debug('[ExternalScriptResolver] Fetch 失败:', node.url, e.message);
      return discovered;
    }

    if (!content || content.length < 3) return discovered;

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
