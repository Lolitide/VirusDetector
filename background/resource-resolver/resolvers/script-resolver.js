/**
 * Virus Detector — Inline Script 解析器
 *
 * 静态分析 Inline Script（不执行），提取其中的 URL 模式。
 *
 * 扫描模式：
 *   - window.location / location.href / location.assign / location.replace
 *   - window.open()
 *   - fetch() / axios()
 *   - download 属性
 *   - new URL()
 *   - 字符串字面量中的 ZIP/RAR/7Z 等资源 URL
 *
 * @module resource-resolver/resolvers/script-resolver
 */

import { BaseResolver } from './base-resolver.js';
import {
  RESOURCE_TYPES, SOURCE_TYPES,
  LOCATION_PATTERNS, WINDOW_OPEN_PATTERN, FETCH_PATTERNS,
  DOWNLOAD_ATTR_PATTERN, NEW_URL_PATTERN, STRING_URL_PATTERN,
  URL_PATTERN
} from '../config.js';

export class ScriptResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.SCRIPT_INLINE;
  }

  async resolve(node, context) {
    const discovered = [];
    const scriptText = node.metadata.scriptText || '';
    if (!scriptText || scriptText.length < 3) return discovered;

    const pageUrl = node.parentUrl || context.pageUrl;
    const foundUrls = new Set();

    // ========== 1. location 赋值模式 ==========
    for (const pattern of LOCATION_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(scriptText)) !== null) {
        const rawUrl = match[1];
        const absoluteUrl = this.resolveUrl(rawUrl, pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // ========== 2. window.open ==========
    WINDOW_OPEN_PATTERN.lastIndex = 0;
    let woMatch;
    while ((woMatch = WINDOW_OPEN_PATTERN.exec(scriptText)) !== null) {
      const absoluteUrl = this.resolveUrl(woMatch[1], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // ========== 3. fetch / XHR / axios ==========
    for (const pattern of FETCH_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(scriptText)) !== null) {
        const absoluteUrl = this.resolveUrl(match[1], pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // ========== 4. download 属性 ==========
    DOWNLOAD_ATTR_PATTERN.lastIndex = 0;
    let dlMatch;
    while ((dlMatch = DOWNLOAD_ATTR_PATTERN.exec(scriptText)) !== null) {
      const downloadTarget = dlMatch[1];
      // download 属性值可能是文件名，但也要检查是否是 URL
      if (downloadTarget && downloadTarget.includes('/')) {
        const absoluteUrl = this.resolveUrl(downloadTarget, pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // ========== 5. new URL() ==========
    NEW_URL_PATTERN.lastIndex = 0;
    let nuMatch;
    while ((nuMatch = NEW_URL_PATTERN.exec(scriptText)) !== null) {
      const absoluteUrl = this.resolveUrl(nuMatch[1], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // ========== 6. 字符串中的归档/可执行 URL ==========
    STRING_URL_PATTERN.lastIndex = 0;
    let strMatch;
    while ((strMatch = STRING_URL_PATTERN.exec(scriptText)) !== null) {
      const absoluteUrl = this.resolveUrl(strMatch[1], pageUrl);
      if (absoluteUrl) foundUrls.add(absoluteUrl);
    }

    // ========== 7. 通用 URL 模式（从字符串字面量中提取） ==========
    // 提取脚本中所有字符串字面量里的 URL
    const stringLiterals = this._extractStringLiterals(scriptText);
    for (const literal of stringLiterals) {
      URL_PATTERN.lastIndex = 0;
      let uMatch;
      while ((uMatch = URL_PATTERN.exec(literal)) !== null) {
        const absoluteUrl = this.resolveUrl(uMatch[0], pageUrl);
        if (absoluteUrl) foundUrls.add(absoluteUrl);
      }
    }

    // 创建节点
    for (const url of foundUrls) {
      const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(url);
      const isCrossDomain = this.isCrossDomain(url, pageUrl);

      let nodeType;
      if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
      else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
      else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
      else if (isJson) nodeType = RESOURCE_TYPES.JSON;
      else nodeType = RESOURCE_TYPES.UNKNOWN;

      discovered.push({
        url,
        type: nodeType,
        sourceType: SOURCE_TYPES.INLINE_SCRIPT,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          isExternal: isCrossDomain,
          textSnippet: scriptText.substring(0, 200)
        }
      });
    }

    return discovered;
  }

  /**
   * 提取 JS 代码中的所有字符串字面量
   * @param {string} code
   * @returns {string[]}
   */
  _extractStringLiterals(code) {
    const literals = [];
    // 单引号字符串
    let match;
    const singlePattern = /'([^'\\]*(?:\\.[^'\\]*)*)'/g;
    while ((match = singlePattern.exec(code)) !== null) {
      if (match[1].length > 5) literals.push(match[1]);
    }
    // 双引号字符串
    const doublePattern = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
    while ((match = doublePattern.exec(code)) !== null) {
      if (match[1].length > 5) literals.push(match[1]);
    }
    // 模板字符串
    const templatePattern = /`([^`\\]*(?:\\.[^`\\]*)*)`/g;
    while ((match = templatePattern.exec(code)) !== null) {
      if (match[1].length > 5) literals.push(match[1]);
    }
    return literals;
  }
}
