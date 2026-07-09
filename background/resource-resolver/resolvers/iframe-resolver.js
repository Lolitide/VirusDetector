/**
 * Virus Detector — iframe 解析器
 *
 * 解析 iframe src URL，标记为需要进一步解析的独立页面。
 * iframe 内的页面可能有自己的资源树，但出于性能考虑仅记录 src URL。
 *
 * @module resource-resolver/resolvers/iframe-resolver
 */

import { BaseResolver } from './base-resolver.js';
import { RESOURCE_TYPES, SOURCE_TYPES } from '../config.js';

export class IframeResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.IFRAME;
  }

  async resolve(node, context) {
    const discovered = [];

    // iframe src 通常是一个完整页面，但我们只标记 URL
    // 不进一步获取 iframe 内容（成本和复杂度过高）
    const iframeUrl = node.url;
    const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(iframeUrl);
    const isCrossDomain = this.isCrossDomain(iframeUrl, context.pageUrl);

    // 虽然 iframe 本身是 HTML 页面，但如果 src 指向归档文件则标记
    if (!isArchive && !isExecutable && !isTxt && !isJson) {
      // 普通 iframe → 标记但不递归（避免加载整个子页面）
      node.metadata._iframeResolved = true;
      return discovered;
    }

    // 如果不寻常的 iframe src（如指向 .zip），记录为归档
    let nodeType;
    if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
    else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
    else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
    else nodeType = RESOURCE_TYPES.IFRAME;

    discovered.push({
      url: iframeUrl,
      type: nodeType,
      sourceType: SOURCE_TYPES.IFRAME_SRC,
      depth: node.depth + 1,
      metadata: {
        ext,
        isCrossDomain,
        isExternal: isCrossDomain
      }
    });

    return discovered;
  }
}
