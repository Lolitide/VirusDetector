/**
 * Virus Detector — Meta Refresh 解析器
 *
 * 解析 <meta http-equiv="refresh" content="..."> 中的跳转 URL。
 * 支持 content="5;url=..." 和 content="0;URL=..." 格式。
 *
 * @module resource-resolver/resolvers/meta-resolver
 */

import { BaseResolver } from './base-resolver.js';
import { RESOURCE_TYPES, SOURCE_TYPES } from '../config.js';

export class MetaRefreshResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.META_REFRESH;
  }

  async resolve(node, context) {
    const discovered = [];
    const metaUrls = node.metadata.metaUrls || [];

    for (const meta of metaUrls) {
      const rawUrl = meta.url || '';
      if (!rawUrl) continue;

      const absoluteUrl = this.resolveUrl(rawUrl, node.parentUrl || context.pageUrl);
      if (!absoluteUrl) continue;

      const isCrossDomain = this.isCrossDomain(absoluteUrl, context.pageUrl);
      const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(absoluteUrl);

      let nodeType;
      if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
      else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
      else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
      else if (isJson) nodeType = RESOURCE_TYPES.JSON;
      else nodeType = RESOURCE_TYPES.UNKNOWN;

      discovered.push({
        url: absoluteUrl,
        type: nodeType,
        sourceType: SOURCE_TYPES.META_REFRESH,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          delay: meta.delay || 0,
          originalContent: meta.originalContent || ''
        }
      });
    }

    return discovered;
  }
}
