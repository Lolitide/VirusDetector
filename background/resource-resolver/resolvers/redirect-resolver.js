/**
 * Virus Detector — HTTP 重定向解析器
 *
 * 发送 HEAD 请求跟随 HTTP 301/302/307/308 重定向，记录最终 URL。
 * 不下载内容体，仅跟踪 Location 头。
 *
 * @module resource-resolver/resolvers/redirect-resolver
 */

import { BaseResolver } from './base-resolver.js';
import { RESOURCE_TYPES, SOURCE_TYPES } from '../config.js';

export class RedirectResolver extends BaseResolver {
  canHandle(node) {
    // 处理 type 为 redirect_* 的节点
    return node.type && node.type.startsWith('redirect_');
  }

  async resolve(node, context) {
    const discovered = [];

    // 检查深度
    if (node.depth >= context.config.maxDepth) {
      return discovered;
    }

    const maxRedirects = 5;
    let currentUrl = node.url;
    const visitedInChain = new Set();

    for (let i = 0; i < maxRedirects; i++) {
      if (visitedInChain.has(currentUrl)) {
        // 重定向循环
        break;
      }
      visitedInChain.add(currentUrl);

      try {
        const response = await context.fetchFn(currentUrl, {
          method: 'HEAD',
          followRedirects: false
        });

        const status = response.status || 0;
        if (status >= 300 && status < 400 && response.headers) {
          const location = this._getLocationHeader(response);
          if (location) {
            const nextUrl = this.resolveUrl(location, currentUrl);
            if (nextUrl && nextUrl !== currentUrl) {
              // 记录重定向
              context.graph.addRedirect(currentUrl, nextUrl, status);

              const isCrossDomain = this.isCrossDomain(nextUrl, context.pageUrl);
              const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(nextUrl);

              currentUrl = nextUrl;

              // 如果是最后一个重定向或到达了实际资源
              if (i === maxRedirects - 1 || isArchive || isExecutable || isTxt || isJson) {
                let nodeType;
                if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
                else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
                else if (isTxt) nodeType = RESOURCE_TYPES.TXT;
                else if (isJson) nodeType = RESOURCE_TYPES.JSON;
                else nodeType = `redirect_${status}`;

                discovered.push({
                  url: nextUrl,
                  type: nodeType,
                  sourceType: SOURCE_TYPES.REDIRECT,
                  depth: node.depth + 1,
                  metadata: {
                    ext,
                    isCrossDomain,
                    statusCode: status,
                    redirectCount: i + 1
                  }
                });
              }
              continue;
            }
          }
        }

        // 非重定向响应 → 记录最终 URL
        if (currentUrl !== node.url) {
          const { ext, isArchive, isExecutable, isTxt } = this.classifyUrl(currentUrl);

          let nodeType = RESOURCE_TYPES.UNKNOWN;
          if (isArchive) nodeType = RESOURCE_TYPES.ARCHIVE;
          else if (isExecutable) nodeType = RESOURCE_TYPES.EXECUTABLE;
          else if (isTxt) nodeType = RESOURCE_TYPES.TXT;

          discovered.push({
            url: currentUrl,
            type: nodeType,
            sourceType: SOURCE_TYPES.REDIRECT,
            depth: node.depth + 1,
            metadata: {
              ext,
              isCrossDomain: this.isCrossDomain(currentUrl, context.pageUrl),
              redirectCount: i
            }
          });
        }
        break;

      } catch (e) {
        // 网络错误 → 停止跟随
        console.debug('[RedirectResolver] HEAD 请求失败:', currentUrl, e.message);
        break;
      }
    }

    return discovered;
  }

  /**
   * 从响应头中提取 Location 值
   */
  _getLocationHeader(response) {
    if (!response.headers) return null;
    // 可能是 Headers 对象或普通对象
    if (typeof response.headers.get === 'function') {
      return response.headers.get('location') || response.headers.get('Location');
    }
    return response.headers['location'] || response.headers['Location'] || null;
  }
}
