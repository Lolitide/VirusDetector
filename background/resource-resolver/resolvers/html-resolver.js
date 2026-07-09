/**
 * Virus Detector — HTML 解析器
 *
 * 从 Content Script 发送的 HTML URL 列表中构建资源节点。
 * Content Script 已经完成了 DOM 查询，此处仅做规范化、分类和节点创建。
 *
 * 扫描的标签：a[href], link[href], script[src], img[src], iframe[src],
 *              form[action], source[src], video[src], audio[src],
 *              object[data], embed[src]
 *
 * @module resource-resolver/resolvers/html-resolver
 */

import { BaseResolver } from './base-resolver.js';
import { RESOURCE_TYPES, SOURCE_TYPES } from '../config.js';

export class HtmlResolver extends BaseResolver {
  canHandle(node) {
    return node.type === RESOURCE_TYPES.HTML || node.type === 'page_root';
  }

  async resolve(node, context) {
    const discovered = [];
    const htmlUrls = node.metadata.htmlUrls || [];
    const pageUrl = node.url;

    if (!htmlUrls || htmlUrls.length === 0) {
      return discovered;
    }

    for (const item of htmlUrls) {
      // 支持 { rawUrl, tagName, attrName } 格式
      const rawUrl = typeof item === 'string' ? item : item.rawUrl || item.url || '';
      const tagName = item.tagName || '';
      const attrName = item.attrName || '';

      // 规范化 URL（相对路径 → 绝对路径）
      const absoluteUrl = this.resolveUrl(rawUrl, pageUrl);
      if (!absoluteUrl) continue;

      // 跳过页面本身
      if (this._isSamePageUrl(absoluteUrl, pageUrl)) continue;

      // 分类
      const { ext, isArchive, isExecutable, isTxt, isJson } = this.classifyUrl(absoluteUrl);
      const sourceType = this._determineSourceType(tagName, attrName);
      const isCrossDomain = this.isCrossDomain(absoluteUrl, pageUrl);

      // 确定节点类型
      let nodeType;
      if (isArchive) {
        nodeType = RESOURCE_TYPES.ARCHIVE;
      } else if (isExecutable) {
        nodeType = RESOURCE_TYPES.EXECUTABLE;
      } else if (isTxt) {
        nodeType = RESOURCE_TYPES.TXT;
      } else if (isJson) {
        nodeType = RESOURCE_TYPES.JSON;
      } else if (tagName === 'iframe' || attrName === 'src' && tagName === 'iframe') {
        nodeType = RESOURCE_TYPES.IFRAME;
      } else if (tagName === 'script' && attrName === 'src') {
        nodeType = RESOURCE_TYPES.SCRIPT_EXTERNAL;
      } else {
        nodeType = RESOURCE_TYPES.UNKNOWN;
      }

      discovered.push({
        url: absoluteUrl,
        type: nodeType,
        sourceType,
        depth: node.depth + 1,
        metadata: {
          ext,
          isCrossDomain,
          isExternal: isCrossDomain,
          tagName,
          attrName
        }
      });
    }

    return discovered;
  }

  /**
   * 判断是否与页面 URL 相同（忽略 hash 差异）
   */
  _isSamePageUrl(url, pageUrl) {
    try {
      const u1 = new URL(url);
      const u2 = new URL(pageUrl);
      u1.hash = '';
      u2.hash = '';
      return u1.href === u2.href;
    } catch (e) {
      return url.replace(/#.*$/, '') === pageUrl.replace(/#.*$/, '');
    }
  }

  /**
   * 根据 HTML 标签和属性确定 sourceType
   */
  _determineSourceType(tagName, attrName) {
    const tag = (tagName || '').toLowerCase();
    const attr = (attrName || '').toLowerCase();

    if (tag === 'a' && attr === 'href') return SOURCE_TYPES.A_HREF;
    if (tag === 'link' && attr === 'href') return SOURCE_TYPES.LINK_HREF;
    if (tag === 'script' && attr === 'src') return SOURCE_TYPES.SCRIPT_SRC;
    if (tag === 'img' && attr === 'src') return SOURCE_TYPES.IMG_SRC;
    if (tag === 'iframe' && attr === 'src') return SOURCE_TYPES.IFRAME_SRC;
    if (tag === 'form' && attr === 'action') return SOURCE_TYPES.FORM_ACTION;

    // 通用映射
    if (attr === 'src') return tag + '_src';
    if (attr === 'href') return tag + '_href';
    if (attr === 'data') return tag + '_data';

    return SOURCE_TYPES.A_HREF; // 默认
  }
}
