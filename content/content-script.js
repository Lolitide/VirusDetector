/**
 * Virus Detector — Content Script (内容脚本)
 *
 * 注入到每个页面中，负责采集页面数据供评分引擎使用。
 * 在 document_idle 阶段运行，分两次采集（600ms + 3500ms）以捕获懒加载内容。
 *
 * @module content-script
 * @version 2.2.4
 *
 * 职责：
 *   1. 采集链接分析数据 (collectLinkMetrics) — 规则四数据源
 *      - 同页链接（完整 URL 精确匹配）
 *      - 死链检测（HEAD 请求验证，上限 5 个）
 *      - 重复链接追踪（>=4 个元素指向同一链接 → 规则 A-③）
 *      - 外链下载分析（下载按钮文本 + 文件扩展名）
 *   2. 采集页面度量 (collectPageMetrics) — 规则五数据源
 *      - DOM节点数、外部资源去重总数、框架标记（HTML全文+window全局变量双重检测）、文本长度
 *   3. 扫描 ICP 备案号 (findIcpStrings) — 规则三数据源
 *      - 6 层递进扫描：footer → ICP 元素 → 底部 30% 区域 → <a> 链接 → fixed 元素 → TreeWalker
 *   4. 响应来自 Service Worker 的 REQUEST_PAGE_TEXT 重采请求
 */

(function () {
  'use strict';

  // ==================== 规则四：链接分析数据采集 ====================

  /**
   * 异步采集链接分析指标
   * - 同页链接（完全一致URL）
   * - 死链（仅包括指向不存在子页面的链接）
   * - 重复链接（≥4个元素指向同一链接）
   * - 外链下载分析
   */
  async function collectLinkMetrics() {
    var currentUrl = window.location.href;
    var currentOrigin = window.location.origin;
    var currentHost = window.location.hostname;

    var links = document.querySelectorAll('a[href]');
    var samePageLinks = 0;
    var deadLinks = 0;
    var deadLinkSamples = [];
    var externalDownloadLinks = [];

    // 用于规则四A-③：跟踪链接被多少不同元素指向
    var linkElementMap = new Map();  // href (normalized) → Set of element signatures

    var DOWNLOAD_KW = ['下载','download','下載','立即下载','免费下载','高速下载',
      '安全下载','点击下载','直接下载','本地下载','官方下载','download now',
      'free download','立即安装','一键安装','安装包','setup','install','get started'];
    var FILE_EXTS = ['.exe','.msi','.dmg','.apk','.zip','.rar','.7z',
      '.tar','.gz','.tgz','.bz2','.xz','.iso','.cab','.arj','.bat','.cmd',
      '.ps1','.vbs','.scr','.jar','.bin','.run','.sh','.pkg'];
    var ARCHIVE_EXTS = ['.zip','.rar','.7z','.tar','.gz','.tgz','.bz2','.xz',
      '.iso','.cab','.arj','.lzh','.z','.zst'];

    // 收集待检测死链的候选项（同域名的不同路径链接）
    var deadLinkCandidates = [];

    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var href = (link.getAttribute('href') || '').trim();
      if (!href) continue;
      var lowerHref = href.toLowerCase();

      // 跳过 javascript: 和纯锚点链接（不计入任何检测）
      if (/^javascript\s*:/i.test(href) || /^#?$/.test(href) || /^#\d*$/.test(href)) {
        continue;
      }

      // ① 同页链接：仅当链接完整URL与当前页URL完全一致时计入
      try {
        var resolved = new URL(href, window.location.href);
        var resolvedHref = resolved.href;

        // 严格比对：完整URL完全一致
        if (resolvedHref === currentUrl) {
          samePageLinks++;
        } else if (resolved.hostname === currentHost) {
          // 同域名但不同路径 → 可能是死链候选
          deadLinkCandidates.push({ href: resolvedHref, text: (link.textContent || '').trim().substring(0, 50), element: link });
        }

        // 规则四A-③：跟踪有多少不同元素指向同一个链接
        var normalizedHref = resolvedHref.replace(/#.*$/, ''); // 去除hash后归一化
        if (!linkElementMap.has(normalizedHref)) {
          linkElementMap.set(normalizedHref, new Set());
        }
        // 使用元素标签+文本前30字符作为元素签名去重
        var elemSig = link.tagName + '|' + (link.textContent || '').trim().substring(0, 30);
        linkElementMap.get(normalizedHref).add(elemSig);
      } catch (e) {
        // 无法解析的URL忽略（不包括hash/javascript，已在上面过滤）
      }

      // 外链分析（同之前逻辑）
      try {
        var resolved2 = new URL(href, window.location.href);
        if (resolved2.hostname && resolved2.hostname !== currentHost) {
          var linkText = (link.textContent || '').toLowerCase();
          var parentText = (link.parentElement ? link.parentElement.textContent : '').toLowerCase();
          var ariaLabel = (link.getAttribute('aria-label') || '').toLowerCase();
          var className = (link.className || '').toLowerCase();
          var parentClass = (link.parentElement ? link.parentElement.className : '').toLowerCase();
          var combined = [linkText, parentText, ariaLabel, className, parentClass].join(' ');

          var hasDownloadText = DOWNLOAD_KW.some(function(kw) { return combined.includes(kw); });
          var isFileLink = FILE_EXTS.some(function(ext) { return lowerHref.endsWith(ext); });
          var isArchive = ARCHIVE_EXTS.some(function(ext) { return lowerHref.endsWith(ext); });

          if (hasDownloadText || isFileLink) {
            externalDownloadLinks.push({
              href: href.substring(0, 200),
              text: (link.textContent || '').trim().substring(0, 80),
              hasDownloadText: hasDownloadText, isFileLink: isFileLink, isArchive: isArchive
            });
          }
        }
      } catch (e) {}
    }

    // ② 死链检测：对同域名不同路径的链接进行HEAD请求验证（限5个）
    if (deadLinkCandidates.length > 0) {
      // 去重（按href）
      var uniqueCandidates = [];
      var seenHrefs = new Set();
      for (var c = 0; c < deadLinkCandidates.length; c++) {
        var chref = deadLinkCandidates[c].href;
        if (!seenHrefs.has(chref)) {
          seenHrefs.add(chref);
          uniqueCandidates.push(deadLinkCandidates[c]);
        }
      }
      // 最多检查5个候选
      var candidatesToCheck = uniqueCandidates.slice(0, 5);

      // 并行HEAD请求（原串行for循环改为Promise.allSettled，最坏耗时从15秒降至3秒）
      var deadCheckPromises = candidatesToCheck.map(function(candidate) {
        return fetchWithTimeout(candidate.href, { method: 'HEAD' }, 3000)
          .then(function(resp) { return { candidate: candidate, response: resp, error: null }; })
          .catch(function(err) { return { candidate: candidate, response: null, error: err }; });
      });
      var deadCheckResults = await Promise.allSettled(deadCheckPromises);

      for (var r = 0; r < deadCheckResults.length; r++) {
        var result = deadCheckResults[r].value;
        if (result.response && result.response.status >= 400) {
          deadLinks++;
          if (deadLinkSamples.length < 5) {
            deadLinkSamples.push({ href: result.candidate.href.substring(0, 100), text: result.candidate.text, status: result.response.status });
          }
        } else if (result.error) {
          deadLinks++;
          if (deadLinkSamples.length < 5) {
            deadLinkSamples.push({ href: result.candidate.href.substring(0, 100), text: result.candidate.text, error: 'network_error' });
          }
        }
      }
    }

    // ③ 重复链接检测：统计≥4个不同元素指向同一个链接
    var duplicateLinks = [];
    var DUPLICATE_THRESHOLD = 4;
    var DOWNLOAD_LINK_KW = ['down', 'download', '下載', '下载', 'dl', 'get', 'setup',
      'install', 'free', 'app', 'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z'];

    linkElementMap.forEach(function(elements, href) {
      if (elements.size >= DUPLICATE_THRESHOLD) {
        var lowerHrefForCheck = href.toLowerCase();
        var isDownloadLink = DOWNLOAD_LINK_KW.some(function(kw) {
          return lowerHrefForCheck.includes(kw);
        });
        duplicateLinks.push({
          href: href.substring(0, 200),
          elementCount: elements.size,
          isDownloadLink: isDownloadLink
        });
      }
    });

    // 去重外链
    var seen = new Set();
    var unique = externalDownloadLinks.filter(function(d) {
      if (seen.has(d.href)) return false; seen.add(d.href); return true;
    });

    return {
      totalLinks: links.length,
      samePageLinks: samePageLinks, deadLinks: deadLinks, deadLinkSamples: deadLinkSamples,
      externalDownloadLinks: unique,
      externalWithDownloadText: unique.filter(function(d) { return d.hasDownloadText; }).length,
      externalFileLinks: unique.filter(function(d) { return d.isFileLink; }).length,
      externalArchiveLinks: unique.filter(function(d) { return d.isArchive; }).length,
      // 规则四A-③
      duplicateLinks: duplicateLinks,
      hasDuplicateLinks: duplicateLinks.length > 0,
      hasDuplicateDownloadLink: duplicateLinks.some(function(d) { return d.isDownloadLink; })
    };
  }

  /**
   * 带超时的fetch封装
   */
  function fetchWithTimeout(url, options, timeoutMs) {
    return new Promise(function(resolve, reject) {
      var controller = new AbortController();
      var signal = controller.signal;
      var timeoutId = setTimeout(function() {
        controller.abort();
        reject(new Error('timeout'));
      }, timeoutMs);

      fetch(url, Object.assign({}, options, { signal: signal }))
        .then(function(response) {
          clearTimeout(timeoutId);
          resolve(response);
        })
        .catch(function(err) {
          clearTimeout(timeoutId);
          reject(err);
        });
    });
  }

  // ==================== 规则五：页面度量采集 ====================

  function collectPageMetrics() {
    const html = document.documentElement.outerHTML || '';
    const htmlLines = html.split('\n').length;

    // DOM复杂度：节点总数（替代HTML行数作为结构复杂度指标，不受代码压缩/格式化影响）
    const domNodeCount = document.getElementsByTagName('*').length;

    // 外部资源总计数（云上/服务器资源：含外部脚本、外部样式、图片、字体、媒体等）
    const currentHost = window.location.hostname;
    function isExternal(url) {
      if (!url) return false;
      try {
        var u = new URL(url, window.location.href);
        return u.hostname && u.hostname !== currentHost;
      } catch (e) { return false; }
    }

    // 统计各类外部资源（合并查询，避免重复 querySelectorAll）
    var extRes = {
      scripts: [],
      styles: [],
      images: [],
      media: [],
      fonts: []
    };

    // 外部脚本：带 src 属性的 <script>（不含内联脚本）
    extRes.scripts = Array.from(document.querySelectorAll('script[src]'))
      .map(function(s) { return s.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部样式：<link rel="stylesheet">
    extRes.styles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
      .map(function(l) { return l.getAttribute('href') || ''; })
      .filter(isExternal);

    // 外部图片
    extRes.images = Array.from(document.querySelectorAll('img[src]'))
      .map(function(i) { return i.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部媒体：视频、音频、iframe 等
    extRes.media = Array.from(document.querySelectorAll('video[src], audio[src], source[src], iframe[src]'))
      .map(function(el) { return el.getAttribute('src') || ''; })
      .filter(isExternal);

    // 外部字体
    extRes.fonts = Array.from(document.querySelectorAll('link[rel*="font"], link[as="font"]'))
      .map(function(l) { return l.getAttribute('href') || ''; })
      .filter(isExternal);

    // 外部资源去重总数（同URL只计一次）
    var allExternal = new Set();
    Object.values(extRes).forEach(function(urls) {
      urls.forEach(function(u) { allExternal.add(u); });
    });

    var totalExternalResources = allExternal.size;
    var hasExternalResources = totalExternalResources > 0;

    // 框架标记检测（增强版：HTML全文扫描 + window全局变量双重检测）
    // 注：此列表需与 utils/constants.js 中 FRAMEWORK_HTML_MARKERS 保持同步
    const FRAMEWORK_HTML_MARKERS = [
      'react', 'vue', 'angular', 'webpack', '__initial_state__',
      '_next/', 'nuxt', 'svelte', 'jquery', 'bootstrap',
      'node_modules', '.jsx', '.tsx', 'data-v-', 'ng-version',
      '__vue__', '__react', 'redux', 'react-dom', 'vue-router',
      'webpackjsonp', '__webpack_require__', '__nuxt', '__next'
    ];

    // A. HTML 源码全文扫描（不再限制5000字符，搜索范围覆盖整个HTML文档）
    const htmlLower = html.toLowerCase();
    var htmlFrameworkHits = [];
    for (var i = 0; i < FRAMEWORK_HTML_MARKERS.length; i++) {
      if (htmlLower.indexOf(FRAMEWORK_HTML_MARKERS[i]) !== -1) {
        htmlFrameworkHits.push(FRAMEWORK_HTML_MARKERS[i]);
      }
    }

    // B. window 全局变量检测（捕获外部JS加载的框架，即使HTML源码中无痕迹）
    var globalFrameworkHits = [];
    try {
      if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) globalFrameworkHits.push('react');
      if (window.Vue || window.__VUE__) globalFrameworkHits.push('vue');
      if (window.angular || document.querySelector('[ng-version]')) globalFrameworkHits.push('angular');
      if (window.jQuery) globalFrameworkHits.push('jquery');
      if (window.__NEXT_DATA__) globalFrameworkHits.push('next');
      if (window.__NUXT__) globalFrameworkHits.push('nuxt');
      if (window.__webpack_require__ || window.webpackJsonp) globalFrameworkHits.push('webpack');
      if (window.__svelte || window.__svelte__) globalFrameworkHits.push('svelte');
      if (window.bootstrap || (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal)) globalFrameworkHits.push('bootstrap');
      // Vue 的 DOM 痕迹（Vue 会在元素上添加 data-v-xxxxxxxx 属性）
      if (document.querySelector('[data-v-]')) globalFrameworkHits.push('vue');
    } catch (e) { /* 跨域iframe或安全策略可能抛出异常 */ }

    // 合并并去重
    var allFrameworkHits = [];
    var frameworkSeen = new Set();
    htmlFrameworkHits.concat(globalFrameworkHits).forEach(function(hit) {
      if (!frameworkSeen.has(hit)) {
        frameworkSeen.add(hit);
        allFrameworkHits.push(hit);
      }
    });
    var hasFrameworkMarkers = allFrameworkHits.length > 0;

    // 页面文本长度
    const bodyText = (document.body ? document.body.innerText : '') || '';
    const textLength = bodyText.length;

    // Meta generator（AI生成页面的典型特征，保留供未来分析）
    const metaGenerator = document.querySelector('meta[name="generator"]');
    const generator = metaGenerator ? metaGenerator.getAttribute('content') : null;

    // 内联样式数量
    const inlineStyles = document.querySelectorAll('[style]').length;

    // <head>中的<link>数量
    const headLinks = document.querySelectorAll('head link').length;

    // 带src的脚本总数（含同源+外部，保留供参考）
    const totalScriptsWithSrc = document.querySelectorAll('script[src]').length;

    return {
      htmlLines,
      domNodeCount,
      totalScriptsWithSrc,
      hasFrameworkMarkers,
      frameworkHits: allFrameworkHits,
      textLength,
      generator,
      inlineStyles,
      headLinks,
      url: window.location.href,
      hasExternalResources: hasExternalResources,
      totalExternalResources: totalExternalResources,
      externalBreakdown: {
        scripts: extRes.scripts.length,
        styles: extRes.styles.length,
        images: extRes.images.length,
        media: extRes.media.length,
        fonts: extRes.fonts.length
      }
    };
  }

  // ==================== ICP备案号扫描 ====================

  function findIcpStrings() {
    const icpStrings = [];
    const seen = new Set();

    function add(text) {
      const t = text.trim();
      if (t.length > 3 && t.length < 500 && !seen.has(t) &&
          /ICP|icp|备案|beian|BeiAn|BEIAN|公安|公网安备|经营许可证|B2-|增值电信/.test(t)) {
        icpStrings.push(t); seen.add(t);
      }
    }

    // 1. footer元素（包括任何class/id含footer的元素）
    document.querySelectorAll(
      'footer, .footer, #footer, [class*="footer"], [id*="footer"], ' +
      '[class*="foot"], [id*="foot"], ' +
      'div:last-of-type, section:last-of-type'
    ).forEach(el => add(el.textContent || ''));

    // 2. icp/beian/copyright/record 命名的元素
    const sel = '[id*="icp"],[class*="icp"],[id*="beian"],[class*="beian"],' +
                '[id*="备案"],[class*="备案"],[id*="copyright"],[class*="copyright"],' +
                '[id*="record"],[class*="record"],[id*="公安"],[class*="公安"],' +
                '.record,#record,.icp-info,#icp-info,.beian-info,#beian-info,' +
                '[id*="license"],[class*="license"],[id*="police"],[class*="police"],' +
                '[id*="icpNo"],[class*="icpNo"],[id*="beianNo"],[class*="beianNo"]';
    try {
      document.querySelectorAll(sel).forEach(el => add(el.textContent || ''));
    } catch (e) { /* selector error */ }

    // 3. 页面底部区域元素（body 最后 30% 的直接子元素及其内部文本）
    if (document.body) {
      const children = [...document.body.children];
      const startIdx = Math.max(0, Math.floor(children.length * 0.7));
      for (let i = startIdx; i < children.length; i++) {
        const t = (children[i].textContent || '').trim();
        if (t.length > 5 && t.length < 1000) add(t);
        // 同时检查该元素内的所有<a>链接文本
        const links = children[i].querySelectorAll('a');
        for (const link of links) {
          const linkText = (link.textContent || '').trim();
          if (linkText.length > 2 && linkText.length < 200) add(linkText);
        }
      }
    }

    // 4. 检查所有页面<a>元素（很多ICP备案号嵌在链接中）
    document.querySelectorAll('a').forEach(el => {
      const href = (el.getAttribute('href') || '').toLowerCase();
      const text = (el.textContent || '').trim();
      if (text.length > 3 && text.length < 300 &&
          /ICP|备案|beian|公安/.test(text + href)) {
        add(text);
      }
      if (href.includes('beian') || href.includes('icp') || href.includes('miit')) {
        add(text || href);
      }

      // 专项：beian.gov.cn / beian.miit.gov.cn 等政府备案查询链接
      // 链接文本通常为完整备案号，如 "粤ICP备2024178421号"
      if (/(beian\.gov\.cn|beian\.miit\.gov\.cn|miitbeian\.gov\.cn)/i.test(href)) {
        // 优先取链接文本，其次取父元素文本，再取相邻文本
        var linkText = (el.textContent || '').trim();
        if (linkText.length > 5 && /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]/.test(linkText)) {
          add(linkText);
        }
        // 同时检查父元素中的完整备案信息
        var parentEl = el.parentElement;
        if (parentEl) {
          var parentText = (parentEl.textContent || '').trim();
          if (parentText.length > 5 && parentText.length < 500 &&
              /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]/.test(parentText)) {
            add(parentText);
          }
        }
      }
    });

    // 5. 检查 position:fixed bottom:0 的元素（底部固定栏）
    // 优化：原 querySelectorAll('*') 扫描全部元素+getComputedStyle会触发布局重算。
    // 改为只扫描 body 最后 500 个元素（ICP备案的固定栏都在页面底部）。
    try {
      const bodyChildren = document.body ? [...document.body.children] : [];
      const startScan = Math.max(0, bodyChildren.length - 500); // 最多扫描底部500个
      for (let si = startScan; si < bodyChildren.length; si++) {
        // 先快速检查子元素数量，子元素多的容器更可能含底部固定栏
        const container = bodyChildren[si];
        if (container.children.length === 0 && !container.classList.length && !container.id) continue;
        const style = window.getComputedStyle(container);
        if (style.position === 'fixed' &&
            (style.bottom === '0px' || parseInt(style.bottom) < 50)) {
          const t = (container.textContent || '').trim();
          if (t.length > 5 && t.length < 500) add(t);
        }
        // 同时检查容器内的直接子元素
        for (const child of container.children) {
          const childStyle = window.getComputedStyle(child);
          if (childStyle.position === 'fixed' &&
              (childStyle.bottom === '0px' || parseInt(childStyle.bottom) < 50)) {
            const t = (child.textContent || '').trim();
            if (t.length > 5 && t.length < 500) add(t);
          }
        }
      }
    } catch (e) { /* ignore */ }

    // 6. TreeWalker 扫描全页面所有文本节点
    let count = 0;
    const MAX_NODES = 50000; // 足够覆盖大型页面
    try {
      const walker = document.createTreeWalker(
        document.body || document.documentElement, NodeFilter.SHOW_TEXT,
        { acceptNode: () => (count++ < MAX_NODES) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT }
      );
      let node;
      while ((node = walker.nextNode())) {
        const t = node.textContent.trim();
        if (t.length > 5 && t.length < 300 &&
            (t.includes('ICP') || t.includes('icp') || t.includes('备案') ||
             t.includes('beian') || t.includes('公安') || t.includes('B2-') ||
             t.includes('经营许可证') || t.includes('增值电信'))) {
          add(t);
        }
      }
    } catch (e) { /* ignore */ }

    return icpStrings;
  }

  /**
   * 检测页面是否存在可点击的工信部备案查询链接
   * 检查 <a> 标签 href 是否指向 beian.miit.gov.cn 等政府备案域名
   * @returns {boolean}
   */
  function checkIcpGovLink() {
    try {
      var links = document.querySelectorAll('a[href*="beian.miit.gov.cn"], a[href*="beian.gov.cn"], a[href*="miitbeian.gov.cn"]');
      return links.length > 0;
    } catch (e) {
      return false;
    }
  }

  // ==================== 发送分析结果 ====================

  function safeCollect(fn, fallback) {
    try { return fn(); } catch (e) { console.error('[VirusDetector] 采集失败:', e); return fallback; }
  }

  // 首次扫描结果缓存，用于二次扫描去重
  var _firstScanData = null;

  async function sendAnalysisResult() {
    // 每个采集函数独立 try-catch，一个失败不影响其他
    var pageMetrics = safeCollect(collectPageMetrics, null);
    var icpStrings = safeCollect(findIcpStrings, []);
    // 链接分析含异步HEAD请求检测死链，需await
    var linkMetrics = null;
    try {
      linkMetrics = await collectLinkMetrics();
    } catch (e) {
      console.error('[VirusDetector] 链接分析采集失败:', e);
    }

    var hasIcpGovLink = checkIcpGovLink();
    var payload = {
      url: window.location.href, domain: window.location.hostname, title: document.title,
      pageText: safeCollect(function() { return (document.body ? document.body.innerText : '').substring(0, 15000); }, ''),
      icpStrings: icpStrings, pageMetrics: pageMetrics, linkMetrics: linkMetrics,
      hasIcpGovLink: hasIcpGovLink
    };

    // 二次扫描去重：与首次结果比对，无新增数据则跳过发送
    if (_firstScanData) {
      var firstIcpCount = (_firstScanData.icpStrings || []).length;
      var firstLinkCount = _firstScanData.linkMetrics ? _firstScanData.linkMetrics.totalLinks : 0;
      var newIcpCount = (icpStrings || []).length;
      var newLinkCount = linkMetrics ? linkMetrics.totalLinks : 0;
      var firstExternalCount = _firstScanData.linkMetrics ? _firstScanData.linkMetrics.externalDownloadLinks.length : 0;
      var newExternalCount = linkMetrics ? linkMetrics.externalDownloadLinks.length : 0;

      // ICP 备案号无新增 且 链接/外链数量无增长 → 跳过二次发送
      if (newIcpCount <= firstIcpCount && newLinkCount <= firstLinkCount && newExternalCount <= firstExternalCount) {
        console.log('[VirusDetector] 二次扫描无新增数据，跳过重复发送');
        return;
      }
      console.log('[VirusDetector] 二次扫描检测到新数据 (ICP:' + firstIcpCount + '→' + newIcpCount +
        ', 链接:' + firstLinkCount + '→' + newLinkCount + ', 外链:' + firstExternalCount + '→' + newExternalCount + ')');
    } else {
      _firstScanData = { icpStrings: icpStrings, linkMetrics: linkMetrics };
    }

    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS_RESULT',
      payload: payload,
      timestamp: Date.now()
    }).catch(function() {});
  }

  // ==================== 消息监听 ====================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'REQUEST_PAGE_TEXT') {
      (async () => {
        try {
          var linkMetrics = null;
          try {
            linkMetrics = await collectLinkMetrics();
          } catch (e) {
            console.error('[VirusDetector] 链接分析采集失败:', e);
          }
          sendResponse({
            success: true,
            pageMetrics: safeCollect(collectPageMetrics, null),
            linkMetrics: linkMetrics,
            icpStrings: safeCollect(findIcpStrings, []),
            hasIcpGovLink: checkIcpGovLink(),
            pageText: (document.body ? document.body.innerText : '').substring(0, 15000),
            title: document.title,
            url: window.location.href
          });
        } catch (e) {
          sendResponse({ success: false, error: e.message });
        }
      })();
      return true;
    }
    return false;
  });

  // ==================== 初始化 ====================

  function init() {
    setTimeout(sendAnalysisResult, 600);
    // 二次扫描（懒加载页脚）
    setTimeout(sendAnalysisResult, 3500);
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    init();
  } else {
    window.addEventListener('load', () => setTimeout(sendAnalysisResult, 600));
  }

})();
