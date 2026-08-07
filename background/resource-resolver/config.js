/**
 * Virus Detector — Resource Resolver 配置常量
 *
 * 数值类限制参数与 utils/constants.js 单一真源（RESOLVER_* 常量），
 * 本文件以别名形式 re-export 保持解析器层导入名不变；
 * 解析器注册表、URL 提取正则、资源类型枚举等 resolver 专属配置保留在本文件。
 *
 * ⚠️ 共享正则注意：本文件导出的 LOCATION_PATTERNS / FETCH_PATTERNS / URL_PATTERN 等
 * 均带 g 标志（正则对象有 lastIndex 状态），调用方必须在 exec 循环前重置
 * `pattern.lastIndex = 0`，否则会跳跃匹配（现有调用方均已合规，勿回退）。
 *
 * @module resource-resolver/config
 */

import {
  RESOLVER_MAX_DEPTH, RESOLVER_MAX_TOTAL_RESOURCES, RESOLVER_MAX_TXT_SIZE,
  RESOLVER_MAX_JSON_SIZE, RESOLVER_MAX_INLINE_SCRIPT_LENGTH, RESOLVER_MAX_PAGE_TEXT_LENGTH,
  RESOLVER_PER_RESOURCE_TIMEOUT, RESOLVER_TOTAL_TIMEOUT,
  RESOLVER_FETCH_INTERMEDIATE_PAGES_DEFAULT, RESOLVER_MAX_INTERMEDIATE_PAGES,
  RESOLVER_MAX_INTERMEDIATE_PAGE_SIZE, RESOLVER_INTERMEDIATE_PAGE_TIMEOUT,
  RESOLVER_TEXT_EXTENSIONS, RESOLVER_JSON_EXTENSIONS,
  ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS, INTERMEDIATE_PAGE_KEYWORDS,
  MAX_REDIRECTS, MIN_SCRIPT_LENGTH, SNIPPET_PADDING,
  JSON_MAX_DEPTH, JSON_MAX_KEYS, JSON_MIN_URL_LENGTH,
  buildArchiveUrlPattern
} from '../../utils/constants.js';

// ==================== 递归控制（别名，值来自 constants.js） ====================

/** 最大递归深度（页面本身 depth=0，最多向下 3 层） */
export const MAX_DEPTH = RESOLVER_MAX_DEPTH;

/** 整个解析过程最多处理的资源数（含页面本身） */
export const MAX_TOTAL_RESOURCES = RESOLVER_MAX_TOTAL_RESOURCES;

// ==================== 大小限制（别名，值来自 constants.js） ====================

/** TXT 文件最大下载大小（字节），超过立即停止解析 */
export const MAX_TXT_SIZE = RESOLVER_MAX_TXT_SIZE; // 256KB

/** JSON 文件最大下载大小（字节） */
export const MAX_JSON_SIZE = RESOLVER_MAX_JSON_SIZE; // 128KB

/** Inline Script 单个最大分析长度（字符），超过截断 */
export const MAX_INLINE_SCRIPT_LENGTH = RESOLVER_MAX_INLINE_SCRIPT_LENGTH; // 32KB

/** 页面文本最大采集长度（字符），用于 URL 正则提取 */
export const MAX_PAGE_TEXT_LENGTH = RESOLVER_MAX_PAGE_TEXT_LENGTH; // 64KB

// ==================== 超时控制（别名，值来自 constants.js） ====================

/** 单个资源 fetch 超时（毫秒） */
export const PER_RESOURCE_TIMEOUT = RESOLVER_PER_RESOURCE_TIMEOUT;

/** 整个 Resolver 总超时（毫秒），超时后立即返回已构建的 Graph */
export const TOTAL_TIMEOUT = RESOLVER_TOTAL_TIMEOUT;

// ==================== 中间页抓取配置（别名，值来自 constants.js） ====================

/** 是否启用中间 HTML 下载页抓取（默认关闭，可通过设置开启） */
export const FETCH_INTERMEDIATE_PAGES = RESOLVER_FETCH_INTERMEDIATE_PAGES_DEFAULT;

/** 最大抓取的中间页数量 */
export const MAX_INTERMEDIATE_PAGES = RESOLVER_MAX_INTERMEDIATE_PAGES;

/** 中间页 HTML 最大下载大小（字节） */
export const MAX_INTERMEDIATE_PAGE_SIZE = RESOLVER_MAX_INTERMEDIATE_PAGE_SIZE; // 128KB

/** 中间页抓取超时（毫秒） */
export const INTERMEDIATE_PAGE_TIMEOUT = RESOLVER_INTERMEDIATE_PAGE_TIMEOUT;

/** 下载中间页关键词（= constants.js INTERMEDIATE_PAGE_KEYWORDS 并集） */
export { INTERMEDIATE_PAGE_KEYWORDS };

// ==================== 解析器开关 ====================

/** 第一阶段启用的解析器（按优先级排序） */
export const ENABLED_RESOLVERS = [
  'HtmlResolver',
  'ScriptResolver',
  'MetaRefreshResolver',
  'TxtResolver',
  'RedirectResolver',
  'JsonResolver',
  'IframeResolver'
];

/** 第二阶段预留（默认关闭）的解析器 */
export const DISABLED_RESOLVERS = [
  'ExternalScriptResolver'
];

// ==================== 文件类型定义（并集，值来自 constants.js） ====================

/**
 * 压缩包 / 镜像文件扩展名（= constants.js ARCHIVE_EXTENSIONS 并集，含 .img/.dmg）
 * 这些文件被 Rule2 重点检测。
 */
export { ARCHIVE_EXTENSIONS };

/**
 * 可执行程序扩展名（受 detectNonArchiveFiles 开关控制）
 */
export { EXECUTABLE_EXTENSIONS };

/**
 * 文本类资源扩展名（会 fetch 内容进行解析）
 */
export const TEXT_EXTENSIONS = RESOLVER_TEXT_EXTENSIONS;

/**
 * JSON 资源扩展名
 */
export const JSON_EXTENSIONS = RESOLVER_JSON_EXTENSIONS;

// ==================== URL 提取正则 ====================

/** 通用 URL 提取正则（从文本中提取 http/https URL）。g 标志，调用方需重置 lastIndex */
export const URL_PATTERN = /https?:\/\/[^\s<>"'`{}[\]|\\^`一-鿿]+/gi;

/** 归档/可执行文件 URL 提取正则（由 constants.js buildArchiveUrlPattern 生成，后缀边界锚定） */
export const ARCHIVE_URL_PATTERN = buildArchiveUrlPattern([...ARCHIVE_EXTENSIONS, ...EXECUTABLE_EXTENSIONS]);

// ==================== Inline Script 分析正则 ====================
// ⚠️ 以下正则均带 g 标志（共享可变 lastIndex），exec 循环前必须重置 lastIndex = 0

/** location 赋值模式 */
export const LOCATION_PATTERNS = [
  /window\.location\s*=\s*["'`]([^"'`]+)["'`]/gi,
  /location\.href\s*=\s*["'`]([^"'`]+)["'`]/gi,
  /location\.assign\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,
  /location\.replace\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/gi,
  /window\.location\.href\s*=\s*["'`]([^"'`]+)["'`]/gi,
  /self\.location\s*=\s*["'`]([^"'`]+)["'`]/gi,
  /top\.location\s*=\s*["'`]([^"'`]+)["'`]/gi,
  /parent\.location\s*=\s*["'`]([^"'`]+)["'`]/gi
];

/** window.open 模式 */
export const WINDOW_OPEN_PATTERN = /window\.open\s*\(\s*["'`]([^"'`]+)["'`]/gi;

/** fetch / XHR 模式 */
export const FETCH_PATTERNS = [
  /fetch\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  /axios\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  /axios\.get\s*\(\s*["'`]([^"'`]+)["'`]/gi,
  /axios\.post\s*\(\s*["'`]([^"'`]+)["'`]/gi
];

/** download 属性 */
export const DOWNLOAD_ATTR_PATTERN = /download\s*=\s*["'`]([^"'`]*)["'`]/gi;

/** new URL() 构造 */
export const NEW_URL_PATTERN = /new\s+URL\s*\(\s*["'`]([^"'`]+)["'`]/gi;

/**
 * 字符串字面量中的 URL（含关键扩展名）。
 * 扩展名由 constants.js ARCHIVE_EXTENSIONS ∪ EXECUTABLE_EXTENSIONS 并集生成（36 项），
 * 后缀边界靠字符串字面量引号收尾锚定。
 */
export const STRING_URL_PATTERN = (() => {
  // 扩展名前置反斜杠转义（'\\' 标准转义）；正则源码中 / 无需转义
  const exts = [...ARCHIVE_EXTENSIONS, ...EXECUTABLE_EXTENSIONS]
    .map((e) => '\\' + e)
    .join('|');
  return new RegExp(`["'\`](https?://[^"'\`]*(${exts})[^"'\`]*)["'\`]`, 'gi');
})();

// ==================== 资源类型枚举 ====================

export const RESOURCE_TYPES = {
  HTML: 'html',
  TXT: 'txt',
  SCRIPT_INLINE: 'script_inline',
  SCRIPT_EXTERNAL: 'script_external',
  META_REFRESH: 'meta_refresh',
  REDIRECT_301: 'redirect_301',
  REDIRECT_302: 'redirect_302',
  REDIRECT_307: 'redirect_307',
  REDIRECT_308: 'redirect_308',
  IFRAME: 'iframe',
  JSON: 'json',
  ARCHIVE: 'archive',
  EXECUTABLE: 'executable',
  UNKNOWN: 'unknown'
};

export const SOURCE_TYPES = {
  A_HREF: 'a_href',
  LINK_HREF: 'link_href',
  SCRIPT_SRC: 'script_src',
  IMG_SRC: 'img_src',
  IFRAME_SRC: 'iframe_src',
  FORM_ACTION: 'form_action',
  INLINE_SCRIPT: 'inline_script',
  META_REFRESH: 'meta_refresh',
  TXT_CONTENT: 'txt_content',
  REDIRECT: 'redirect',
  JSON_CONTENT: 'json_content',
  HTML_TEXT: 'html_text',
  PAGE_ROOT: 'page_root',
  STRING_LITERAL: 'string_literal'
};

// ==================== 解析限额（别名，值来自 constants.js） ====================

/** HTTP 30x 重定向最大跟随次数 */
export { MAX_REDIRECTS };

/** Inline/外部脚本内容最短长度（低于此值不做静态分析） */
export { MIN_SCRIPT_LENGTH };

/** 匹配文本片段前后保留的上下文字符数 */
export { SNIPPET_PADDING };

/** JSON 内容递归解析深度上限 */
export { JSON_MAX_DEPTH };

/** JSON 内容单对象最多遍历 key 数 */
export { JSON_MAX_KEYS };

/** 字符串字面量中 URL 的最短长度（低于此值视为噪音） */
export { JSON_MIN_URL_LENGTH };
