/**
 * Virus Detector — Resource Resolver 配置常量
 *
 * 集中管理递归深度、资源数量、大小、超时等所有限制参数。
 * 部分常量也在 utils/constants.js 中引用，便于评分引擎和设置页使用。
 *
 * @module resource-resolver/config
 */

// ==================== 递归控制 ====================

/** 最大递归深度（页面本身 depth=0，最多向下 3 层） */
export const MAX_DEPTH = 3;

/** 整个解析过程最多处理的资源数（含页面本身） */
export const MAX_TOTAL_RESOURCES = 20;

// ==================== 大小限制 ====================

/** TXT 文件最大下载大小（字节），超过立即停止解析 */
export const MAX_TXT_SIZE = 256 * 1024; // 256KB

/** JSON 文件最大下载大小（字节） */
export const MAX_JSON_SIZE = 128 * 1024; // 128KB

/** Inline Script 单个最大分析长度（字符），超过截断 */
export const MAX_INLINE_SCRIPT_LENGTH = 32 * 1024; // 32KB

/** 页面文本最大采集长度（字符），用于 URL 正则提取 */
export const MAX_PAGE_TEXT_LENGTH = 64 * 1024; // 64KB

// ==================== 超时控制 ====================

/** 单个资源 fetch 超时（毫秒） */
export const PER_RESOURCE_TIMEOUT = 2000;

/** 整个 Resolver 总超时（毫秒），超时后立即返回已构建的 Graph */
export const TOTAL_TIMEOUT = 5000;

// ==================== 中间页抓取配置 ====================

/** 是否启用中间 HTML 下载页抓取（默认关闭，可通过设置开启） */
export const FETCH_INTERMEDIATE_PAGES = false;

/** 最大抓取的中间页数量 */
export const MAX_INTERMEDIATE_PAGES = 3;

/** 中间页 HTML 最大下载大小（字节） */
export const MAX_INTERMEDIATE_PAGE_SIZE = 128 * 1024; // 128KB

/** 中间页抓取超时（毫秒） */
export const INTERMEDIATE_PAGE_TIMEOUT = 3000;

/** 下载中间页关键词：链接文本匹配这些词时认为是可疑中间页 */
export const INTERMEDIATE_PAGE_KEYWORDS = [
  '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
  '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
  'download now', 'free download', '立即安装', '一键安装',
  '安装包', 'setup', 'install', 'get started', 'down',
  'dl', 'get', 'app', 'client', 'file', '链接', 'link',
  '百度网盘', '蓝奏云', '天翼云', '123云盘', '阿里云盘',
  '迅雷', 'bt', '磁力', 'magnet'
];

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

// ==================== 文件类型定义 ====================

/**
 * 压缩包 / 镜像文件扩展名（与 utils/constants.js ARCHIVE_EXTENSIONS 保持一致）
 * 这些文件被 Rule2 重点检测。
 */
export const ARCHIVE_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
  '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
  '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
];

/**
 * 可执行程序扩展名（受 detectNonArchiveFiles 开关控制）
 */
export const EXECUTABLE_EXTENSIONS = [
  '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
  '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
  '.bin', '.run', '.sh', '.dmg'
];

/**
 * 文本类资源扩展名（会 fetch 内容进行解析）
 */
export const TEXT_EXTENSIONS = ['.txt', '.text', '.log', '.csv'];

/**
 * JSON 资源扩展名
 */
export const JSON_EXTENSIONS = ['.json'];

// ==================== URL 提取正则 ====================

/** 通用 URL 提取正则（从文本中提取 http/https URL） */
export const URL_PATTERN = /https?:\/\/[^\s<>"'`{}[\]|\\^`一-鿿]+/gi;

/** 归档文件 URL 提取正则（专门匹配压缩包/可执行文件 URL） */
export const ARCHIVE_URL_PATTERN = (() => {
  const exts = [...ARCHIVE_EXTENSIONS, ...EXECUTABLE_EXTENSIONS]
    .map(e => e.replace(/\./g, '\\.'))
    .join('|');
  return new RegExp(
    `https?:\/\/[^\\s<>"'\`{}\\[\\]|\\\\^\`]+\.(${exts})(\\?[^\\s<>"'\`{}\\[\\]|\\\\^\`]*)?`,
    'gi'
  );
})();

// ==================== Inline Script 分析正则 ====================

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

/** 字符串字面量中的 URL（含关键扩展名） */
export const STRING_URL_PATTERN = /["'`](https?:\/\/[^"'`]*\.(zip|rar|7z|tar|gz|tgz|bz2|xz|iso|cab|exe|msi|apk|dmg|pkg|bat|cmd|ps1|vbs|scr|jar|bin|run|sh)[^"'`]*)["'`]/gi;

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
