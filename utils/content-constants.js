/**
 * Virus Detector — 经典脚本常量镜像
 *
 * 为 content_scripts（MAIN / ISOLATED 两个 world）与扩展页同步脚本
 * （theme-init.js / body-sync.js，首帧前执行无法 import ES module）
 * 提供 utils/constants.js 的受控子集，写入 window.VT_CONSTANTS。
 *
 * 一致性保障：tests/constants-sync.test.mjs 按键映射表逐项比对
 * 本文件与 utils/constants.js 的值，不一致即测试失败。
 * 新增键流程：先改 utils/constants.js → 再改本文件 → 再更新测试映射表。
 *
 * ⚠️ 页面可能预置同名 window.VT_CONSTANTS（MAIN world 暴露给页面 JS）：
 * 读取方一律使用字段级 `C.X || fallback` 兜底，本文件不覆盖已有同名键。
 *
 * @module content-constants
 */
(function () {
  'use strict';

  var C = (typeof window !== 'undefined' && window.VT_CONSTANTS) || {};
  window.VT_CONSTANTS = C;

  // ==================== 1. UI 本地存储键与分区 ====================
  // 值不可变更（存量用户 localStorage 中已存在）；与 constants.js UI_KEYS 一致
  C.UI_KEYS = { THEME: 'vt_theme', MODE: 'vt_mode', ACTIVE_SECTION: 'vt_activeSection' };
  // 仅高级模式显示的分区（options/body-sync 共用；与 constants.js ADVANCED_ONLY_SECTIONS 一致）
  C.ADVANCED_ONLY_SECTIONS = ['thresholds', 'download', 'blacklist'];

  // ==================== 2. 扩展名（全量并集，与 constants.js 一致） ====================
  C.ARCHIVE_EXTENSIONS = [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
    '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
    '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
  ];   // 20 项（含 .img/.dmg）

  C.EXECUTABLE_EXTENSIONS = [
    '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
    '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
    '.bin', '.run', '.sh', '.dmg'
  ];   // 17 项

  // 派生（与 constants.js FILE_EXTENSIONS 同法，保证永不漂移）
  C.FILE_EXTENSIONS = Array.from(new Set(C.ARCHIVE_EXTENSIONS.concat(C.EXECUTABLE_EXTENSIONS)));

  // ==================== 2.5 可信外链域名（与 constants.js TRUSTED_EXTERNAL_DOMAINS 一致） ====================
  C.TRUSTED_EXTERNAL_DOMAINS = [
    // 代码托管
    'github.com', 'github.io', 'gist.github.com', 'gitee.com', 'gitlab.com',
    'gitcode.com', 'coding.net', 'bitbucket.org', 'sourceforge.net',
    // 文档 / 标准 / 学术
    'readthedocs.io', 'readthedocs.org', 'docs.rs', 'mozilla.org',
    'developer.mozilla.org', 'w3.org', 'arxiv.org', 'doi.org'
  ];

  // ==================== 3. 关键词（并集） ====================
  C.PROMO_KEYWORDS = [
    // 中文关键词
    '下载', '产品', '软件', '安装', '免费', '官方', '应用', '工具',
    '版本', '最新', '破解', '注册', '激活', '绿色', '汉化', '插件',
    '专业版', '正式版', '购买', '激活码', '注册机', '补丁', '试用',
    '客户端', '安装包', '精简版', '去广告', '便携版',
    // 英文关键词
    'download', 'product', 'software', 'install', 'free', 'official',
    'app', 'tool', 'version', 'latest', 'crack', 'register', 'activate',
    'pro', 'premium', 'setup', 'license', 'keygen', 'patch', 'trial',
    'portable', 'release', 'full version'
  ];

  C.DOWNLOAD_LINK_KEYWORDS = [
    'down', 'download', '下載', '下载', 'dl', 'get', 'setup', 'install',
    'free', 'app', 'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z'
  ];

  // 下载意图关键词（并集，统一小写；匹配前请对目标文本 toLowerCase）
  C.DOWNLOAD_INTENT_KEYWORDS = [
    '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
    '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
    'download now', 'free download', 'download free',
    '立即安装', '一键安装', '安装包',
    'down', 'dl', 'get', 'setup', 'install', 'free', 'app',
    'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z',
    'get started', 'ダウンロード'
  ];

  // 中间下载页抓取关键词（config 版 ∪ content-script 版并集）
  C.INTERMEDIATE_PAGE_KEYWORDS = [
    '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
    '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
    'download now', 'free download', '立即安装', '一键安装',
    '安装包', 'setup', 'install', 'get started', 'down',
    'dl', 'get', 'app', 'client', 'file', '链接', 'link',
    '百度网盘', '蓝奏云', '天翼云', '123云盘', '阿里云盘',
    '迅雷', 'bt', '磁力', 'magnet',
    '迅雷下载', 'bt下载', '磁力链接'
  ];

  // ==================== 4. 框架标记 ====================
  C.FRAMEWORK_HTML_MARKERS = [
    'react', 'vue', 'angular', 'webpack', '__initial_state__',
    '_next/', 'next/', 'nuxt', 'svelte', 'jquery', 'bootstrap',
    'node_modules', '.jsx', '.tsx', 'data-v-', 'ng-version',
    '__vue__', '__react', 'redux', 'react-dom', 'vue-router',
    'webpackjsonp', '__webpack_require__', '__nuxt', '__next',
    // —— 静态站点生成器 / 文档框架 ——
    'docusaurus', 'mkdocs', 'material-docs', 'mkdocs-material',
    'hugo', '_astro', 'astro', 'gatsby', 'hexo', 'jekyll',
    'nextra', 'vitepress', 'vuepress', 'docsify', 'sveltekit',
    'remix', 'eleventy', 'pelican', 'gitbook', 'docusaurus-tag-manager'
  ];

  C.FRAMEWORK_RESOURCE_MARKERS = [
    '_next/', '/_next/', 'next/static', '_nuxt/', '/_nuxt/',
    'react', 'react-dom', 'vue', 'vue-router', 'angular',
    'svelte', 'jquery', 'bootstrap', 'webpack'
  ];

  // ==================== 5. AUTH 正则源串 + 守卫事件名 ====================
  C.AUTH_HOST_PATTERN_SOURCE = '^(login|logon|signin|auth|oauth|account|accounts|identity|id|sso|secure|security|verify|verification|console)\\.';
  C.AUTH_PATH_PATTERN_SOURCE = '(?:^|[\\/?#&=._-])(login|logon|logout|signin|sign-in|signout|sign-out|auth|oauth|authorize|sso|saml|2fa|mfa|otp|totp|challenge|verify|verification|webauthn|passkey|password|credential|credentials|session|callback|consent|recover|recovery|reset|device)(?:$|[\\/?#&=._-])';
  C.AUTH_INTERACTION_PATTERN_SOURCE = '(login|logon|sign\\s*in|authorize|verification|verify|passkey|webauthn|2fa|mfa|otp|登录|验证码|身份验证|双重验证|两步验证)';
  C.DISABLE_GUARD_EVENT = 'virus-detector:disable-navigation-guard';

  // ==================== 6. 消息/存储键子集（仅经典脚本用到） ====================
  C.MSG_TYPES = {
    PAGE_ANALYSIS_RESULT: 'PAGE_ANALYSIS_RESULT',
    CHECK_WHITELIST: 'CHECK_WHITELIST',
    REQUEST_PAGE_TEXT: 'REQUEST_PAGE_TEXT',
    UPDATE_SETTINGS: 'UPDATE_SETTINGS',
    AUTH_INTERACTION_DETECTED: 'AUTH_INTERACTION_DETECTED'
  };
  C.STORAGE_KEYS = { GLOBAL_SETTINGS: 'global_settings' };

  // ==================== 7. 采集/检测阈值（与 constants.js 同名常量一致） ====================
  C.DEAD_LINK_CHECK_MAX = 5;
  C.DEAD_LINK_TIMEOUT_MS = 3000;
  C.DEAD_LINK_SAMPLE_MAX = 5;
  C.TXT_FETCH_LIMIT = 3;
  C.TXT_FETCH_TIMEOUT_MS = 3000;
  C.DUPLICATE_LINK_THRESHOLD = 4;
  C.DOWNLOAD_DENSITY_THRESHOLD = 2.0;
  C.EMOJI_MIN_TEXT_LENGTH = 100;
  C.EMOJI_KEYWORD_MATCH_THRESHOLD = 1;
  C.CJK_RANGES = [
    [0x4E00, 0x9FFF],
    [0x3400, 0x4DBF],
    [0xF900, 0xFAFF]
  ];
  C.CJK_MIN_COUNT = 20;
  C.CJK_MIN_RATIO = 0.02;
  C.CJK_ABSOLUTE_COUNT = 120;
  C.ATTR_SCAN_LIMIT = 2000;
  C.MAX_NODES = 15000;
  C.MIN_SCRIPT_LENGTH = 3;
  C.MAX_INLINE_SCRIPT_LENGTH = 32 * 1024;
  C.MAX_PAGE_TEXT_LENGTH = 64 * 1024;
  C.SCAN_DELAY_FIRST_MS = 600;
  C.SCAN_DELAY_SECOND_MS = 3500;
  C.IDLE_TIMEOUT_MS = 1500;
  C.EMOJI_REGEX_SOURCE = '\\p{Emoji_Presentation}|\\p{Extended_Pictographic}';
})();
