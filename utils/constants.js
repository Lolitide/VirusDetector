/**
 * Virus Detector — 全局常量配置
 *
 * 集中管理评分阈值、检测关键词、TLD 模式、消息类型、
 * 存储键名和缓存策略。所有模块通过 import 共用同一份配置。
 *
 * 本文件是全部常量的唯一真源（Single Source of Truth）：
 *   - settings-schema.js 的 SETTINGS_DEFAULTS 由此派生；
 *   - resource-resolver/config.js 的 RESOLVER_* 数值由此引用；
 *   - content 脚本与扩展页同步脚本经 utils/content-constants.js 镜像
 *     （一致性由 tests/constants-sync.test.mjs 保证）。
 * 本文件自身不 import 任何模块，无循环依赖风险。
 * 所有导出的数组/对象在文件末尾统一深冻结，import 方不得修改。
 *
 * @module constants
 */

// ==================== 版本号（统一入口） ====================
/**
 * 当前扩展版本号，用于 User-Agent 与上报载荷等展示性用途。
 * 注意：更新检测以 chrome.runtime.getManifest().version 为唯一真源，不依赖此常量；
 * 发版时仍需同步修改此处 + manifest.json + README（本常量已与 manifest 脱节过一次，见 v2.5.1）。
 */
export const VERSION = '2.5.2';

// ==================== 评分体系 ====================
/** 触发警告的总分阈值（注入拦截 + 警告窗口 + 图标变红） */
export const SCORE_THRESHOLD = 100;

/** 下载意图 Gate 文本密度阈值（每千字符命中次数），可在设置中调整 */
export const DOWNLOAD_DENSITY_THRESHOLD = 2.0;

/** 触发下载确认弹窗的阈值（不注入页面拦截，仅弹窗二次确认） */
export const DOWNLOAD_CONFIRM_THRESHOLD = 80;

export const SCORE_RULE_1 = 60;              // 规则一：域名仿冒（封顶）
// 规则一联动评分（分级嫌疑 + 多特征联动，取代原「命中即 +60」硬处理）：
export const SCORE_RULE1_STRONG = 45;        // STRONG 嫌疑基础分（typosquat/官方域标签/形近/堆叠/拼音）
export const SCORE_RULE1_WEAK = 10;          // WEAK 嫌疑基础分（弱关键词段/子串命中）
export const SCORE_RULE1_WEAK_NO_CLAIM = 5;  // WEAK 且页面未声称任何品牌 → 减半（+5）
export const SCORE_RULE1_CLAIM_BRAND = 20;   // 页面 title 声称被仿冒品牌 → 增强
export const SCORE_RULE1_NO_ICP = 10;        // 无 ICP 备案 → 增强
export const SCORE_RULE1_ICP_PRESENT = 15;   // 有 ICP 备案（且页面展示备案号）→ 降权
export const SCORE_RULE1_NEW_DOMAIN = 10;    // 域名注册 < 90 天 → 增强
export const SCORE_RULE1_OLD_DOMAIN = 10;    // 域名注册 > 730 天 → 降权
export const SCORE_RULE1_DOWNLOAD = 10;      // 页面存在指向非官方跨域下载链接 → 增强
export const SCORE_RULE_2_HIGH = 40;         // 规则二：压缩包下载（域名已有≥30嫌疑）
export const SCORE_RULE_2_LOW = 10;          // 规则二：压缩包下载（弱信号）
export const SCORE_RULE_3 = 50;             // 规则三：ICP备案号缺失（所有网站）
export const SCORE_RULE_3_FAKE = 30;        // 规则三：ICP备案号存在但无法核验（无政府链接/虚假号码）
// 规则三联动降权（保持 50 上限，可信档案下可降至下限 SCORE_RULE3_MIN_SCORE）：
export const SCORE_RULE3_OLD_DOMAIN_DEDUCT = 20;  // 老域名（注册 > 730 天）→ 无备案降权
export const SCORE_RULE3_NO_CLAIM_DEDUCT = 10;    // 页面 title 未声称任何品牌 → 无备案降权
export const SCORE_RULE3_TRUSTED_DEDUCT = 10;     // 存在可信信号（可信外链或 meta generator）→ 无备案降权
export const SCORE_RULE3_MIN_SCORE = 10;          // 无备案分支最低分（保留法规信号，不归零）

// 规则四：链接分析
export const SCORE_RULE_4A_SAME_PAGE = 20;      // 规则四A-① ≥8个链接指向当前页本身（完全一致URL）
export const SCORE_RULE_4A_DEAD_LINK = 20;      // 规则四A-② ≥3个死链（指向不存在子页面的链接）
export const SCORE_RULE_4A_DUPLICATE_LINK = 20; // 规则四A-③ 重复链接得分封顶（scoring-engine 按 4*log2(n) 计算后取 min）
export const SCORE_RULE_4A_DOWNLOAD_LINK_BONUS = 10; // 规则四A-③附加 该链接是下载链接（含download等字样）
export const SCORE_RULE_4B_DOWNLOAD_BTN = 10;   // 规则四B-a 外链绑在下载按钮上
export const SCORE_RULE_4B_FILE_LINK = 10;      // 规则四B-b 外链指向文件
export const SCORE_RULE_4B_ARCHIVE_LINK = 10;   // 规则四B-b附加 文件是压缩包格式

export const SCORE_RULE_5 = 30;              // 规则五：代码工程化 — 高度可疑（强信号≥2）
export const SCORE_RULE_5_PARTIAL = 20;      // 规则五：代码工程化 — 中度可疑（强信号≥1且总信号≥2）

// 规则二触发阈值：域名嫌疑分达到此值才给高分
export const RULE_2_DOMAIN_SUSPICION_THRESHOLD = 30;

// ==================== 规则二：主动压缩包链接检测（Phase A） ====================
/** 主动检测得分上限（页面扫描阶段） */
export const SCORE_RULE_2_PROACTIVE_MAX = 30;

/** 单个高危压缩包链接（跨域+下载关键词）基础得分 */
export const SCORE_RULE_2_PER_HIGH_RISK = 10;

/** 单个中危压缩包链接（跨域+无下载关键词）基础得分 */
export const SCORE_RULE_2_PER_LOW_RISK = 5;

/** 单个可信平台压缩包链接（跨域+指向GitHub等知名平台）降权得分 */
export const SCORE_RULE_2_TRUSTED_PLATFORM = 3;

/** 官网下载链接劫持检测：仿冒站上的下载链接指向非官方域名，额外加分 */
export const SCORE_RULE_2_HIJACK = 30;

/** 官网劫持加分硬上限（Math.min(hijackCount * SCORE_RULE_2_HIJACK, 此值)） */
export const HIJACK_SCORE_CAP = 60;

/** 批量分发阈值：压缩包链接数 >= 此值时触发批量加权 */
export const SCORE_RULE_2_BATCH_THRESHOLD = 3;

/** 批量分发乘数（≥BATCH_THRESHOLD 时基础分×此值） */
export const SCORE_RULE_2_BATCH_MULTIPLIER = 2.0;

/** 域名嫌疑加权乘数：existingScore >= DOMAIN_SUSPICION_THRESHOLD 时应用 */
export const SCORE_RULE_2_SUSPICION_MULTIPLIER = 1.5;

// ==================== 风险等级 ====================
export const RISK_LEVEL = {
  SAFE: 'safe',
  WARNING: 'warning'
};

// ==================== 压缩包扩展名 ====================
/**
 * 压缩包/镜像文件扩展名（全量并集，各层统一口径，含 .img/.dmg）。
 * 全库唯一真源；content-constants.js 镜像与导航守卫/注入层兜底由 constants-sync 测试保证一致。
 */
export const ARCHIVE_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
  '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
  '.tar.bz2', '.tar.xz', '.gz2', '.zst', '.img', '.dmg'
];

// ==================== 规则四：链接分析 ====================
// 链接指向当前页的判断阈值
export const SAME_PAGE_LINK_THRESHOLD = 8;    // ≥8个同页链接 → 触发①（排除导航区域后）

// 重复链接检测阈值（规则四A-③）
export const DUPLICATE_LINK_THRESHOLD = 4;    // ≥4个不同元素指向同一个链接 → 触发③

// 死链最小数量（规则四A-②）
export const DEAD_LINK_THRESHOLD = 3;    // ≥3条死链 → 触发②

// 下载链接检测关键词（规则四A-③附加分）
export const DOWNLOAD_LINK_KEYWORDS = [
  'down', 'download', '下載', '下载', 'dl', 'get', 'setup', 'install',
  'free', 'app', 'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z'
];

// 下载语义关键词（判断链接是否绑在下载按钮上）
export const DOWNLOAD_BUTTON_KEYWORDS = [
  '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
  '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
  'Download Now', 'Free Download', 'Download Free',
  '立即安装', '一键安装', '安装包'
];

/**
 * 下载意图关键词（全量并集，统一小写去重）。
 * = DOWNLOAD_BUTTON_KEYWORDS ∪ DOWNLOAD_LINK_KEYWORDS ∪ 'get started' ∪ 'ダウンロード'
 * 各端匹配前一律对目标文本 toLowerCase，小写形式保证所有词条都能命中。
 */
export const DOWNLOAD_INTENT_KEYWORDS = [
  '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
  '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
  'download now', 'free download', 'download free',
  '立即安装', '一键安装', '安装包',
  'down', 'dl', 'get', 'setup', 'install', 'free', 'app',
  'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z',
  'get started', 'ダウンロード'
];

/**
 * 中间下载页抓取关键词（标记"页面 A → 下载页 B"的中间页）。
 * 语义独立，与 DOWNLOAD_BUTTON_KEYWORDS 重叠是设计如此。
 */
export const INTERMEDIATE_PAGE_KEYWORDS = [
  '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
  '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
  'download now', 'free download', '立即安装', '一键安装',
  '安装包', 'setup', 'install', 'get started', 'down',
  'dl', 'get', 'app', 'client', 'file', '链接', 'link',
  '百度网盘', '蓝奏云', '天翼云', '123云盘', '阿里云盘',
  '迅雷', 'bt', '磁力', 'magnet',
  '迅雷下载', 'bt下载', '磁力链接'
];

/** 可执行程序文件扩展名（受 detectNonArchiveFiles 开关控制） */
export const EXECUTABLE_EXTENSIONS = [
  '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
  '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
  '.bin', '.run', '.sh', '.dmg'
];

// 文件扩展名（压缩包 + 可执行文件，规则四B-b；由两份列表派生，保证永不漂移）
export const FILE_EXTENSIONS = [...new Set([...ARCHIVE_EXTENSIONS, ...EXECUTABLE_EXTENSIONS])];

// ==================== 可信外链域名（开源/标准/文档平台） ====================
// 页面链接指向这些平台（或其子域）是「开源项目/文档/学术性质」的反向信号，
// 用于规则三(ICP)与规则五(代码工程化)的可信降权。小而精原则：
// 只收录攻击者难以伪造的托管平台与标准组织，不收录泛用 CDN/资讯站。
// 匹配规则：链接 hostname 等于列表项或以其为后缀（如 xxx.github.io 命中 github.io）。
export const TRUSTED_EXTERNAL_DOMAINS = [
  // 代码托管
  'github.com', 'github.io', 'gist.github.com', 'gitee.com', 'gitlab.com',
  'gitcode.com', 'coding.net', 'bitbucket.org', 'sourceforge.net',
  // 文档 / 标准 / 学术
  'readthedocs.io', 'readthedocs.org', 'docs.rs', 'mozilla.org',
  'developer.mozilla.org', 'w3.org', 'arxiv.org', 'doi.org'
];

// ==================== 代码工程化检测（规则五） ====================
export const AI_PAGE_THRESHOLDS = {
  MIN_DOM_NODES: 100,             // DOM节点数低于此值为可疑（替代HTML行数，不受代码格式化影响）
  MIN_EXTERNAL_RESOURCES: 5,      // 外部资源去重总数（脚本+样式+图片+字体+媒体）低于此值为可疑
  MIN_TEXT_LENGTH: 500            // 页面文本需大于此值才进入检测
};

// ==================== 规则五子规则：关键词预筛选 + Emoji 密度检测 ====================
/**
 * 先通过推广/产品关键词预筛选确定页面是否为推广性质，
 * 再基于 Emoji 密度进行分段线性加分（上限 20 分）。
 *
 * 设计原理：
 *   - 正常页面 Emoji 密度通常极低
 *   - 钓鱼/欺诈推广页面常大量使用 Emoji 吸引眼球
 *   - 关键词预筛避免对非推广页面的误报
 */
/** 推广/产品页面关键词（中英文），用于预筛选 */
export const PROMO_KEYWORDS = [
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

/** 推广关键词匹配度阈值：匹配数量 >= 此值才进入 Emoji 密度检测 */
export const EMOJI_KEYWORD_MATCH_THRESHOLD = 1;

/** Emoji 密度检测所需的最小文本长度（字符数） */
export const EMOJI_MIN_TEXT_LENGTH = 100;

/** Emoji 密度得分上限 */
export const EMOJI_DENSITY_MAX_SCORE = 20;

/** Emoji 密度下阈值（个/千字符），低于此值不加分 */
export const EMOJI_DENSITY_THRESHOLD_LOW = 2.0;

/** Emoji 密度上阈值（个/千字符），高于此值得满分 */
export const EMOJI_DENSITY_THRESHOLD_HIGH = 10.0;

/**
 * Emoji 匹配正则源串（统一小写/无关）。
 * 使用显式 \p{Extended_Pictographic} 而非 \p{Emoji}（后者含数字与符号，需尾随 VS16 限定）。
 * 用法：new RegExp(EMOJI_REGEX_SOURCE, 'gu')
 */
export const EMOJI_REGEX_SOURCE = '\\p{Emoji_Presentation}|\\p{Extended_Pictographic}';

// 主流框架标记 — HTML源码字符串匹配用（content-script 使用此列表做全文搜索）
// 覆盖主流 SPA 框架 + 常见静态站点生成器（避免对 Docusaurus/MkDocs/Hugo/Astro 等合法站误判"无框架"）
export const FRAMEWORK_HTML_MARKERS = [
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

/** 框架资源 URL 标记（script/link 的 src/href 中匹配，content-script 使用） */
export const FRAMEWORK_RESOURCE_MARKERS = [
  '_next/', '/_next/', 'next/static', '_nuxt/', '/_nuxt/',
  'react', 'react-dom', 'vue', 'vue-router', 'angular',
  'svelte', 'jquery', 'bootstrap', 'webpack'
];

// ==================== 导航守卫（L0） ====================
/** 认证页动态卸载导航守卫的页面事件名（MAIN world 内 dispatchEvent 通信） */
export const DISABLE_GUARD_EVENT = 'virus-detector:disable-navigation-guard';

// 认证 URL 特征正则源串（content-script / service-worker 由本源串构造；navigation-guard 持有字面量兜底副本，由 constants-sync 测试保证一致）
/** 认证主机名特征（hostname 前缀） */
export const AUTH_HOST_PATTERN_SOURCE = '^(login|logon|signin|auth|oauth|account|accounts|identity|id|sso|secure|security|verify|verification|console)\\.';
/** 认证路径/参数特征（路径+query+hash 中分段匹配） */
export const AUTH_PATH_PATTERN_SOURCE = '(?:^|[\\/?#&=._-])(login|logon|logout|signin|sign-in|signout|sign-out|auth|oauth|authorize|sso|saml|2fa|mfa|otp|totp|challenge|verify|verification|webauthn|passkey|password|credential|credentials|session|callback|consent|recover|recovery|reset|device)(?:$|[\\/?#&=._-])';
/** 认证交互特征（页面文案/控件标识） */
export const AUTH_INTERACTION_PATTERN_SOURCE = '(login|logon|sign\\s*in|authorize|verification|verify|passkey|webauthn|2fa|mfa|otp|登录|验证码|身份验证|双重验证|两步验证)';

/**
 * 构造认证 URL 特征正则（'i' 标志，无 g 标志，可安全 .test()）。
 * @returns {{host: RegExp, path: RegExp, interaction: RegExp}}
 */
export function buildAuthPatterns() {
  return {
    host: new RegExp(AUTH_HOST_PATTERN_SOURCE, 'i'),
    path: new RegExp(AUTH_PATH_PATTERN_SOURCE, 'i'),
    interaction: new RegExp(AUTH_INTERACTION_PATTERN_SOURCE, 'i')
  };
}

// ==================== 消息类型 ====================
export const MSG_TYPES = {
  PAGE_ANALYSIS_RESULT: 'PAGE_ANALYSIS_RESULT',
  GET_TAB_STATE: 'GET_TAB_STATE',
  REQUEST_PAGE_TEXT: 'REQUEST_PAGE_TEXT',
  GET_OFFICIAL_LINK: 'GET_OFFICIAL_LINK',
  CLEAR_TAB_STATE: 'CLEAR_TAB_STATE',
  ADD_TO_WHITELIST: 'ADD_TO_WHITELIST',
  REMOVE_FROM_WHITELIST: 'REMOVE_FROM_WHITELIST',
  CHECK_WHITELIST: 'CHECK_WHITELIST',
  DOWNLOAD_CONFIRMATION: 'DOWNLOAD_CONFIRMATION',
  GET_DOWNLOAD_BLACKLIST: 'GET_DOWNLOAD_BLACKLIST',
  REMOVE_DOWNLOAD_BLACKLIST: 'REMOVE_DOWNLOAD_BLACKLIST',
  SUBMIT_REPORT: 'SUBMIT_REPORT',
  SETTINGS_UPDATED: 'SETTINGS_UPDATED',
  UPDATE_SETTINGS: 'UPDATE_SETTINGS',
  BULK_UPDATE_WHITELIST: 'BULK_UPDATE_WHITELIST',
  CHECK_UPDATE: 'CHECK_UPDATE',
  // 认证交互（页面出现登录/2FA 控件时 content → background）
  AUTH_INTERACTION_DETECTED: 'AUTH_INTERACTION_DETECTED',
  // 站点黑名单
  ADD_SITE_BLACKLIST: 'ADD_SITE_BLACKLIST',
  REMOVE_SITE_BLACKLIST: 'REMOVE_SITE_BLACKLIST',
  GET_SITE_BLACKLIST: 'GET_SITE_BLACKLIST',
  CLEAR_SITE_BLACKLIST: 'CLEAR_SITE_BLACKLIST'
};

// ==================== 存储键 ====================
export const STORAGE_KEYS = {
  TAB_STATE_PREFIX: 'tab_state_',
  DOMAIN_CACHE: 'domain_cache_',
  GLOBAL_SETTINGS: 'global_settings',
  WHITELIST: 'whitelist',
  SITE_BLACKLIST: 'site_blacklist',
  DOWNLOAD_BLACKLIST: 'download_blacklist',
  PENDING_DOWNLOADS: 'pending_downloads',
  USER_REPORTS: 'user_reports',
  UPDATE_INFO: 'update_info',
  /** ICP 备案 API 缓存键前缀（icp-api.js / options.js 共用） */
  ICP_CACHE_PREFIX: 'icp_api_v1_'
};

/**
 * 扩展页 UI 本地存储键（localStorage，options/popup/theme-init/body-sync 共用）。
 * 值不可变更（存量用户浏览器中已存在这些键）。
 */
export const UI_KEYS = {
  THEME: 'vt_theme',
  MODE: 'vt_mode',
  ACTIVE_SECTION: 'vt_activeSection'
};

export const CACHE_TTL = 24 * 60 * 60 * 1000;  // 24 小时

export const DAY_MS = 24 * 60 * 60 * 1000;  // 1 天

export const HOUR_MS = 60 * 60 * 1000;  // 1 小时

// ==================== 用户上报 → GitHub Issue ====================
/** Cloudflare Worker 上报代理 URL（部署后替换为实际 URL） */
export const REPORT_API_URL = 'https://virus-detector-report.lolitide.workers.dev/api/report';

/** 上报类型枚举（popup / warning / download-confirm 三端与 SW 分派共用） */
export const REPORT_TYPES = {
  FALSE_POSITIVE: 'false_positive',
  CONFIRMED_PHISH: 'confirmed_phish'
};

// ==================== 更新检测 ====================
/**
 * Cloudflare Worker 版本查询接口（主源）。
 * Worker 服务端请求 GitHub API 并做边缘缓存，规避 api.github.com
 * 按来源 IP 60次/小时 的未认证限额（共享出口 IP 下极易耗尽）。
 */
export const UPDATE_VERSION_API_URL = 'https://virus-detector-report.lolitide.workers.dev/api/version';

/** GitHub Releases API（回退源，Worker 不可达时使用） */
export const GITHUB_RELEASES_API_URL = 'https://api.github.com/repos/Lolitide/VirusDetector/releases/latest';

/** GitHub Releases 页面（用户手动下载） */
export const GITHUB_RELEASES_PAGE = 'https://github.com/Lolitide/VirusDetector/releases';

/** 仓库首页（popup / options 展示用） */
export const GITHUB_REPO_PAGE = 'https://github.com/Lolitide/VirusDetector';

/** 新建 Issue 页面（上报引导用） */
export const GITHUB_NEW_ISSUE_URL = 'https://github.com/Lolitide/VirusDetector/issues/new/choose';

/**
 * 更新渠道：'auto' | 'manual' | 'store'
 * - 'auto'：运行时根据 manifest.update_url 判定（商店安装会被商店注入该字段）
 * - 'store'：跳过远程检查（浏览器商店自动更新）；上架打包时由构建脚本改写为此值
 * - 'manual'：始终执行远程检查（GitHub zip / 开发者模式安装）
 */
export const UPDATE_CHANNEL = 'auto';

/** 单个更新源的超时时间（毫秒） */
export const UPDATE_CHECK_TIMEOUT_MS = 8000;

/** 更新检查失败后的重试间隔（分钟），成功后恢复 24h 周期 */
export const UPDATE_RETRY_DELAY_MINUTES = 60;

/** 更新检查 alarm 名称（chrome.alarms） */
export const ALARM_NAME_UPDATE_CHECK = 'updateCheck';

/** 更新检查正常周期（分钟）= 24 小时 */
export const UPDATE_CHECK_PERIOD_MINUTES = 1440;

// ==================== RDAP / Whois API 配置 ====================
/** RDAP IANA 引导文件 URL（TLD → RDAP 服务器映射） */
export const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/** WhoisCX API 基础 URL（Whois 回退查询）——必须走 https，域名查询信息含敏感数据 */
export const WHOIS_API_URL = 'https://api.whoiscx.com/whois/';

/** RDAP 代理服务 URL（无公开 RDAP 服务的 TLD 回退，rdap-client 使用） */
export const RDAP_PROXY_URL = 'https://rdap.ss/api/query?q=';

/** Google DoH PTR 反查端点前缀（url-utils PSL 反查用；调用方拼 `&type=PTR`） */
export const PSL_DOH_URL = 'https://dns.google/resolve?name=';

/** PSL DoH 查询超时（毫秒） */
export const PSL_DNS_TIMEOUT_MS = 5000;

/** RDAP 查询结果缓存有效期（毫秒），24小时。缓存由 WhoisClient 共享管理 */
export const WHOIS_CACHE_TTL = 24 * 60 * 60 * 1000;

/** WhoisCX API 请求超时（毫秒） */
export const WHOIS_API_TIMEOUT = 8000;

/** WhoisCX 最小请求间隔默认值（毫秒，限流保护） */
export const MIN_WHOIS_INTERVAL_MS = 2100;

/** Whois 请求间隔下限（毫秒，用户设置不得低于此值） */
export const WHOIS_INTERVAL_FLOOR_MS = 1000;

/** RDAP 客户端请求超时（毫秒） */
export const RDAP_REQUEST_TIMEOUT = 10000;

// ==================== 域名注册时间评分规则 ====================
/**
 * 基于域名注册天数（creation_days）通过 S 型衰减函数计算可疑加分。
 * 公式：floor(MAX / (1 + (x / (60 * b))^a))
 *   x     = creation_days（域名已注册天数）
 *   MAX   = 最大增加可疑分数
 *   a     = 衰减速率参数（越大衰减越快）
 *   b     = 衰减零点参数（控制衰减中心位置，单位：60天）
 */
export const SCORE_DOMAIN_AGE_MAX = 60;          // 最大增加可疑分数

/** 域名年龄衰减速率参数 a（越大衰减越快） */
export const DOMAIN_AGE_DECAY_A = 2.2;

/** 域名年龄衰减零点参数 b（控制衰减中心位置，单位：60天） */
export const DOMAIN_AGE_DECAY_B = 1.9;

// ==================== 下载链接跨域检测规则 ====================
/** 下载链接与当前页面跨域（不同主域名）基础加分 */
export const SCORE_DOWNLOAD_CROSS_DOMAIN = 10;

/** 下载链接域名过新（新注册）附加加分 */
export const SCORE_DOWNLOAD_NEW_DOMAIN = 10;

/** 下载链接域名剩余有效期阈值（天），低于此值视为可疑 */
export const DOWNLOAD_VALID_DAYS_THRESHOLD = 365;

/** 下载链接域名注册天数阈值（天），低于此值视为新域名 */
export const DOWNLOAD_CREATION_DAYS_THRESHOLD = 90;

// ==================== 站点黑名单 ====================
/** 站点域名命中黑名单时的基础高分（直接触发警告流程） */
export const SCORE_SITE_BLACKLIST = 60;

// ==================== 下载域名黑名单 ====================
/** 下载域名命中黑名单时的额外加分 */
export const SCORE_DOWNLOAD_BLACKLIST = 20;

/** 是否检测非压缩包可执行文件（.exe/.msi 等），默认关闭，后续由设置页控制 */
export const DETECT_NON_ARCHIVE_FILES_DEFAULT = false;

/** 黑名单条目过期天数（天），超过此天数无命中自动清理 */
export const DOWNLOAD_BLACKLIST_CLEANUP_DAYS = 90;

/** 黑名单容量上限（条） */
export const DOWNLOAD_BLACKLIST_MAX_ENTRIES = 500;
export const SITE_BLACKLIST_MAX_ENTRIES = 500;

/** 单条黑名单记录保存的最近来源页上限（download-blacklist 使用） */
export const BLACKLIST_MAX_SOURCE_PAGES = 20;

/** 用户上报记录容量上限（service-worker 使用） */
export const REPORTS_MAX_ENTRIES = 200;

// ==================== Resource Resolver 配置 ====================
/**
 * Resource Resolver 的运行时参数（唯一真源；config.js 以其为别名 re-export）。
 */

/** Resource Resolver 最大递归深度（0=页面本身，最多向下 N 层） */
export const RESOLVER_MAX_DEPTH = 3;

/** Resource Resolver 整个解析过程最多处理的资源数 */
export const RESOLVER_MAX_TOTAL_RESOURCES = 20;

/** TXT 文件最大下载大小（字节） */
export const RESOLVER_MAX_TXT_SIZE = 256 * 1024; // 256KB

/** JSON 文件最大下载大小（字节） */
export const RESOLVER_MAX_JSON_SIZE = 128 * 1024; // 128KB

/** Inline Script 单个最大分析长度（字符），超过截断 */
export const RESOLVER_MAX_INLINE_SCRIPT_LENGTH = 32 * 1024; // 32KB

/** 页面文本最大采集长度（字符），用于 URL 正则提取 */
export const RESOLVER_MAX_PAGE_TEXT_LENGTH = 64 * 1024; // 64KB

/** 单个资源 fetch 超时（毫秒） */
export const RESOLVER_PER_RESOURCE_TIMEOUT = 2000;

/** Resource Resolver 总超时（毫秒） */
export const RESOLVER_TOTAL_TIMEOUT = 5000;

/** 是否启用中间 HTML 下载页抓取（默认关闭，可通过设置开启） */
export const RESOLVER_FETCH_INTERMEDIATE_PAGES_DEFAULT = false;

/** 最大抓取的中间页数量 */
export const RESOLVER_MAX_INTERMEDIATE_PAGES = 3;

/** 中间页 HTML 最大下载大小（字节） */
export const RESOLVER_MAX_INTERMEDIATE_PAGE_SIZE = 128 * 1024; // 128KB

/** 中间页抓取超时（毫秒） */
export const RESOLVER_INTERMEDIATE_PAGE_TIMEOUT = 3000;

/** 文本类资源扩展名（会 fetch 内容进行解析） */
export const RESOLVER_TEXT_EXTENSIONS = ['.txt', '.text', '.log', '.csv'];

/** JSON 资源扩展名 */
export const RESOLVER_JSON_EXTENSIONS = ['.json'];

/** JSON 内容递归解析深度上限 */
export const JSON_MAX_DEPTH = 10;

/** JSON 内容单对象最多遍历 key 数 */
export const JSON_MAX_KEYS = 50;

/** 字符串字面量中 URL 的最短长度（低于此值视为噪音） */
export const JSON_MIN_URL_LENGTH = 10;

/** HTTP 30x 重定向最大跟随次数 */
export const MAX_REDIRECTS = 5;

/** Inline/外部脚本内容最短长度（低于此值不做静态分析） */
export const MIN_SCRIPT_LENGTH = 3;

/** 匹配文本片段前后保留的上下文字符数（txt-resolver 与中间页报告） */
export const SNIPPET_PADDING = 40;

// ==================== 内容脚本采集参数 ====================
/** 死链候选数上限（先截断再抽样） */
export const DEAD_LINK_CHECK_MAX = 5;

/** 死链 HEAD 请求验证样本数上限 */
export const DEAD_LINK_SAMPLE_MAX = 5;

/** 死链 HEAD 请求超时（毫秒） */
export const DEAD_LINK_TIMEOUT_MS = 3000;

/** 页面 .txt 链接最多尝试解析数量 */
export const TXT_FETCH_LIMIT = 3;

/** .txt 内容 fetch 超时（毫秒） */
export const TXT_FETCH_TIMEOUT_MS = 3000;

/** 页面加载后第一次扫描延迟（毫秒） */
export const SCAN_DELAY_FIRST_MS = 600;

/** 页面加载后第二次扫描延迟（毫秒） */
export const SCAN_DELAY_SECOND_MS = 3500;

/** 空闲重扫等待（毫秒） */
export const IDLE_TIMEOUT_MS = 1500;

/** DOM 属性扫描节点数上限（框架特征扫描） */
export const ATTR_SCAN_LIMIT = 2000;

/** TreeWalker 全文本节点遍历上限（ICP 文本扫描） */
export const MAX_NODES = 15000;

// ==================== CJK 内容判定 ====================
/** CJK 统一表意文字 Unicode 范围（U+4E00–U+9FFF / U+3400–U+4DBF / U+F900–U+FAFF） */
export const CJK_RANGES = [
  [0x4E00, 0x9FFF],
  [0x3400, 0x4DBF],
  [0xF900, 0xFAFF]
];

/** CJK 判定：命中数下限（与比例同时满足） */
export const CJK_MIN_COUNT = 20;

/** CJK 判定：占文本比例下限 */
export const CJK_MIN_RATIO = 0.02;

/** CJK 判定：命中数绝对下限（满足即判为中文内容，兼容中英混排） */
export const CJK_ABSOLUTE_COUNT = 120;

// ==================== 域名年龄减分规则 ====================
/**
 * 基于当前页面域名注册天数（creation_days）的减分规则。
 * 仅当当前可疑总分 >= 阈值时才应用，避免对低分网站的过度减分。
 *
 * 减分公式（x = creation_days）：
 *   x < 365           → bonus = 0
 *   365 ≤ x < 730     → bonus = floor(MAX_BONUS * (x - 365) / (730 - 365))
 *   x ≥ 730           → bonus = MAX_BONUS
 */
export const SCORE_DOMAIN_AGE_BONUS_MAX = 20;        // 最大减分分值

/** 域名年龄减分应用阈值：当前可疑分数需 >= 此值才执行减分 */
export const DOMAIN_AGE_BONUS_SCORE_THRESHOLD = 20;

/** 域名年龄减分起始天数：注册天数 < 此值不减分 */
export const DOMAIN_AGE_BONUS_MIN_DAYS = 365;

/** 域名年龄减分封顶天数：注册天数 ≥ 此值获得最大减分 */
export const DOMAIN_AGE_BONUS_MAX_DAYS = 730;

// ==================== ResourceGraph 派生加分（规则二 Phase C） ====================
/** TXT 跳转链加分上限（TXT 深度链每级 +8） */
export const GRAPH_TXT_BONUS_CAP = 15;

/** TXT 跳转链每级加分 */
export const GRAPH_TXT_PER_LEVEL = 8;

/** 重定向链加分上限（每跳 +3） */
export const GRAPH_REDIRECT_CAP = 10;

/** 重定向链每跳加分 */
export const GRAPH_REDIRECT_PER_HOP = 3;

/** 可执行文件加分上限（每个 +5） */
export const GRAPH_EXE_CAP = 20;

/** 可执行文件每个加分 */
export const GRAPH_EXE_PER_FILE = 5;

/** 压缩包 MIME 类型表（scoring-engine 第三层 MIME 检测） */
export const ARCHIVE_MIME_TYPES = [
  'application/zip',
  'application/x-rar-compressed',
  'application/x-7z-compressed',
  'application/x-tar',
  'application/gzip',
  'application/x-bzip2',
  'application/x-xz',
  'application/x-compress',
  'application/x-iso9660-image',
  'application/vnd.ms-cab-compressed',
  'application/x-arj',
  'application/x-lzh',
  'application/zstd',
  'application/x-compressed-tar',
  'application/x-gzip',
  'application/x-bzip',
  'application/x-lzma'
];

// ==================== 弹窗/确认窗口/通知时序 ====================
/** 警告窗口自动关闭倒计时（秒） */
export const WARNING_AUTO_CLOSE_SECONDS = 30;

/** 下载确认窗口自动关闭倒计时（秒） */
export const CONFIRM_AUTO_CLOSE_SECONDS = 60;

/** 钓鱼确认上报后自动关闭窗口的等待（毫秒） */
export const PHISH_CONFIRM_TIMEOUT_MS = 3000;

/** options 页 toast 自动关闭时间（毫秒） */
export const TOAST_DURATION_MS = 3000;

/** 待确认下载缓存有效期（毫秒），5 分钟 */
export const PENDING_DOWNLOAD_TTL_MS = 5 * 60 * 1000;

/** 页面注入拦截器 MutationObserver 停止观察的存活时间（毫秒） */
export const BLOCKER_OBSERVER_LIFETIME_MS = 30000;

/** 同一标签页警告弹窗冷却期（毫秒） */
export const WARNING_COOLDOWN_MS = 5000;

/** 下载意图 Gate 等待评分结果超时（毫秒） */
export const GATE_TIMEOUT_MS = 8000;

// ==================== UI 枚举 ====================
/** 主题枚举（options / settings-schema 共用） */
export const THEME_VALUES = ['dark', 'light', 'auto'];

/** 灵敏度预设档位（settings-schema SENSITIVITY_PRESETS 键与 options 滑块共用） */
export const PRESET_LEVELS = ['low', 'medium', 'high', 'custom'];

/** 仅高级模式显示的分区 id（options.js / body-sync.js 共用） */
export const ADVANCED_ONLY_SECTIONS = ['thresholds', 'download', 'blacklist'];

// ==================== 下载二次确认动作枚举 ====================
/** 下载确认弹窗三选项动作值（warning ↔ background 协议） */
export const DOWNLOAD_CONFIRM_ACTIONS = {
  ALLOW_ONCE: 'allow_once',
  TRUST_SITE: 'trust_site',
  BLOCK_BLACKLIST: 'block_blacklist'
};

// ==================== URL 提取正则生成 ====================
/**
 * 生成"URL 以归档/可执行扩展名结尾（后缀边界锚定）"的提取正则。
 * 用 lookahead (?=[?#\s]|$) 锚定：a.zip / a.zip?x / a.zip#f 匹配，
 * a.zip.bak / a.zipx 不匹配（修复旧正则把 a.zip.bak 整段误配为 zip 的漏检面）。
 *
 * @param {string[]} exts 扩展名数组（如 ARCHIVE_EXTENSIONS）
 * @returns {RegExp} 'gi' 标志正则；调用方如需重复 exec 须自行重置 lastIndex
 */
export function buildArchiveUrlPattern(exts) {
  // 扩展名自带前导点，逐项前置反斜杠转义为 \.zip 形式（'\\' 是标准转义，避免 \. 歧义写法）；
  // 模板不再额外加 \.（否则会出现 \.(\.zip) 双重转义）；正则源码中 / 无需转义，直接写 /
  const body = exts.map((e) => '\\' + e).join('|');
  return new RegExp(
    `https?://[^\\s<>"'{}[\\]|\\\\^\`]+(${body})(?=[?#\\s]|$)`,
    'gi'
  );
}

// ==================== ICP 备案查询 API 配置 ====================
// 备案核验改为「按域名查询 API」（见 background/icp-api.js），端点集中于此避免硬编码。
// 多源备援：主用 uapis（稳定），备援 apihz（公开接口，限流 10 次/分钟）。
// 每个 provider：
//   name        展示名
//   enabled     是否启用
//   needKey     是否需要 key（apihz 公开 demo 凭据默认可用，故为 false）
//   rateLimitPerMin  每分钟最大请求数（0/缺省 = 不限）
//   buildUrl(d, cfg) 拼 URL（cfg 为本 provider 对象，可读取 id/key 等）
//   parse(data) 解析响应 → { hasIcp, icpNumber?, unitName? }
//
// ⚠️ apihz 的 id/key='88888888' 是官方公开 demo 凭据（用户可在设置中覆盖）。
// 该凭据随时可能被上游撤销：撤销后查询将静默失败，且失败结果会被
// failCacheMs=5min 短缓存掩盖，表现为"ICP 检测失效但无报错"。
// 如遇 apihz 持续查询失败，请引导用户在设置页填写自有凭据。
export const ICP_API_CONFIG = {
  cacheTtlMs: 24 * 60 * 60 * 1000, // 域名级缓存 24h
  timeoutMs: 8000,                  // 单源超时
  failCacheMs: 5 * 60 * 1000,       // 全源失败短时缓存，避免重试打爆接口
  providers: [
    {
      name: 'uapis',
      enabled: true,
      needKey: false,
      rateLimitPerMin: 0,
      buildUrl: (domain) => `https://uapis.cn/api/v1/network/icp?domain=${encodeURIComponent(domain)}`,
      // 响应成功：{"code":"200","serviceLicence":"京ICP证030173号","unitName":"...","msg":"query success"}
      // 响应无记录：{"code":"200","serviceLicence":"查询失败","unitName":"查询失败","msg":"查询成功"}（autodesk.com/java.com 等外国站）
      // 注意：uapis 查不到时仍返回 code:200，只是 serviceLicence="查询失败"；必须把"真实备案号"与失败文案区分开，
      // 否则会把无备案的外国站误判 hasIcp:true，再经规则三步骤 1.5 直接放行，造成漏检。
      parse: (data) => {
        const lic = data && typeof data.serviceLicence === 'string' ? data.serviceLicence.trim() : '';
        // 真实备案号必含「ICP备」或「ICP证」（如"京ICP备10005211号-8"可带分主体序号后缀）；
        // "查询失败"/空 不含该标记，一律视为无备案
        const isRealIcp = /ICP[备证]/.test(lic);
        if (data && (data.code === 200 || data.code === '200') && isRealIcp) {
          const unit = (data.unitName && data.unitName !== '查询失败') ? data.unitName : '';
          return { hasIcp: true, icpNumber: lic, unitName: unit };
        }
        return { hasIcp: false };
      }
    },
    {
      name: 'apihz',
      enabled: true,
      needKey: false,        // 公开 demo 凭据默认可用；用户可在设置中覆盖 id/key
      rateLimitPerMin: 10,   // 公开接口限制约 10 次/分钟
      id: '88888888',
      key: '88888888',
      buildUrl: (domain, cfg) => `https://cn.apihz.cn/api/wangzhan/icp.php?id=${cfg.id}&key=${cfg.key}&domain=${encodeURIComponent(domain)}`,
      // 响应成功：{"code":200,"icp":"蜀ICP备...号","unit":"..."}
      // 响应无记录：{"code":400,"msg":"查询失败或没有备案。"}
      // 同样仅当 icp 为真实备案号（含「ICP备/证」且以「号」结尾）才判有备案。
      parse: (data) => {
        const lic = data && typeof data.icp === 'string' ? data.icp.trim() : '';
        const isRealIcp = /ICP[备证]/.test(lic);
        if (data && (data.code === 200 || data.code === '200') && isRealIcp) {
          const unit = (data.unit && data.unit !== '查询失败') ? data.unit : '';
          return { hasIcp: true, icpNumber: lic, unitName: unit };
        }
        return { hasIcp: false };
      }
    }
  ]
};

// ==================== 导出保护（深冻结） ====================
// 所有导出的数组/对象深冻结，import 方不得修改（严格模式下写入会抛 TypeError）。
// 例外：utils/exemptions/icp-exempt.js 的 ICP_EXEMPT_DOMAINS（Set）设计为运行时动态
// 扩充（icp-utils.js registerNonChineseBrandDomains），不属于本文件，不在此冻结。
function deepFreeze(obj) {
  if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
    Object.freeze(obj);
    for (const key of Object.keys(obj)) deepFreeze(obj[key]);
  }
  return obj;
}

deepFreeze(RISK_LEVEL);
deepFreeze(ARCHIVE_EXTENSIONS);
deepFreeze(DOWNLOAD_LINK_KEYWORDS);
deepFreeze(DOWNLOAD_BUTTON_KEYWORDS);
deepFreeze(DOWNLOAD_INTENT_KEYWORDS);
deepFreeze(INTERMEDIATE_PAGE_KEYWORDS);
deepFreeze(FILE_EXTENSIONS);
deepFreeze(EXECUTABLE_EXTENSIONS);
deepFreeze(AI_PAGE_THRESHOLDS);
deepFreeze(PROMO_KEYWORDS);
deepFreeze(FRAMEWORK_HTML_MARKERS);
deepFreeze(FRAMEWORK_RESOURCE_MARKERS);
deepFreeze(MSG_TYPES);
deepFreeze(STORAGE_KEYS);
deepFreeze(UI_KEYS);
deepFreeze(REPORT_TYPES);
deepFreeze(DOWNLOAD_CONFIRM_ACTIONS);
deepFreeze(RESOLVER_TEXT_EXTENSIONS);
deepFreeze(RESOLVER_JSON_EXTENSIONS);
deepFreeze(CJK_RANGES);
deepFreeze(ARCHIVE_MIME_TYPES);
deepFreeze(THEME_VALUES);
deepFreeze(PRESET_LEVELS);
deepFreeze(ADVANCED_ONLY_SECTIONS);
deepFreeze(ICP_API_CONFIG);
