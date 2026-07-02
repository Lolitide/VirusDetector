/**
 * Virus Detector — 全局常量配置
 *
 * 集中管理评分阈值、检测关键词、TLD 模式、消息类型、
 * 存储键名和缓存策略。所有模块通过 import 共用同一份配置。
 *
 * @module constants
 * @version 2.2.4
 */

// ==================== 评分体系 ====================
/** 触发警告的总分阈值 */
export const SCORE_THRESHOLD = 100;

// 新规则分值
export const SCORE_RULE_1 = 60;              // 规则一：域名仿冒
export const SCORE_RULE_2_HIGH = 40;         // 规则二：压缩包下载（域名已有≥30嫌疑）
export const SCORE_RULE_2_LOW = 10;          // 规则二：压缩包下载（弱信号）
export const SCORE_RULE_3 = 50;             // 规则三：ICP备案号缺失（所有网站）
export const SCORE_RULE_3_FAKE = 30;        // 规则三：ICP备案号存在但无法核验（无政府链接/虚假号码）

// 规则四：链接分析（替代证书检测）
export const SCORE_RULE_4A_SAME_PAGE = 20;      // 规则四A-① ≥3个链接指向当前页本身（完全一致URL）
export const SCORE_RULE_4A_DEAD_LINK = 20;      // 规则四A-② ≥1个死链（指向不存在子页面的链接）
export const SCORE_RULE_4A_DUPLICATE_LINK = 20; // 规则四A-③ ≥4个不同元素指向同一个链接
export const SCORE_RULE_4A_DOWNLOAD_LINK_BONUS = 10; // 规则四A-③附加 该链接是下载链接（含download等字样）
export const SCORE_RULE_4B_DOWNLOAD_BTN = 10;   // 规则四B-a 外链绑在下载按钮上
export const SCORE_RULE_4B_FILE_LINK = 10;      // 规则四B-b 外链指向文件
export const SCORE_RULE_4B_ARCHIVE_LINK = 10;   // 规则四B-b附加 文件是压缩包格式

export const SCORE_RULE_5 = 30;              // 规则五：代码工程化 — 高度可疑（3/3信号）
export const SCORE_RULE_5_PARTIAL = 20;      // 规则五：代码工程化 — 中度可疑（2/3信号）

// 规则二触发阈值：域名嫌疑分达到此值才给高分
export const RULE_2_DOMAIN_SUSPICION_THRESHOLD = 30;

// ==================== 风险等级 ====================
export const RISK_LEVEL = {
  SAFE: 'safe',
  WARNING: 'warning'
};

// ==================== 压缩包扩展名 ====================
export const ARCHIVE_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
  '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
  '.tar.bz2', '.tar.xz', '.gz2', '.zst'
]; 

// ==================== 规则四：链接分析 ====================
// 链接指向当前页的判断阈值
export const SAME_PAGE_LINK_THRESHOLD = 5;    // ≥5个同页链接 → 触发①

// 重复链接检测阈值（规则四A-③）
export const DUPLICATE_LINK_THRESHOLD = 4;    // ≥4个不同元素指向同一个链接 → 触发③

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

// 文件扩展名（规则四B-b）
export const FILE_EXTENSIONS = [
  '.exe', '.msi', '.dmg', '.apk', '.appx', '.deb', '.rpm',
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
  '.iso', '.cab', '.arj', '.lzh', '.z', '.zst',
  '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
  '.bin', '.run', '.sh', '.pkg'
];

// 单独列出压缩包扩展名（用于规则四B-b的附加分）
export const ARCHIVE_EXTENSIONS_RULE4 = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
  '.iso', '.cab', '.arj', '.lzh', '.z', '.zst'
];

// ==================== 代码工程化检测（规则五） ====================
export const AI_PAGE_THRESHOLDS = {
  MIN_DOM_NODES: 100,             // DOM节点数低于此值为可疑（替代HTML行数，不受代码格式化影响）
  MIN_EXTERNAL_RESOURCES: 5,      // 外部资源去重总数（脚本+样式+图片+字体+媒体）低于此值为可疑
  MIN_TEXT_LENGTH: 500,           // 页面文本需大于此值才进入检测
  RULE_5_SIGNALS_FULL: 3,         // 命中3个信号 → 高度可疑 +30
  RULE_5_SIGNALS_PARTIAL: 2       // 命中2个信号 → 中度可疑 +20
};

// ==================== 规则五子规则：关键词预筛选 + Emoji 密度检测 ====================
/**
 * 先通过推广/产品关键词预筛选确定页面是否为推广性质，
 * 再基于 Emoji 密度进行分段线性加分（上限 30 分）。
 *
 * 设计原理：
 *   - 正常页面 Emoji 密度通常极低
 *   - 钓鱼/欺诈推广页面常大量使用 Emoji 吸引眼球
 *   - 关键词预筛避免对非推广页面的误报
 */
/** 推广/产品页面关键词（中英文），用于预筛选 */
export const EMOJI_PROMO_KEYWORDS = [
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
export const EMOJI_DENSITY_MAX_SCORE = 30;

/** Emoji 密度下阈值（个/千字符），低于此值不加分 */
export const EMOJI_DENSITY_THRESHOLD_LOW = 2.0;

/** Emoji 密度上阈值（个/千字符），高于此值得满分 */
export const EMOJI_DENSITY_THRESHOLD_HIGH = 10.0;

// 主流框架标记 — HTML源码字符串匹配用（content-script 使用此列表做全文搜索）
export const FRAMEWORK_HTML_MARKERS = [
  'react', 'vue', 'angular', 'webpack', '__initial_state__',
  '_next/', 'nuxt', 'svelte', 'jquery', 'bootstrap',
  'node_modules', '.jsx', '.tsx', 'data-v-', 'ng-version',
  '__vue__', '__react', 'redux', 'react-dom', 'vue-router',
  'webpackjsonp', '__webpack_require__', '__nuxt', '__next'
];

// ==================== 消息类型 ====================
export const MSG_TYPES = {
  PAGE_ANALYSIS_RESULT: 'PAGE_ANALYSIS_RESULT',
  GET_TAB_STATE: 'GET_TAB_STATE',
  DOWNLOAD_DETECTED: 'DOWNLOAD_DETECTED',
  ICP_SCAN_RESULT: 'ICP_SCAN_RESULT',
  REQUEST_PAGE_TEXT: 'REQUEST_PAGE_TEXT',
  UPDATE_SCORE: 'UPDATE_SCORE',
  GET_OFFICIAL_LINK: 'GET_OFFICIAL_LINK',
  CLEAR_TAB_STATE: 'CLEAR_TAB_STATE',
  INJECT_DOWNLOAD_BLOCKER: 'INJECT_DOWNLOAD_BLOCKER',
  TRIGGER_WARNING_FLOW: 'TRIGGER_WARNING_FLOW',
  ADD_TO_WHITELIST: 'ADD_TO_WHITELIST',
  REMOVE_FROM_WHITELIST: 'REMOVE_FROM_WHITELIST',
  CHECK_WHITELIST: 'CHECK_WHITELIST'
};

// ==================== 存储键 ====================
export const STORAGE_KEYS = {
  TAB_STATE_PREFIX: 'tab_state_',
  DOMAIN_CACHE: 'domain_cache_',
  SSL_CACHE: 'ssl_cache_',
  GLOBAL_SETTINGS: 'global_settings',
  WHITELIST: 'whitelist'
};

// 缓存有效期（毫秒）
export const CACHE_TTL = 24 * 60 * 60 * 1000;  // 24小时

// ==================== RDAP / Whois API 配置 ====================
/** RDAP IANA 引导文件 URL（TLD → RDAP 服务器映射） */
export const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/** WhoisCX API 基础 URL（Whois 回退查询） */
export const WHOIS_API_URL = 'http://api.whoiscx.com/whois/';

/** RDAP 查询结果缓存有效期（毫秒），24小时。缓存由 WhoisClient 共享管理 */
export const WHOIS_CACHE_TTL = 24 * 60 * 60 * 1000;

/** WhoisCX API 请求超时（毫秒） */
export const WHOIS_API_TIMEOUT = 8000;

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
export const DOMAIN_AGE_DECAY_A = 2;

/** 域名年龄衰减零点参数 b（控制衰减中心位置，单位：60天） */
export const DOMAIN_AGE_DECAY_B = 1;

// ==================== 下载链接跨域检测规则 ====================
/** 下载链接与当前页面跨域（不同主域名）基础加分 */
export const SCORE_DOWNLOAD_CROSS_DOMAIN = 10;

/** 下载链接域名过新（新注册）附加加分 */
export const SCORE_DOWNLOAD_NEW_DOMAIN = 10;

/** 下载链接域名剩余有效期阈值（天），低于此值视为可疑 */
export const DOWNLOAD_VALID_DAYS_THRESHOLD = 365;

/** 下载链接域名注册天数阈值（天），低于此值视为新域名 */
export const DOWNLOAD_CREATION_DAYS_THRESHOLD = 90;

// ==================== 域名年龄减分规则 ====================
/**
 * 基于当前页面域名注册天数（creation_days）的减分规则。
 * 仅当当前可疑总分 >= 阈值时才应用，避免对低分网站的过度减分。
 *
 * 减分公式（x = creation_days）：
 *   x < 180           → bonus = 0
 *   180 ≤ x < 730     → bonus = floor(MAX_BONUS * (x - 180) / (730 - 180))
 *   x ≥ 730           → bonus = MAX_BONUS
 */
export const SCORE_DOMAIN_AGE_BONUS_MAX = 20;        // 最大减分分值

/** 域名年龄减分应用阈值：当前可疑分数需 >= 此值才执行减分 */
export const DOMAIN_AGE_BONUS_SCORE_THRESHOLD = 20;

/** 域名年龄减分起始天数：注册天数 < 此值不减分 */
export const DOMAIN_AGE_BONUS_MIN_DAYS = 180;

/** 域名年龄减分封顶天数：注册天数 ≥ 此值获得最大减分 */
export const DOMAIN_AGE_BONUS_MAX_DAYS = 730;
