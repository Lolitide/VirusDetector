/**
 * Virus Detector — 全局常量配置
 *
 * 集中管理评分阈值、检测关键词、TLD 模式、消息类型、
 * 存储键名和缓存策略。所有模块通过 import 共用同一份配置。
 *
 * @module constants
 */

// ==================== 版本号（统一入口） ====================
/**
 * 当前扩展版本号，用于 User-Agent 与上报载荷等展示性用途。
 * 注意：更新检测以 chrome.runtime.getManifest().version 为唯一真源，不依赖此常量；
 * 发版时仍需同步修改此处 + manifest.json + README（本常量已与 manifest 脱节过一次，见 v2.5.1）。
 */
export const VERSION = '2.5.1';

// ==================== 评分体系 ====================
/** 触发警告的总分阈值（注入拦截 + 警告窗口 + 图标变红） */
export const SCORE_THRESHOLD = 100;

/** 触发下载确认弹窗的阈值（不注入页面拦截，仅弹窗二次确认） */
export const DOWNLOAD_CONFIRM_THRESHOLD = 80;

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
export const ARCHIVE_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
  '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
  '.tar.bz2', '.tar.xz', '.gz2', '.zst'
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
export const EMOJI_DENSITY_MAX_SCORE = 30;

/** Emoji 密度下阈值（个/千字符），低于此值不加分 */
export const EMOJI_DENSITY_THRESHOLD_LOW = 2.0;

/** Emoji 密度上阈值（个/千字符），高于此值得满分 */
export const EMOJI_DENSITY_THRESHOLD_HIGH = 10.0;

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
  CHECK_WHITELIST: 'CHECK_WHITELIST',
  DOWNLOAD_CONFIRMATION: 'DOWNLOAD_CONFIRMATION',
  GET_DOWNLOAD_BLACKLIST: 'GET_DOWNLOAD_BLACKLIST',
  REMOVE_DOWNLOAD_BLACKLIST: 'REMOVE_DOWNLOAD_BLACKLIST',
  SUBMIT_REPORT: 'SUBMIT_REPORT',
  SETTINGS_UPDATED: 'SETTINGS_UPDATED',
  GET_SETTINGS: 'GET_SETTINGS',
  UPDATE_SETTINGS: 'UPDATE_SETTINGS',
  BULK_UPDATE_WHITELIST: 'BULK_UPDATE_WHITELIST',
  CHECK_UPDATE: 'CHECK_UPDATE',
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
  SSL_CACHE: 'ssl_cache_',
  GLOBAL_SETTINGS: 'global_settings',
  WHITELIST: 'whitelist',
  SITE_BLACKLIST: 'site_blacklist',
  DOWNLOAD_BLACKLIST: 'download_blacklist',
  PENDING_DOWNLOADS: 'pending_downloads',
  USER_REPORTS: 'user_reports',
  UPDATE_INFO: 'update_info'
};

// 缓存有效期（毫秒）
export const CACHE_TTL = 24 * 60 * 60 * 1000;  // 24小时

// ==================== 用户上报 → GitHub Issue ====================
/** Cloudflare Worker 上报代理 URL（部署后替换为实际 URL） */
export const REPORT_API_URL = 'https://virus-detector-report.lolitide.workers.dev/api/report';

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

// ==================== Resource Resolver 配置 ====================
/**
 * Resource Resolver 的运行时参数。
 * 与 background/resource-resolver/config.js 保持同步。
 */

/** Resource Resolver 最大递归深度（0=页面本身，最多向下 N 层） */
export const RESOLVER_MAX_DEPTH = 3;

/** Resource Resolver 整个解析过程最多处理的资源数 */
export const RESOLVER_MAX_TOTAL_RESOURCES = 20;

/** TXT 文件最大下载大小（字节） */
export const RESOLVER_MAX_TXT_SIZE = 256 * 1024; // 256KB

/** 单个资源 fetch 超时（毫秒） */
export const RESOLVER_PER_RESOURCE_TIMEOUT = 2000;

/** Resource Resolver 总超时（毫秒） */
export const RESOLVER_TOTAL_TIMEOUT = 5000;

/** 可执行程序文件扩展名（受 detectNonArchiveFiles 开关控制） */
export const EXECUTABLE_EXTENSIONS = [
  '.exe', '.msi', '.apk', '.pkg', '.appx', '.deb', '.rpm',
  '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
  '.bin', '.run', '.sh', '.dmg'
];

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
export const DOMAIN_AGE_BONUS_MIN_DAYS = 365;

/** 域名年龄减分封顶天数：注册天数 ≥ 此值获得最大减分 */
export const DOMAIN_AGE_BONUS_MAX_DAYS = 730;

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
