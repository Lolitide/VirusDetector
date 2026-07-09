/**
 * Virus Detector — 设置 Schema（中央配置权威）
 *
 * 提供所有设置的默认值、校验规则、分区定义和灵敏度预设。
 * settings-schema.js 是唯一的事实来源（Single Source of Truth），
 * options.js 和 service-worker.js 均依赖此文件。
 *
 * @module settings-schema
 */

// ==================== Schema 版本 ====================
/** 用于检测旧版本数据并触发迁移 */
export const SCHEMA_VERSION = 1;

// ==================== 灵敏度预设 ====================
/**
 * 选择非 custom 预设时，预设值覆盖显示但不持久化；
 * 切回 custom 时恢复用户自定义的所有阈值。
 */
export const SENSITIVITY_PRESETS = {
  low: {
    label: '低灵敏度',
    description: '仅检测高风险钓鱼网站，大幅减少误报。适合不希望被打扰的用户。',
    overrides: {
      scoreThreshold: 150,
      downloadConfirmThreshold: 120,
      rule1_score: 50,
      rule2_highScore: 30,
      rule2_lowScore: 5,
      rule3_score: 35,
      rule3_fakeScore: 20,
      rule4a_samePageScore: 10,
      rule4a_deadLinkScore: 10,
      rule4a_duplicateLinkScore: 10,
      rule4b_downloadBtnScore: 5,
      rule4b_fileLinkScore: 5,
      rule4b_archiveLinkScore: 5,
      rule5_fullScore: 20,
      rule5_partialScore: 10,
      domainAge_scoreMax: 40,
      download_blacklistScore: 10,
      download_crossDomainScore: 5,
      download_newDomainScore: 5,
      download_suspicionMultiplier: 1.0,
      download_batchMultiplier: 1.5
    }
  },
  medium: {
    label: '中灵敏度（默认）',
    description: '平衡检测率与误报率，适合大多数用户。',
    overrides: {}  // 空对象表示使用 SETTINGS_DEFAULTS 中的值
  },
  high: {
    label: '高灵敏度',
    description: '最大程度检测可疑网站，误报可能增加。仅推荐有鉴别能力的用户使用。',
    overrides: {
      scoreThreshold: 70,
      downloadConfirmThreshold: 50,
      rule2_highScore: 50,
      rule3_score: 35,
      rule3_fakeScore: 25,
      rule4a_deadLinkScore: 30,
      rule4a_samePageScore: 30,
      rule4a_duplicateLinkScore: 30,
      rule4a_downloadBonus: 15,
      rule4b_downloadBtnScore: 15,
      rule4b_archiveLinkScore: 15,
      rule5_fullScore: 40,
      rule5_partialScore: 30,
      domainAge_scoreMax: 80,
      download_crossDomainScore: 15,
      download_newDomainScore: 15,
      download_blacklistScore: 30,
      download_suspicionMultiplier: 2.0,
      download_batchMultiplier: 2.5,
      download_creationDaysThreshold: 180
    }
  },
  custom: {
    label: '自定义',
    description: '手动配置每项检测参数，完全自主控制。',
    overrides: {}
  }
};

// ==================== 设置默认值 ====================
export const SETTINGS_DEFAULTS = {
  // === 常规设置 (basic) ===
  sensitivityPreset: 'medium',
  theme: 'dark',
  desktopNotifications: true,
  showWarningWindow: true,
  showDetectionDetails: true,

  // === 检测规则开关 (basic) ===
  rule1Enabled: true,
  rule2Enabled: true,
  rule3Enabled: true,
  rule4Enabled: true,
  rule5Enabled: true,
  downloadInjection: true,

  // === 评分阈值 (advanced) ===
  scoreThreshold: 100,
  downloadConfirmThreshold: 80,
  rule1_score: 60,
  rule2_highScore: 40,
  rule2_lowScore: 10,
  rule2_domainSuspicionThreshold: 30,
  rule2_proactiveMax: 30,
  rule2_perHighRisk: 10,
  rule2_perLowRisk: 5,
  rule2_trustedPlatformScore: 3,
  rule2_hijackScore: 30,
  rule2_batchThreshold: 3,
  rule2_batchMultiplier: 2.0,
  rule2_suspicionMultiplier: 1.5,
  rule3_score: 50,
  rule3_fakeScore: 30,
  rule4a_samePageScore: 20,
  rule4a_deadLinkScore: 20,
  rule4a_duplicateLinkScore: 20,
  rule4a_downloadBonus: 10,
  rule4b_downloadBtnScore: 10,
  rule4b_fileLinkScore: 10,
  rule4b_archiveLinkScore: 10,
  rule5_fullScore: 30,
  rule5_partialScore: 20,
  domainAge_scoreMax: 60,
  domainAge_decayA: 2.2,
  domainAge_decayB: 1.9,
  domainAgeBonus_max: 20,
  domainAgeBonus_scoreThreshold: 20,
  domainAgeBonus_minDays: 365,
  domainAgeBonus_maxDays: 730,

  // === 下载检测 (advanced) ===
  detectNonArchiveFiles: false,
  hijackDetection: true,
  download_crossDomainScore: 10,
  download_newDomainScore: 10,
  download_blacklistScore: 20,
  download_validDaysThreshold: 365,
  download_creationDaysThreshold: 90,
  download_blacklistMaxEntries: 500,
  download_blacklistCleanupDays: 90,

  // === 链接分析 (advanced) ===
  link_samePageThreshold: 8,
  link_duplicateThreshold: 4,
  link_deadLinkThreshold: 3,
  checkDeadLinks: true,

  // === 代码工程化 (advanced) ===
  code_minDomNodes: 100,
  code_minExternalResources: 5,
  code_minTextLength: 500,
  emojiDensityCheck: true,
  emoji_keywordMatchThreshold: 1,
  emoji_minTextLength: 100,
  emoji_densityMaxScore: 30,
  emoji_densityThresholdLow: 2.0,
  emoji_densityThresholdHigh: 10.0,
  code_signalsFull: 3,
  code_signalsPartial: 2,

  // === 缓存与性能 (advanced) ===
  cache_ttlHours: 24,
  api_timeoutMs: 8000,
  whois_apiIntervalMs: 2100,
  warning_cooldownMs: 5000,

  // === 隐私与数据 (basic) ===
  allowAnonymousReporting: true,
  autoWhitelistFalsePositive: true
};

// ==================== Section 定义（驱动 UI 渲染） ====================
/**
 * 每个 Section 包含：
 *   id          — 唯一标识符
 *   label       — 显示标签（中文）
 *   iconSVG     — 内联 SVG 图标
 *   description — 描述文字
 *   mode        — 'basic' | 'advanced'
 *   groups[]    — 设置分组，每个 group 含 settings[] 列表
 *
 * 每个 Setting 包含：
 *   key         — SETTINGS_DEFAULTS 中的键名
 *   type        — 'boolean' | 'number' | 'select'
 *   label       — 显示标签
 *   desc        — 描述文字
 *   mode        — 'basic' | 'advanced'
 *   min/max/step — number 类型的约束
 *   options     — select 类型的 [{value, label}]
 *   disabledBy  — 条件禁用表达式（如 "!rule1Enabled"），可选
 */

export const SECTIONS = [
  // ========== 1. 常规 ==========
  {
    id: 'general',
    label: '常规',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>',
    description: '基本设置和界面偏好',
    mode: 'basic',
    groups: [
      {
        id: 'general-preset',
        label: '检测灵敏度',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>',
        mode: 'basic',
        settings: [
          {
            key: 'sensitivityPreset', type: 'preset', label: '灵敏度预设',
            desc: '拖拽滑块选择检测灵敏度等级',
            mode: 'basic'
          }
        ]
      },
      {
        id: 'general-ui',
        label: '界面与通知',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
        mode: 'basic',
        settings: [
          {
            key: 'theme', type: 'theme', label: '浅色模式',
            desc: '切换浅色/深色界面主题（设置页和弹窗均生效）',
            mode: 'basic'
          },
          {
            key: 'desktopNotifications', type: 'boolean', label: '桌面通知',
            desc: '检测到危险网站时弹出系统通知',
            mode: 'basic'
          },
          {
            key: 'showWarningWindow', type: 'boolean', label: '警告弹窗',
            desc: '检测到危险网站时弹出全屏警告窗口',
            mode: 'basic'
          },
          {
            key: 'showDetectionDetails', type: 'boolean', label: '显示检测详情',
            desc: '在弹窗中显示每项规则的详细检测结果和分值',
            mode: 'basic'
          }
        ]
      }
    ]
  },

  // ========== 2. 检测规则 ==========
  {
    id: 'detection',
    label: '检测规则',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    description: '启用或禁用各项检测规则',
    mode: 'basic',
    groups: [
      {
        id: 'detection-rules',
        label: '规则开关',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        mode: 'basic',
        settings: [
          {
            key: 'rule1Enabled', type: 'boolean', label: '域名仿冒检测',
            desc: '检测当前域名是否仿冒知名品牌的官方网站',
            mode: 'basic'
          },
          {
            key: 'rule2Enabled', type: 'boolean', label: '压缩包下载检测',
            desc: '检测页面中的压缩包下载链接，识别可疑分发行为',
            mode: 'basic'
          },
          {
            key: 'rule3Enabled', type: 'boolean', label: 'ICP 备案检测',
            desc: '检测网站是否具备合法的 ICP 备案号（中国大陆网站）',
            mode: 'basic'
          },
          {
            key: 'rule4Enabled', type: 'boolean', label: '链接分析',
            desc: '分析页面中链接的异常模式（死链、重复链接、同页跳转）',
            mode: 'basic'
          },
          {
            key: 'rule5Enabled', type: 'boolean', label: '代码工程化检测',
            desc: '检测页面结构和代码质量，识别自动生成的钓鱼页面',
            mode: 'basic'
          },
          {
            key: 'downloadInjection', type: 'boolean', label: '下载拦截注入',
            desc: '在高风险页面注入下载拦截脚本，实时监控下载行为',
            mode: 'basic'
          }
        ]
      },
      {
        id: 'detection-emoji',
        label: 'Emoji 辅助检测',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>',
        mode: 'developer',
        settings: [
          {
            key: 'emojiDensityCheck', type: 'boolean', label: 'Emoji 密度检测',
            desc: '检测页面中 Emoji 的使用密度，钓鱼推广页面常大量使用 Emoji',
            mode: 'advanced'
          }
        ]
      }
    ]
  },

  // ========== 5. 链接分析 ==========
  {
    id: 'links',
    label: '链接分析',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
    description: '链接分析规则的阈值和开关',
    mode: 'hidden',
    groups: [
      {
        id: 'links-thresholds',
        label: '检测阈值',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" y1="20" x2="20" y2="20"/><polyline points="6 20 6 14 10 8 14 14 18 6 18 20"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'link_samePageThreshold', type: 'number', label: '同页链接阈值', desc: '≥此数量触发同页链接检测', min: 2, max: 50, step: 1, mode: 'advanced' },
          { key: 'link_duplicateThreshold', type: 'number', label: '重复链接阈值', desc: '≥此数量触发重复链接检测', min: 2, max: 20, step: 1, mode: 'advanced' },
          { key: 'link_deadLinkThreshold', type: 'number', label: '死链阈值', desc: '≥此数量触发死链检测', min: 0, max: 20, step: 1, mode: 'advanced' },
          { key: 'checkDeadLinks', type: 'boolean', label: '死链主动检测',
            desc: '发送 HEAD 请求验证死链（关闭后仅统计不验证，不影响计分）',
            mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 6. 代码工程化 ==========
  {
    id: 'code',
    label: '代码工程',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
    description: '代码工程化检测的阈值配置',
    mode: 'hidden',
    groups: [
      {
        id: 'code-signals',
        label: '三信号阈值',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'code_minDomNodes', type: 'number', label: '最小 DOM 节点数', desc: 'DOM 节点数低于此值为可疑信号', min: 10, max: 1000, step: 10, mode: 'advanced' },
          { key: 'code_minExternalResources', type: 'number', label: '最小外部资源数', desc: '外部脚本+样式+图片去重总数低于此值为可疑', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'code_minTextLength', type: 'number', label: '最小文本长度', desc: '页面可见文本小于此值不进入检测', min: 0, max: 5000, step: 50, mode: 'advanced' },
          { key: 'code_signalsFull', type: 'number', label: '触顶信号数', desc: '命中≥此信号数 → 高度可疑', min: 1, max: 5, step: 1, mode: 'advanced' },
          { key: 'code_signalsPartial', type: 'number', label: '中等信号数', desc: '命中≥此信号数 → 中度可疑', min: 1, max: 5, step: 1, mode: 'advanced' }
        ]
      },
      {
        id: 'code-emoji',
        label: 'Emoji 密度检测',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'emoji_densityMaxScore', type: 'number', label: 'Emoji 得分上限', desc: 'Emoji 密度检测单次最大加分', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'emoji_densityThresholdLow', type: 'number', label: '密度下阈值(个/千字)', desc: '低于此值不加分', min: 0, max: 20, step: 0.5, mode: 'advanced' },
          { key: 'emoji_densityThresholdHigh', type: 'number', label: '密度上阈值(个/千字)', desc: '高于此值得满分', min: 0, max: 50, step: 0.5, mode: 'advanced' },
          { key: 'emoji_keywordMatchThreshold', type: 'number', label: '关键词匹配阈值', desc: '推广关键词匹配≥此值才进入Emoji检测', min: 0, max: 10, step: 1, mode: 'advanced' },
          { key: 'emoji_minTextLength', type: 'number', label: '最小文本长度', desc: '页面文本少于此值跳过Emoji检测', min: 0, max: 1000, step: 10, mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 7. 域名年龄 ==========
  {
    id: 'domain-age',
    label: '域名年龄',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    description: '域名年龄评分系统的参数调整',
    mode: 'hidden',
    groups: [
      {
        id: 'domainage-main',
        label: 'S 型衰减函数参数',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'domainAge_scoreMax', type: 'number', label: '最大加分', desc: '新注册域名的最大可疑加分', min: 0, max: 200, step: 5, mode: 'advanced' },
          { key: 'domainAge_decayA', type: 'number', label: '衰减速率 a', desc: '公式：MAX/(1+(x/(60×b))^a)，a 越大衰减越快', min: 0.1, max: 10, step: 0.1, mode: 'advanced' },
          { key: 'domainAge_decayB', type: 'number', label: '衰减零点 b', desc: '控制衰减中心位置（单位：60 天）', min: 0.1, max: 10, step: 0.1, mode: 'advanced' }
        ]
      },
      {
        id: 'domainage-bonus',
        label: '域名年龄减分（信任加分）',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'domainAgeBonus_max', type: 'number', label: '最大减分', desc: '老域名的最大可疑分数抵消值', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'domainAgeBonus_scoreThreshold', type: 'number', label: '减分触发阈值', desc: '当前可疑总分需≥此值才执行减分', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'domainAgeBonus_minDays', type: 'number', label: '起始天数', desc: '注册天数 < 此值不减分', min: 0, max: 1000, step: 30, mode: 'advanced' },
          { key: 'domainAgeBonus_maxDays', type: 'number', label: '封顶天数', desc: '注册天数 ≥ 此值获得最大减分', min: 0, max: 3650, step: 30, mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 8. 缓存与性能 ==========
  {
    id: 'cache',
    label: '缓存与性能',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    description: '缓存策略、API 超时和时间参数',
    mode: 'hidden',
    groups: [
      {
        id: 'cache-storage',
        label: '缓存策略',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'cache_ttlHours', type: 'number', label: '缓存有效期(小时)', desc: '域名检测结果缓存多久后重新检测', min: 1, max: 168, step: 1, mode: 'advanced' }
        ]
      },
      {
        id: 'cache-api',
        label: 'API 超时与限流',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'api_timeoutMs', type: 'number', label: 'API 请求超时(ms)', desc: 'RDAP/Whois API 请求超时时间', min: 1000, max: 30000, step: 500, mode: 'advanced' },
          { key: 'whois_apiIntervalMs', type: 'number', label: 'Whois 请求间隔(ms)', desc: 'WhoisCX API 最小请求间隔（避免被限流）', min: 1000, max: 10000, step: 100, mode: 'advanced' }
        ]
      },
      {
        id: 'cache-limits',
        label: '容量与限制',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'download_blacklistMaxEntries', type: 'number', label: '黑名单容量', desc: '下载域名黑名单最大条目数', min: 10, max: 2000, step: 50, mode: 'advanced' },
          { key: 'download_blacklistCleanupDays', type: 'number', label: '黑名单过期(天)', desc: '超过此天数无命中自动清理', min: 7, max: 365, step: 7, mode: 'advanced' }
        ]
      },
      {
        id: 'cache-timing',
        label: '时间参数',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        mode: 'hidden',
        settings: [
          { key: 'warning_cooldownMs', type: 'number', label: '警告冷却期(ms)', desc: '同一标签页两次警告之间的最小间隔', min: 1000, max: 30000, step: 500, mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 9. 隐私与数据 ==========
  {
    id: 'privacy',
    label: '隐私与数据',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
    description: '数据收集偏好和隐私设置',
    mode: 'basic',
    groups: [
      {
        id: 'privacy-reporting',
        label: '数据上报',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
        mode: 'basic',
        settings: [
          {
            key: 'allowAnonymousReporting', type: 'boolean', label: '允许匿名上报',
            desc: '允许提交误报和钓鱼确认报告到云端，帮助改进检测准确度',
            mode: 'basic'
          },
          {
            key: 'autoWhitelistFalsePositive', type: 'boolean', label: '自动加白误报',
            desc: '当用户标记为误报时自动将域名加入个人白名单',
            mode: 'basic'
          }
        ]
      },
      {
        id: 'privacy-actions',
        label: '数据管理',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
        mode: 'basic',
        settings: [
          {
            key: '_clearCache', type: 'action', label: '清除检测缓存',
            desc: '清除所有域名检测结果的缓存，下次访问时重新检测',
            mode: 'basic'
          },
          {
            key: '_clearAllData', type: 'action', label: '清除全部数据',
            desc: '清除缓存、白名单、黑名单、上报记录等所有本地数据',
            mode: 'advanced'
          }
        ]
      }
    ]
  },

  // ========== 10. 白名单 ==========
  {
    id: 'whitelist',
    label: '白名单',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 11l2 2 4-4"/></svg>',
    description: '管理信任的域名列表。白名单中的网站将跳过所有安全检测，每行一个域名。',
    mode: 'basic',
    type: 'custom',
    renderFn: '_renderWhitelistSection'
  },

  // ========== 12. 关于 ==========
  {
    id: 'about',
    label: '关于',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    description: '版本信息和项目链接',
    mode: 'basic',
    noCard: true
  },

  // ========== 12. 评分阈值 ==========
  {
    id: 'thresholds',
    label: '评分阈值',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" y1="20" x2="20" y2="20"/><polyline points="6 20 6 14 10 8 14 14 18 6 18 20"/></svg>',
    description: '调整各项检测规则的分值权重和触发阈值',
    mode: 'advanced',
    groups: [
      {
        id: 'thresholds-global',
        label: '全局阈值',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        mode: 'advanced',
        settings: [
          {
            key: 'scoreThreshold', type: 'number', label: '危险警告阈值',
            desc: '总分达到此值触发完整警告流程（图标变红+弹窗+拦截）。默认 100',
            min: 0, max: 500, step: 5, mode: 'advanced'
          },
          {
            key: 'downloadConfirmThreshold', type: 'number', label: '下载确认阈值',
            desc: '总分达到此值触发下载二次确认弹窗。默认 80，应 ≤ 危险警告阈值',
            min: 0, max: 500, step: 5, mode: 'advanced'
          }
        ]
      },
      {
        id: 'thresholds-rule1',
        label: '域名仿冒',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule1_score', type: 'number', label: '域名仿冒分值', desc: '命中域名仿冒时的加分值', min: 0, max: 200, step: 5, mode: 'advanced' }
        ]
      },
      {
        id: 'thresholds-rule2',
        label: '压缩包下载',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule2_highScore', type: 'number', label: '高嫌疑下载分值', desc: '域名已有嫌疑时下载触发', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule2_lowScore', type: 'number', label: '低嫌疑下载分值', desc: '域名无嫌疑时下载触发', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule2_proactiveMax', type: 'number', label: '主动扫描上限', desc: 'Phase A 主动扫描阶段得分上限', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule2_perHighRisk', type: 'number', label: '高危链接基础分', desc: '每个跨域+下载关键词链接', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule2_perLowRisk', type: 'number', label: '中危链接基础分', desc: '每个仅跨域链接', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule2_hijackScore', type: 'number', label: '劫持检测分值', desc: '仿冒站上下载链接指向非官方域名', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule2_domainSuspicionThreshold', type: 'number', label: '域名嫌疑阈值', desc: '域名已有≥此分时触发高嫌疑计分', min: 0, max: 100, step: 5, mode: 'advanced' }
        ]
      },
      {
        id: 'thresholds-rule3',
        label: 'ICP 备案',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule3_score', type: 'number', label: 'ICP 缺失分值', desc: '有中文内容但无备案号', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule3_fakeScore', type: 'number', label: 'ICP 虚假分值', desc: '备案号存在但格式异常/无法核验', min: 0, max: 100, step: 5, mode: 'advanced' }
        ]
      },
      {
        id: 'thresholds-rule4',
        label: '链接分析',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule4a_samePageScore', type: 'number', label: '同页链接分值', desc: '大量链接指向当前页本身', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule4a_deadLinkScore', type: 'number', label: '死链分值', desc: '检测到死链（指向不存在页面）', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule4a_duplicateLinkScore', type: 'number', label: '重复链接分值', desc: '多个元素指向同一链接', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule4a_downloadBonus', type: 'number', label: '下载链接附加分', desc: '重复链接含下载关键词时额外加分', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule4b_downloadBtnScore', type: 'number', label: '下载按钮分值', desc: '外链绑定在下载按钮上', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule4b_fileLinkScore', type: 'number', label: '文件链接分值', desc: '外链指向可执行文件', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'rule4b_archiveLinkScore', type: 'number', label: '压缩包链接分值', desc: '外链指向压缩包格式', min: 0, max: 50, step: 5, mode: 'advanced' }
        ]
      },
      {
        id: 'thresholds-rule5',
        label: '代码工程化',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule5_fullScore', type: 'number', label: '高度可疑分值', desc: '命中 3/3 信号', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'rule5_partialScore', type: 'number', label: '中度可疑分值', desc: '命中 2/3 信号', min: 0, max: 100, step: 5, mode: 'advanced' }
        ]
      },
      {
        id: 'thresholds-domainage',
        label: '域名年龄分值',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'domainAge_scoreMax', type: 'number', label: '最大加分', desc: '域名年龄最大可疑加分', min: 0, max: 200, step: 5, mode: 'advanced' },
          { key: 'domainAge_decayA', type: 'number', label: '衰减速率 a', desc: 'S 型衰减速率，越大衰减越快', min: 0.1, max: 10, step: 0.1, mode: 'advanced' },
          { key: 'domainAge_decayB', type: 'number', label: '衰减零点 b', desc: '衰减中心位置（60天/单位）', min: 0.1, max: 10, step: 0.1, mode: 'advanced' },
          { key: 'domainAgeBonus_max', type: 'number', label: '最大减分', desc: '老域名对可疑分数的最大抵消值', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'domainAgeBonus_minDays', type: 'number', label: '减分起始天数', desc: '注册天数 < 此值不减分', min: 0, max: 1000, step: 30, mode: 'advanced' },
          { key: 'domainAgeBonus_maxDays', type: 'number', label: '减分封顶天数', desc: '注册天数 ≥ 此值获得最大减分', min: 0, max: 3650, step: 30, mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 13. 下载检测 ==========
  {
    id: 'download',
    label: '下载检测',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    description: '下载检测相关的阈值和开关',
    mode: 'advanced',
    groups: [
      {
        id: 'download-basic',
        label: '下载检测',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
        mode: 'advanced',
        settings: [
          {
            key: 'detectNonArchiveFiles', type: 'boolean', label: '非压缩包文件检测',
            desc: '检测 .exe、.msi 等可执行文件的下载，不仅限于压缩包',
            mode: 'advanced'
          },
          {
            key: 'hijackDetection', type: 'boolean', label: '官网劫持检测',
            desc: '检测仿冒网站上指向非官方域名的下载链接',
            mode: 'advanced'
          }
        ]
      },
      {
        id: 'download-scoring',
        label: '下载计分参数',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'download_crossDomainScore', type: 'number', label: '跨域基础分', desc: '下载链接与当前页面跨域', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'download_newDomainScore', type: 'number', label: '新域名加分', desc: '下载链接域名注册时间过新', min: 0, max: 50, step: 5, mode: 'advanced' },
          { key: 'download_blacklistScore', type: 'number', label: '黑名单命中分', desc: '下载域名在黑名单中', min: 0, max: 100, step: 5, mode: 'advanced' },
          { key: 'download_validDaysThreshold', type: 'number', label: '有效期阈值(天)', desc: '下载域名剩余有效期低于此值视为可疑', min: 0, max: 3650, step: 30, mode: 'advanced' },
          { key: 'download_creationDaysThreshold', type: 'number', label: '新域名阈值(天)', desc: '下载域名注册天数低于此值视为新域名', min: 0, max: 3650, step: 30, mode: 'advanced' },
          { key: 'rule2_trustedPlatformScore', type: 'number', label: '可信平台降权分', desc: '指向GitHub等知名平台时仅加此分', min: 0, max: 50, step: 1, mode: 'advanced' }
        ]
      },
      {
        id: 'download-batch',
        label: '批量与加权',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'rule2_batchThreshold', type: 'number', label: '批量阈值', desc: '压缩包链接数 ≥ 此值时触发批量加权', min: 1, max: 20, step: 1, mode: 'advanced' },
          { key: 'rule2_batchMultiplier', type: 'number', label: '批量乘数', desc: '批量分发时基础分×此值', min: 1.0, max: 5.0, step: 0.1, mode: 'advanced' },
          { key: 'rule2_suspicionMultiplier', type: 'number', label: '嫌疑加权乘数', desc: '域名已有 ≥30 嫌疑时基础分×此值', min: 1.0, max: 3.0, step: 0.1, mode: 'advanced' }
        ]
      },
      {
        id: 'download-blacklist',
        label: '黑名单管理',
        iconSVG: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        mode: 'developer',
        settings: [
          { key: 'download_blacklistMaxEntries', type: 'number', label: '黑名单容量上限', desc: '最大存储条目数', min: 10, max: 2000, step: 50, mode: 'advanced' },
          { key: 'download_blacklistCleanupDays', type: 'number', label: '黑名单过期天数', desc: '超过此天数无命中的条目自动清理', min: 7, max: 365, step: 7, mode: 'advanced' }
        ]
      }
    ]
  },

  // ========== 14. 下载黑名单 ==========
  {
    id: 'blacklist',
    label: '下载黑名单',
    iconSVG: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    description: '管理已知的恶意下载域名。黑名单中的域名下载链接将被额外加分拦截。',
    mode: 'advanced',
    type: 'custom',
    renderFn: '_renderBlacklistSection'
  }
];

// ==================== 校验函数 ====================
/**
 * 校验并钳制单个设置值
 * @param {string} key
 * @param {*} value
 * @returns {*} 校验后的值（类型转换 + 范围钳制）
 */
export function validateSetting(key, value) {
  const def = SETTINGS_DEFAULTS[key];
  if (def === undefined) return undefined; // 未知键

  switch (typeof def) {
    case 'boolean':
      return Boolean(value);
    case 'number': {
      let num = Number(value);
      if (isNaN(num)) return def;
      // 从 SECTIONS 中查找 min/max
      const setting = findSettingMeta(key);
      if (setting) {
        if (setting.min !== undefined) num = Math.max(setting.min, num);
        if (setting.max !== undefined) num = Math.min(setting.max, num);
      }
      return num;
    }
    case 'string':
      // select 类型：验证是否在 options 中
      if (def === 'medium' || def === 'dark' || def === 'custom') {
        const setting = findSettingMeta(key);
        if (setting && setting.options) {
          const validValues = setting.options.map(o => o.value);
          if (validValues.includes(value)) return value;
          return def;
        }
      }
      return String(value);
    default:
      return value;
  }
}

/**
 * 从 SECTIONS 中查找某个 key 的元数据（用于校验范围）
 */
function findSettingMeta(key) {
  for (const section of SECTIONS) {
    for (const group of section.groups) {
      for (const setting of group.settings) {
        if (setting.key === key) return setting;
      }
    }
  }
  return null;
}
