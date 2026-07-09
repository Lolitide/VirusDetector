# VirusDetector 设置页功能审计报告

> 生成日期：2026-07-08 | 版本：v2.4.2 | 最后更新：2026-07-08 (更新检测 bug 修复)

## 一、总览

对设置页 12 个 Section、60 个设置项逐一审计，对照 `background/service-worker.js` 和 `background/scoring-engine.js` 的实际消费情况。

| 状态 | 数量 | 占比 | 说明 |
|------|------|------|------|
| ✅ 完全实现 | 14 | 23% | UI 设置值被后端读取并生效 |
| ⚠️ 部分实现 | 4 | 7% | 部分代码路径读取，部分用硬编码常量 |
| ❌ 仅 UI（无后端） | 48 | 77% | UI 控件存在但后端用硬编码常量，调整无效 |
| ➖ 仅常量（无 UI） | 4 | — | SETTINGS_DEFAULTS 中有默认值但无对应 UI 控件 |

**核心问题**：`scoring-engine.js` 中的 `s(key, default)` 辅助函数仅覆盖了约 10 个常量（scoreThreshold、domainAge 参数、规则启用开关），其余 ~35 个分值/阈值常量直接从 `constants.js` 静态导入，用户调整设置页对应控件后评分行为不变。

---

## 二、逐 Section 详细审计

### 1. 常规 (basic)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `sensitivityPreset` | select | ❌ | 仅在 options.js UI 层使用。后端不读取此键，预设覆盖不传入评分引擎。各规则分值虽被预设覆盖显示，但评分引擎仍用硬编码常量 |
| `theme` | select | ❌ | 仅 options.js 设置 CSS data-theme。不影响扩展功能 |
| `desktopNotifications` | boolean | ❌ | service-worker.js 中 `triggerWarningFlow()` 始终调用 `chrome.notifications.create()`，未检查此开关 |
| `showWarningWindow` | boolean | ❌ | `triggerWarningFlow()` 始终弹警告窗口，未检查此开关 |
| `showDetectionDetails` | boolean | ❌ | 整个代码库无任何代码读取此设置（update.md P2 计划功能） |

### 2. 检测规则 (basic)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `rule1Enabled` | boolean | ✅ | `s('rule1Enabled', true)` — evaluateSync 第 169 行 |
| `rule2Enabled` | boolean | ✅ | `s('rule2Enabled', true)` — evaluateSync 第 208 行 |
| `rule3Enabled` | boolean | ⚠️ | **仅在已废弃的 evaluate() 中检查，活跃 evaluateSync() 第 173 行未检查** — 关闭无效 |
| `rule4Enabled` | boolean | ✅ | `s('rule4Enabled', true)` — evaluateSync 第 194 行 |
| `rule5Enabled` | boolean | ✅ | `s('rule5Enabled', true)` — evaluateSync 第 195 行 |
| `downloadInjection` | boolean | ❌ | 代码库中无任何代码读取 — `injectDownloadBlocker` 始终调用 |
| `emojiDensityCheck` | boolean | ❌ | `_evaluateRule5()` 始终运行 Emoji 密度检测，未检查此开关 |

### 3. 评分阈值 (advanced)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `scoreThreshold` | number | ✅ | `getEffectiveThreshold('scoreThreshold', ...)` + `s('scoreThreshold', ...)` |
| `downloadConfirmThreshold` | number | ✅ | `getEffectiveThreshold('downloadConfirmThreshold', ...)` |
| `rule1_score` | number | ❌ | 使用硬编码 `SCORE_RULE_1 = 60` |
| `rule2_highScore` | number | ❌ | 使用硬编码 `SCORE_RULE_2_HIGH = 40` |
| `rule2_lowScore` | number | ❌ | 使用硬编码 `SCORE_RULE_2_LOW = 10` |
| `rule2_proactiveMax` | number | ❌ | 使用硬编码 `SCORE_RULE_2_PROACTIVE_MAX = 30` |
| `rule2_perHighRisk` | number | ❌ | 使用硬编码 `SCORE_RULE_2_PER_HIGH_RISK = 10` |
| `rule2_perLowRisk` | number | ❌ | 使用硬编码 `SCORE_RULE_2_PER_LOW_RISK = 5` |
| `rule2_hijackScore` | number | ❌ | 使用硬编码 `SCORE_RULE_2_HIJACK = 30` |
| `rule3_score` | number | ❌ | 使用硬编码 `SCORE_RULE_3 = 50` |
| `rule3_fakeScore` | number | ❌ | 使用硬编码 `SCORE_RULE_3_FAKE = 30` |
| `rule4a_samePageScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4A_SAME_PAGE = 20` |
| `rule4a_deadLinkScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4A_DEAD_LINK = 20` |
| `rule4a_duplicateLinkScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4A_DUPLICATE_LINK = 20` |
| `rule4a_downloadBonus` | number | ❌ | 使用硬编码 `SCORE_RULE_4A_DOWNLOAD_LINK_BONUS = 10` |
| `rule4b_downloadBtnScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4B_DOWNLOAD_BTN = 10` |
| `rule4b_fileLinkScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4B_FILE_LINK = 10` |
| `rule4b_archiveLinkScore` | number | ❌ | 使用硬编码 `SCORE_RULE_4B_ARCHIVE_LINK = 10` |
| `rule5_fullScore` | number | ❌ | 使用硬编码 `SCORE_RULE_5 = 30` |
| `rule5_partialScore` | number | ❌ | 使用硬编码 `SCORE_RULE_5_PARTIAL = 20` |
| `domainAge_scoreMax` | number | ✅ | `s('domainAge_scoreMax', ...)` — evaluateSync + evaluateDomainAgePart |
| `domainAge_decayA` | number | ✅ | `s('domainAge_decayA', ...)` |
| `domainAge_decayB` | number | ✅ | `s('domainAge_decayB', ...)` |
| `domainAgeBonus_max` | number | ⚠️ | evaluateDomainAgePart 读取，但 evaluateSync 和 _evaluateDomainAgeBonus 用硬编码 |
| `domainAgeBonus_minDays` | number | ⚠️ | evaluateSync + evaluateDomainAgePart 读取，但 _evaluateDomainAgeBonus 用硬编码 |
| `domainAgeBonus_maxDays` | number | ⚠️ | 同上 |

### 4. 下载检测 (advanced)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `detectNonArchiveFiles` | boolean | ✅ | service-worker.js 读取并传入 injectBlockerFunc |
| `hijackDetection` | boolean | ❌ | 无代码读取 — 劫持检测始终运行 |
| `download_crossDomainScore` | number | ❌ | 使用硬编码 10 |
| `download_newDomainScore` | number | ❌ | 使用硬编码 10 |
| `download_blacklistScore` | number | ❌ | 使用硬编码 `SCORE_DOWNLOAD_BLACKLIST = 20` |
| `download_validDaysThreshold` | number | ❌ | 使用硬编码 365 |
| `download_creationDaysThreshold` | number | ❌ | 使用硬编码 90 |
| `rule2_batchThreshold` | number | ❌ | 使用硬编码 `SCORE_RULE_2_BATCH_THRESHOLD = 3` |
| `rule2_batchMultiplier` | number | ❌ | 使用硬编码 `SCORE_RULE_2_BATCH_MULTIPLIER = 2.0` |
| `rule2_suspicionMultiplier` | number | ❌ | 使用硬编码 `SCORE_RULE_2_SUSPICION_MULTIPLIER = 1.5` |
| `download_blacklistMaxEntries` | number | ❌ | 使用硬编码 `DOWNLOAD_BLACKLIST_MAX_ENTRIES = 500` |
| `download_blacklistCleanupDays` | number | ❌ | 使用硬编码 `DOWNLOAD_BLACKLIST_CLEANUP_DAYS = 90` |

### 5. 链接分析 (advanced)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `link_samePageThreshold` | number | ❌ | 使用硬编码 `SAME_PAGE_LINK_THRESHOLD = 8` |
| `link_duplicateThreshold` | number | ❌ | 使用硬编码 `DUPLICATE_LINK_THRESHOLD = 4`（content-script 第 186 行直接引用常量） |
| `link_deadLinkThreshold` | number | ❌ | 使用硬编码 `DEAD_LINK_THRESHOLD = 3` |
| `checkDeadLinks` | boolean | ✅ | 由 content-script.js 通过 storage 直接读取并缓存 |

### 6. 代码工程 (advanced)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `code_minDomNodes` | number | ❌ | 使用硬编码 `AI_PAGE_THRESHOLDS.MIN_DOM_NODES = 100` |
| `code_minExternalResources` | number | ❌ | 使用硬编码 `AI_PAGE_THRESHOLDS.MIN_EXTERNAL_RESOURCES = 5` |
| `code_minTextLength` | number | ❌ | 使用硬编码 `AI_PAGE_THRESHOLDS.MIN_TEXT_LENGTH = 500` |
| `code_signalsFull` | number | ❌ | 使用硬编码 `AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_FULL = 3` |
| `code_signalsPartial` | number | ❌ | 使用硬编码 `AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_PARTIAL = 2` |
| `emoji_densityMaxScore` | number | ❌ | 使用硬编码 `EMOJI_DENSITY_MAX_SCORE = 30` |
| `emoji_densityThresholdLow` | number | ❌ | 使用硬编码 `EMOJI_DENSITY_THRESHOLD_LOW = 2.0` |
| `emoji_densityThresholdHigh` | number | ❌ | 使用硬编码 `EMOJI_DENSITY_THRESHOLD_HIGH = 10.0` |

### 7. 域名年龄 (advanced) — 与评分阈值重复的键

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `domainAgeBonus_scoreThreshold` | number | ✅ | `s('domainAgeBonus_scoreThreshold', ...)` |
| 其余键 | — | — | 与 Section 3 重复，状态同上 |

### 8. 缓存与性能 (advanced)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `cache_ttlHours` | number | ❌ | 缓存管理器使用硬编码 `CACHE_TTL = 24*60*60*1000` ms |
| `api_timeoutMs` | number | ❌ | RDAP 用硬编码 `RDAP_REQUEST_TIMEOUT = 10000`；Whois 用硬编码 `WHOIS_API_TIMEOUT = 8000` |
| `whois_apiIntervalMs` | number | ❌ | WhoisClient 用硬编码 `MIN_WHOIS_INTERVAL = 2100` |
| `download_blacklistMaxEntries` | number | ❌ | 与 Section 4 重复，使用硬编码 |
| `download_blacklistCleanupDays` | number | ❌ | 与 Section 4 重复，使用硬编码 |
| `warning_cooldownMs` | number | ❌ | service-worker.js 用硬编码 `WARNING_COOLDOWN_MS = 5000` |

### 9. 隐私与数据 (basic)

| 设置键 | 类型 | 状态 | 问题描述 |
|--------|------|------|---------|
| `allowAnonymousReporting` | boolean | ❌ | 无代码检查 — `_postReportToWorker()` 始终被调用 |
| `autoWhitelistFalsePositive` | boolean | ❌ | 无代码检查 — SU应用处理始终调用 `addToWhitelist()` |
| `_clearCache` | action | ✅ | 处理程序正确清除 domain_cache_ + ssl_cache_ 键 |
| `_clearAllData` | action | ✅ | 处理程序正确清除除 global_settings 外的全部数据 |

---

## 三、update.md 对照

update.md 中与设置页相关的功能及其实现状态：

| update.md 条目 | 优先级 | 设置页状态 |
|---------------|--------|-----------|
| 设置页面：检测详情选择性显示 | P2 | ❌ `showDetectionDetails` 开关已做但后端未读取 |
| 设置页面：深色、浅色模式切换 | P3 | ✅ `theme` 选择器已实现（仅设置页生效） |
| UI界面：更新显示与检测更新 | P1 | ✅ 关于页更新检测卡片已完成 |
| 增加防止官网下载链接被劫持的检测 | P0 | ❌ `hijackDetection` 开关已做但后端未读取（劫持检测始终运行） |
| UI界面：增加用户自主上报的功能 | P2 | ✅ 上报机制已实现（popup + worker 代理） |
| 检测规则：下载链接的域名检测（知名托管降权） | P2 | ✅ TrustedDownloadHosts 已实现 |
| 检测规则：下载链接重复性检测（非线性计分） | P2 | ✅ 已实现 log2 缩放计分 |
| 检测规则：域名年龄分界线调研并重定义函数 | P2 | ✅ S 型衰减函数已实现 |
| 对.edu.cn结尾的域名跳过检测 | P2 | ✅ `_evaluateRule1()` 前缀检查已实现 |
| 检测规则：加入对网站发行商的黑名单检测 | P3 | ❌ 无对应设置入口 |
| 检测规则：未收录软件跳转 GitHub/Baidu 搜索 | P3 | ❌ 无对应设置入口 |

---

## 四、已知 Dead Code

`scoring-engine.js` 第 66 行的 `static async evaluate(ctx)` 方法：
- 调用未定义的 `s()` 辅助函数（第 73、77、98、113、128、134 行），运行时抛出 ReferenceError
- 但此方法实际上从未被调用（service-worker 使用 evaluateSync + evaluateDomainAgePart）
- 建议：删除此方法或补充 `s()` 定义

---

## 五、修复优先级建议

| 优先级 | 范围 | 涉及文件 | 影响 |
|--------|------|---------|------|
| P0 | rule3Enabled 未在 evaluateSync 检查 | scoring-engine.js ~173行 | 用户关闭规则三不生效 |
| P1 | 规则 1-5 分值常量 → s() 包装器 (~15 个) | scoring-engine.js | 灵敏度预设才有实际效果 |
| P2 | 下载检测参数、链接分析阈值、代码工程阈值 (~20 个) | scoring-engine.js | 高级设置页参数生效 |
| P3 | 布尔开关 → service-worker.js (desktopNotifications, showWarningWindow, downloadInjection, allowAnonymousReporting, autoWhitelistFalsePositive) | service-worker.js | 基础设置页开关生效 |
| P4 | 缓存/性能参数 (cache_ttlHours, api_timeoutMs, warning_cooldownMs) | service-worker.js, whois-client.js, cache-manager.js | 性能调优生效 |
