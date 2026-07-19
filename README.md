# Virus Detector - 银狐木马检测

> Chrome/Edge 浏览器扩展，实时检测银狐木马（Silver Fox Trojan）钓鱼与仿冒网站。

[![Manifest](https://img.shields.io/badge/Manifest-V3-blue)](https://developer.chrome.com/docs/extensions/mv3/)
[![Version](https://img.shields.io/badge/Version-2.5.1-orange)](https://github.com)

---

## 功能简介

通过 8 项检测与下载域名黑名单加成对访问的网站进行实时安全评估。当总分达到 100 分阈值时，自动触发红色警告、桌面通知、下载拦截和警告弹窗。

| 规则 | 最高加分 | 检测内容 |
| ---- | -------- | -------- |
| 域名仿冒 | **60** | 4 类匹配策略 + 去连字符二次检测（精确段匹配、子串包含、关键词堆叠、约束编辑距离） |
| 压缩包下载 | **40** | 两阶段检测：Phase A 主动扫描页面跨域压缩包链接（上限 30 分）+ Phase B 实际下载拦截（上限 40 分） |
| ICP 备案缺失 | **50** | 对所有网站检测 ICP 备案号（含 beian.gov.cn 等政府链接提取） |
| 链接分析 | **70** | Part A（同页链接/死链/重复链接）+ Part B（下载按钮/压缩包链接） |
| 代码工程化 | **60** | 结构信号组合判定（DOM复杂度+框架检测+外部资源+异常JS引用），2信号+20，≥3信号+30；推广页Emoji密度检测最高+30 |
| 域名年龄评分 | **60** | 基于 RDAP 协议（RFC 9083）的 S 型衰减函数计分，新注册域名更可疑 |
| 域名年龄减分 | **-20** | 注册时间长的域名可抵消部分可疑分数（条件：当前分数 ≥ 20） |
| 下载链接跨域 | **30** | 跨域下载 +10，下载域名命中黑名单 +20，新注册域名额外 +10 |
| 下载域名黑名单 | **加成** | 用户拦截后跨站免疫，命中 +20，L0 主动扫描阶段额外加权 |

**附加功能**：

- **可信平台白名单** — Wiki / 博客 / 代码托管等 UGC 平台的注册域自动跳过仿冒检测，避免误报
- **用户白名单** — 信任的网站可加入白名单，跳过所有检测
- **官方网站早期退出** — 域名+ICP 均通过检测后自动跳过后续规则
- **下载主动扫描** — 页面加载时扫描所有跨域压缩包链接，提前为可疑网站加风险分
- **下载二次确认** — 压缩包下载被拦截后弹出三选项确认窗口（放行一次 / 信任网站 / 拉黑下载域名）
- **下载拦截注入** — ≥100 分时注入页面级拦截：精准匹配已知压缩包链接 + 视觉禁用下载按钮 + MutationObserver 动态监控
- **下载域名黑名单** — 用户拦截的下载域名跨站免疫，90 天自动清理，500 条容量上限
- **非压缩包检测开关** — 预留设置页接入，可控制是否拦截 `.exe` `.msi` 等可执行文件（默认关闭）
- **更新检测** — 经 Cloudflare Worker 代理查询 GitHub Releases（边缘缓存 + ETag 条件请求，规避 GitHub API 按来源 IP 的速率限制），GitHub API 直连作为回退源；商店渠道安装自动关闭检查，由浏览器商店自动更新
- **阈值分层** — ≥80 分激活下载确认弹窗，≥100 分激活完整防护（注入拦截 + 警告窗口 + 图标变红）
- **警告弹窗** — 独立窗口展示风险详情，支持一键跳转官方网站并关闭危险页面

---

## 安装方式

### Chrome

1. 下载本项目源码或 `git clone`
2. 打开 `chrome://extensions/`
3. 开启右上角「开发者模式」
4. 点击「加载已解压的扩展程序」
5. 选择项目根目录 `VirusDetector/`

### Edge

1. 下载本项目源码或 `git clone`
2. 打开 `edge://extensions/`
3. 开启「开发人员模式」
4. 点击「加载解压缩的扩展」
5. 选择项目根目录 `VirusDetector/`

---

## 项目结构

```text
VirusDetector/
├── manifest.json                      # Manifest V3 扩展清单
├── README.md
├── icons/                             # 盾牌图标（16/32/48/128 px）
├── background/
│   ├── service-worker.js              # 主协调器 —— 导航监听、下载拦截、消息路由、弹窗调度
│   ├── scoring-engine.js              # 多规则评分引擎 —— 综合评估与风险定级
│   ├── domain-database.js             # 119 品牌域名数据库 + 仿冒检测 + 去连字符二次检测
│   ├── download-blacklist.js          # 下载域名黑名单 —— 跨站免疫、90 天自动清理
│   ├── rdap-client.js                 # RDAP 注册信息查询客户端
│   ├── whois-client.js                # 统一域名查询入口（RDAP 主 + WhoisCX 回退）
│   ├── cache-manager.js               # chrome.storage.local 缓存管理（24h TTL）
│   ├── similarity.js                  # 预留文本相似度工具（当前未接入评分链路）
│   ├── icp-utils.js                   # ICP 备案号正则匹配（覆盖 34 个省级行政区简称）
│   └── resource-resolver/
│       ├── index.js                   # Resource Resolver 主调度器 —— BFS 资源树遍历
│       ├── config.js                  # 解析器配置常量（深度/数量/超时/大小限制）
│       ├── resource-graph.js          # ResourceGraph / ResourceNode 数据结构
│       └── resolvers/
│           ├── base-resolver.js       # 解析器基类（可插拔接口）
│           ├── html-resolver.js       # HTML 源码 URL 提取（11 种标签）
│           ├── script-resolver.js     # Inline Script 静态分析（location/fetch/URL 模式）
│           ├── meta-resolver.js       # Meta Refresh 跳转解析
│           ├── txt-resolver.js        # TXT 内容递归解析（TXT→TXT→ZIP 链）
│           ├── redirect-resolver.js   # HTTP 30x 重定向跟随
│           ├── json-resolver.js       # JSON 内容 ZIP URL 提取
│           ├── iframe-resolver.js     # iframe src 解析
│           └── external-script-resolver.js  # 外部 JS 解析（预留，默认关闭）
├── content/
│   ├── navigation-guard.js            # L0 导航守卫 —— document_start 拦截 JS 自动下载
│   └── content-script.js              # 内容脚本 —— 链接采集、ICP 扫描、资源数据采集
├── popup/
│   ├── popup.html                     # 工具栏弹窗 UI
│   ├── popup.css                      # 弹窗样式（深色主题、SVG 图标系统）
│   └── popup.js                       # 弹窗控制逻辑 —— 状态渲染、白名单操作
├── warning/
│   ├── warning.html                   # 独立警告窗口 UI
│   ├── warning.css                    # 警告窗口样式
│   ├── warning.js                     # 警告窗口控制 —— 关闭危险页面、跳转安全页面
│   ├── download-confirm.html          # 下载二次确认窗口 UI
│   ├── download-confirm.css           # 下载确认窗口样式
│   └── download-confirm.js            # 下载确认控制 —— 三选项用户决策
└── utils/
    ├── constants.js                   # 评分常量、阈值配置、黑名单参数
    ├── url-utils.js                   # 域名解析、PSL 主域提取、DoH DNS 查询
    ├── messaging.js                   # chrome.runtime 消息通信封装
    └── trusted-platforms.js          # 可信平台白名单 —— UGC 平台跳过仿冒检测
```

### 技术特点

- **零依赖**：纯原生 JavaScript（ES Modules），无需 Node.js 构建
- **Manifest V3**：使用 Service Worker 事件驱动架构
- **三层递进拦截**：L0 导航守卫（document_start）→ L1 资源解析器（Resource Resolver）→ L2 页面注入拦截（injectBlocker）→ L3 浏览器下载 API 兜底
- **通信模型**：Background (Service Worker) ↔ Content Script ↔ Popup / Warning 页面消息传递
- **算法**：域名仿冒使用精确段匹配、子串包含、关键词堆叠、约束编辑距离；Resource Resolver 使用 BFS 资源树遍历 + 解析器注册表模式
- **抗绕过**：对抗 IDM 等下载器绕过（页面级 click / location / createElement hook），拦截 JS 程式化下载

---

## 实现方式

### 防御策略

#### 1. 域名仿冒检测（规则一 | 60 分）

采用 4 类匹配策略，并对含 `-` / `_` 的域名执行去连字符二次检测；任一策略命中即判定为仿冒：

```text
规则 A   精确段匹配     → deepseek-go.com 拆分为 [deepseek, go, com] → "deepseek" 精确命中
规则 B   标签子串包含   → pc-huorong.com.cn 的标签包含 "huorong" → 命中（关键词 ≥ 5 字符）
规则 C   关键词堆叠     → google-google-cn-google.hl.cn → "google" 在段中出现 ≥ 3 次
规则 D   约束编辑距离   → firefpx.com 与 "firefox" 距离 ≤ 2 且长度差 ≤ 2 → 命中
二次检测 去连字符重试   → team-viewer.us 去除连字符后按 A/B/C 重试
```

域名数据库覆盖 **119 个**品牌，包含 19 个实际使用类别：安全软件、浏览器、即时通讯、输入法、办公、视频、音乐、云存储、AI Chat、下载工具、压缩工具、电商、地图出行、支付、开发者工具、系统工具、游戏平台、游戏加速器、新闻资讯。

#### 2. 压缩包下载检测（规则二 | 最高 40 分）

采用两阶段递进评分 + 阈值分层防御：

**Phase A — 主动扫描（页面加载时，L0）**：

Content Script 扫描页面上所有 `<a>` 标签，识别指向压缩包文件的链接（同域 + 跨域全覆盖）：

- 筛选跨域链接，按风险分类计分：
  - 🔴 高危（跨域 + 下载关键词）：+10/个
  - 🟠 中危（跨域 + 无下载关键词）：+5/个
- **批量加权**：≥3 个链接时基础分 ×2（钓鱼站典型特征）
- **域名嫌疑加权**：其他规则已有 ≥30 分时 ×1.5
- **黑名单加权**：每个命中下载黑名单的链接额外 +10
- **硬上限**：Phase A 主动得分最高 **30 分**

**Phase B — 被动拦截（实际下载时，L3 兜底）**：

通过 `chrome.downloads.onCreated` 监听下载事件：

- 域名已有 ≥30 分嫌疑 → **+40 分**并取消下载
- 弱信号 → **+10 分**

最终得分 = max(Phase A, Phase B)，实现"主动可提前、被动可升级"。

**阈值分层**：

```text
评分 < 80             → 放行（绿色图标）
80 ≤ 评分 < 100       → 取消下载 + 弹出三选项确认窗口（不注入页面拦截）
评分 ≥ 100            → 取消下载 + 确认窗口 + 注入页面级拦截 + 警告弹窗 + 红色图标
```

**页面注入拦截（≥100 分触发）**：

- **精准匹配**：已知压缩包链接精确阻断，给出差异化提示
- **宽泛拦截**：所有危险扩展名（`.exe` `.msi` `.apk` 等）点击即阻断
- **视觉禁用**：下载按钮置灰 + 移除 `href` 属性（防止右键另存为绕过 IDM）
- **容器禁用**：常见下载容器（`.dl-btn` `.down_url` 等）内链接全部禁用
- **移除 `download` 属性**：防止浏览器原生强制下载
- **红色警告横幅**：页面顶部注入醒目风险提示
- **MutationObserver**：持续监控动态加载的下载按钮（30 秒窗口）
- **非压缩包检测开关**：`.exe` `.msi` 等可执行文件是否拦截由 `global_settings` 控制（默认关闭，预留设置页接入）

**下载二次确认弹窗**：

下载被取消后弹出独立窗口，三项选择：

| 选项 | 行为 |
| ---- | ---- |
| 仅此次放行 | 通过 `chrome.downloads.download()` 重新发起下载，不持久化 |
| 信任网站并放行 | 页面域名加入用户白名单 + 清除评分缓存 + 重新发起下载 |
| 拦截并拉黑下载来源 | 下载域名写入黑名单，跨站免疫，不重新发起下载 |

#### 3. ICP 备案号检测（规则三 | 50 分）

对所有网站进行 ICP 备案号检测，使用正则匹配覆盖中国全部 34 个省级行政区简称：

- 完整的 ICP 备案号格式：`{省份}ICP{备|证}{6-12位数字}号`
- 同时识别公安备案号：`{省份}公网安备{10+位数字}号`
- Content Script 通过 6 层扫描获取页面中所有可能包含备案号的文本：footer 元素、ICP/beian 命名元素、底部 30% 区域、所有 `<a>` 链接（含 beian.gov.cn / beian.miit.gov.cn 等政府备案链接）、position:fixed 底部固定栏、TreeWalker 全文本节点遍历（上限 15000 节点）

#### 4. 链接分析（规则四 | 最高 70 分）

Part A（先执行，可叠加）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| A-1 同页链接 | >= 5 个链接指向当前页（完整 URL 完全一致） | +20 |
| A-2 死链 | >= 1 个指向不存在子页面的链接（HEAD 请求验证；自动二次扫描跳过） | +20 |
| A-3 重复链接 | >= 4 个不同元素指向同一个链接 | +20 |
| A-3 附加 | 该重复链接为下载链接（含 download/down 等关键词） | +10 |

Part B（仅当 Part A 为 0 时执行）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| B-a 下载按钮 | 外链绑定在下载按钮上 | +10 |
| B-b 压缩包链接 | 外链指向压缩包格式文件 | +10 |

#### 5. 代码工程化检测（规则五 | 60 分）

包含两个独立子规则，分数可叠加：

##### 子规则 A：结构信号组合判定

前提：页面文本 > 500 字符（排除空白/占位页面）。

- **信号1** — DOM节点数 < 100（页面结构过于简单，不受HTML格式化影响）
- **信号2** — 无主流框架痕迹（优先基于资源 URL、DOM 特征和 HTML 标记检测，不依赖 `window.*` 全局变量）
- **信号3** — 外部资源去重总数 < 5（脚本+样式+图片+字体+媒体，不含同源资源）
- **信号4** — 异常 JS 引用模式（模板化语言包、通用脚本路径等克隆式资源布局）

组合判定：≥3 个结构信号 = +30（高度可疑），2 个结构信号 = +20（中度可疑），0-1 = 0。

##### 子规则 B：关键词预筛选 + Emoji 密度检测（最高 +30 分）

先通过推广/产品关键词（"下载""产品""软件""download""product""software"等 49 个中英文关键词）预筛选确认页面是否为推广性质，再计算 Emoji 密度并通过分段线性映射加分：

- 文本长度 < 100 字符 → 跳过（0 分）
- 关键词匹配数 < 阈值（默认 1） → 跳过（0 分，非推广页面）
- 计算密度：`density = (emojiCount / textLength) × 1000`（个/千字符）。该计算在 Content Script 本地完成，后台只接收计数和密度等派生指标，不接收页面正文。
- 分段映射：density < 2.0 → 0；2.0 ≤ density < 10.0 → `(density - 2) / 8 × 30`；density ≥ 10.0 → 30（封顶）
- Emoji 匹配使用 Unicode 属性转义正则 `/\p{Emoji_Presentation}|\p{Emoji}️/gu`，覆盖肤色修饰符与零宽连接符序列

设计原理：正常页面 Emoji 密度极低，钓鱼/欺诈推广页面常大量使用 Emoji 吸引眼球，关键词预筛避免对非推广页面的误报。

#### 6. 域名年龄评分（RDAP 协议 | 最高 60 分）

通过 IANA RDAP 引导文件 + 注册局 RDAP 服务器（RFC 9083）查询域名的注册日期，计算已注册天数（`creation_days`），使用 S 型衰减函数计分：

- **直连查询**：从 IANA 引导文件获取 TLD 对应的 RDAP 服务器地址，直接查询注册局
- **备用代理**：对于无公开 RDAP 服务的 TLD（如 `.cn`），或直连查询超时/失败时，自动回退到 `rdap.ss` 代理服务，该代理内部通过注册局 WHOIS 获取结构化数据
- **优雅降级**：如代理也查询失败，返回中性结果（`creationDays = -1`），评分引擎按"注册时间未知"处理，不影响检测流程

```text
score = floor(60 / (1 + (x / (60 × b))^a))

其中 x = creation_days（域名已注册天数）
     a = 衰减速率参数（默认 2，越大衰减越快）
     b = 衰减零点参数（默认 1，控制衰减中心位置）
```

新注册域名（x → 0）：分母 → 1，score → 60（最高可疑）。随注册天数增加，分数逐渐衰减至 0。

#### 7. 域名年龄减分（RDAP 协议 | 最高 -20 分）

对于注册时间足够长的域名，通过减分抵消部分由其他规则产生的可疑分数：

| 注册天数 x | 减分分值 |
| ---------- | -------- |
| x < 180 | 0（新域名不减分） |
| 180 ≤ x < 730 | floor(20 × (x - 180) / 550) |
| x ≥ 730 | 20（最大减分） |

**执行条件**：仅当当前可疑总分 ≥ 20 时才应用（避免对低分网站的过度减分）。

#### 8. 下载链接跨域检测（RDAP 协议 | 最高 30 分）

检测下载文件链接的域名是否与当前页面跨域，并集成下载域名黑名单：

1. **同主域名** → 不加分（0 分）
2. **跨域**（不同主域名）→ +10 分
3. **跨域 + 命中下载域名黑名单** → **+20 分**（替代常规 +10）
4. **跨域 + 黑名单 + 新注册域名**（`valid_days` < 365 且 `creation_days` < 90）→ **+30 分**

此规则在下载事件触发时异步执行，与规则二协同工作。下载域名黑名单在 L0 主动扫描阶段也会产生额外加权。

### 可信平台白名单（误报抑制）

为避免对合法 Wiki、代码托管、博客等 UGC 平台的子页面误判为仿冒官网，规则一在执行前会先通过可信平台白名单进行过滤：

- **匹配粒度**：提取 URL 的**注册域**（eTLD+1），例如 `minecraft.fandom.com` → `fandom.com`
- **命中行为**：注册域命中白名单 → **完全跳过规则一**（域名仿冒检测），不添加仿冒分数
- **其他规则**：规则二~五、域名年龄、下载跨域检测等仍正常运行，不因白名单而跳过
- **可扩展**：白名单基于 `Set` 实现 O(1) 查找，新增/移除平台只需修改数组字面量

白名单覆盖 **44 个平台**，按类别包括：

| 类别 | 平台 |
| ---- | ---- |
| Wiki 农场 | fandom.com, wikia.com, wikimedia.org, miraheze.org, wiki.gg, gamepedia.com |
| 代码托管 Pages | github.io, gitlab.io, bitbucket.io, sourceforge.io, codeberg.page |
| PaaS / 静态托管 | netlify.app, vercel.app, herokuapp.com, pages.dev, surge.sh, glitch.me, onrender.com, fly.dev, workers.dev, deno.dev |
| 博客平台 | medium.com, wordpress.com, blogger.com, blogspot.com, tumblr.com, hatenablog.com, fc2.com, livejournal.com, typepad.com, substack.com, ghost.io, hashnode.dev, dev.to |
| 文档 / 知识库 | readthedocs.io, notion.site, gitbook.io |
| 建站 / 个人页 | weebly.com, wixsite.com, jimdo.com, strikingly.com, carrd.co, about.me, linktr.ee |

> **与用户白名单的区别**：用户白名单（弹窗中操作）完全跳过所有 8 项检测规则；可信平台白名单仅跳过规则一（域名仿冒），是一个内置的、面向 UGC 平台的误报抑制机制。

### Resource Resolver — 统一资源解析层

将资源解析与评分彻底解耦的新架构层。Resource Resolver 负责递归解析页面资源树（HTML → TXT → TXT → ZIP 等多级链），输出结构化的 `ResourceGraph`；Rule2（压缩包下载检测）仅消费 Graph 数据进行评分，不承担任何资源解析职责。

**核心能力**：

| 解析器 | 触发条件 | 能力 | 网络请求 |
|--------|---------|------|:---:|
| HtmlResolver | 页面 HTML | 提取 11 种 HTML 标签的 URL（a/link/script/img/iframe/form/source/video/audio/object/embed），相对路径自动转换 | — |
| ScriptResolver | Inline Script | 静态分析 `location.href`、`window.open`、`fetch`、`axios`、`new URL` 等模式，提取 ZIP/EXE 字符串 | — |
| MetaRefreshResolver | `<meta http-equiv="refresh">` | 解析 `content="5;url=..."` 跳转目标 | — |
| TxtResolver | `.txt` 文件 | Fetch 内容 → 正则提取归档 URL → 支持 TXT→TXT 递归（最多 3 层） | ✓ |
| RedirectResolver | HTTP 30x | HEAD 请求跟随重定向，记录完整跳转链 `{from → to, statusCode}` | ✓ |
| JsonResolver | `.json` 文件 | Fetch JSON → 递归遍历值 → 提取归档 URL | ✓ |
| IframeResolver | `<iframe src>` | 标记 iframe 源 URL | — |
| ExternalScriptResolver | 外部 `.js` | （第二阶段预留，默认关闭）Fetch 外部 JS → 提取 URL 模式 | ✓ |

**安全限制**：最大递归深度 3 层、最多处理 20 个资源、TXT 限制 256KB、单资源超时 2s、总超时 5s。任何失败返回中性结果，不阻塞检测流程。

**中间页抓取**（可选，默认关闭）：对于指向 HTML 页面且带下载关键词（「立即下载」「百度网盘」等）的链接，主动 Fetch 该中间页 HTML 内容，提取其中隐藏的 ZIP/RAR/7Z 等归档 URL，实现 **页面 A → 下载页 B → ZIP** 的完整发现链。

### 三层递进下载拦截

针对 IDM 等下载器绕过 `chrome.downloads.onCreated` 的问题，采用从早到晚、从页面到浏览器的分层防御：

```
Timeline:  document_start       page load        content script reports      user clicks
              │                    │                    │                         │
              ▼                    ▼                    ▼                         ▼
         ┌─────────┐     ┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
         │ Layer 0 │     │    Layer 1      │    │    Layer 2       │    │    Layer 3       │
         │ NavGuard│────▶│ ResourceResolver│───▶│ injectBlocker   │───▶│ downloads API    │
         │ (新)    │     │ + ScoringEngine │    │ (增强)           │    │ (现有,兜底)      │
         └─────────┘     └─────────────────┘    └──────────────────┘    └──────────────────┘
```

| 层级 | 名称 | 时机 | 职责 |
|:---:|------|------|------|
| **L0** | Navigation Guard | `document_start`，先于页面 JS | Hook `window.location` setter + `window.open`，拦截 JS 自动跳转/下载到危险文件 |
| **L1** | Resource Resolver + Phase A | Content Script 上报后（~600ms） | 构建 ResourceGraph，发现 TXT→ZIP 链和中间下载页 |
| **L2** | injectBlockerFunc | 评分 ≥50 注入 lightweight，≥80 注入完整版 | Hook `a.click()` + `document.createElement`，拦截页面级下载点击；≥80 增加视觉禁用 + MutationObserver |
| **L3** | chrome.downloads.onCreated | 浏览器下载事件触发时 | 取消下载 + 弹窗确认（IDM 接管时此层失效，由 L0/L2 兜底） |

**分层注入阈值**：
- 评分 ≥50 → 注入 lightweight 拦截器（仅 JS hooks + click 拦截，无视觉禁用）
- 评分 ≥80 → 注入完整拦截器（视觉禁用下载按钮 + MutationObserver + 下载确认弹窗）
- 评分 ≥100 → 完整拦截器 + 红色警告弹窗 + 桌面通知 + 红色图标

### 评分体系

```text
规则一  域名仿冒            +60 ──→
规则二  压缩包下载          +40 ──→   (Phase A 主动扫描 +30 cap, Phase B 被动下载 +40)
规则三  ICP 备案缺失        +50 ──→
规则四  链接分析            +70 ──→  初步总分
规则五  代码工程化          +60 ──→       │
域名年龄评分                +60 ──→       ├── ≥ 100 → 红色徽章 + 桌面通知 + 警告弹窗 + 注入拦截
域名年龄减分                -20 ──→       ├── ≥ 80  → 下载确认弹窗激活（取消下载 + 三选项）
下载链接跨域                +30 ──→       └── < 80  → 绿色徽章显示分数
下载域名黑名单              加成 ──→

优化：
  - 可信平台白名单：注册域命中 → 规则一自动跳过，避免 UGC 平台误报
  - 规则一 + 规则三均安全 → 跳过规则四/五（官方网站早期退出）
  - 域名年龄减分仅在当前总分 >= 20 时应用（避免低分网站过度减分）
  - 下载域名黑名单 → 跨域检测从 +10 提升为 +20，主动扫描阶段额外加权
```

### 插件功能

#### 用户白名单系统

用户可将信任的网站加入白名单：

- 工具栏弹窗中点击「加入白名单」→ 域名被持久化到 `chrome.storage.local`
- 白名单中的网站**完全跳过所有规则检测**
- 工具栏图标右下角显示蓝色对勾徽章
- 弹窗显示绿色对勾 + 提示文字
- 支持一键移出白名单并立即重新触发检测

#### 缓存策略

- 检测结果缓存于 `chrome.storage.local`，TTL = 24 小时
- Content Script 发回新数据时自动绕过缓存更新
- 清除白名单时同步清除对应域名的缓存

#### 弹窗去重

- 同一标签页 5 秒冷却期，避免重复弹窗
- 同域名不重复弹出警告窗口

#### 消息通信

当前实际路由覆盖 10 种主要消息类型，连接 Background ↔ Content Script ↔ Popup ↔ Warning：

| 消息类型 | 方向 | 用途 |
| -------- | ---- | ---- |
| `PAGE_ANALYSIS_RESULT` | Content → Background | 页面分析数据上报 |
| `REQUEST_PAGE_TEXT` | Background → Content | 请求重新采集页面派生指标（不返回正文） |
| `GET_TAB_STATE` | Popup → Background | 查询当前标签页状态 |
| `GET_OFFICIAL_LINK` | 扩展页 → Background | 查询内置品牌库中的官方链接 |
| `CLEAR_TAB_STATE` | 扩展页（预留） → Background | 清除当前标签页检测状态 |
| `ADD_TO_WHITELIST` | Popup → Background | 添加域名到白名单 |
| `REMOVE_FROM_WHITELIST` | Popup → Background | 从白名单移除域名 |
| `CHECK_WHITELIST` | Popup → Background | 查询域名是否在白名单 |
| `DOWNLOAD_CONFIRMATION` | Warning → Background | 下载确认弹窗用户选择 |
| `GET_DOWNLOAD_BLACKLIST` | 管理界面（预留） → Background | 查询下载域名黑名单 |
| `REMOVE_DOWNLOAD_BLACKLIST` | 管理界面（预留） → Background | 移除下载黑名单条目 |

---

## 所需权限

| 权限 | 用途 |
| ---- | ---- |
| `activeTab` | 读取当前活跃标签页信息 |
| `storage` | 持久化评分状态、白名单、缓存 |
| `downloads` | 监听下载事件、取消危险下载 |
| `scripting` | 注入 Content Script 与下载拦截脚本 |
| `alarms` | Manifest 中保留的定时任务权限；当前代码未调用 `chrome.alarms` |
| `notifications` | 桌面风险通知 |
| `webNavigation` | 监听页面导航以触发分析 |
| `http://*/*`, `https://*/*` | 仅覆盖 HTTP/HTTPS 网站，避免在 `file://`、`data:`、`ftp:`、浏览器内部页面等非网页协议上运行 |

---

## 开发说明

### 代码注释规范

所有模块均包含文件级 JSDoc 注释块，说明模块职责与核心逻辑。关键函数包含参数、返回值和使用说明。

### 扩展调试

1. 打开 `chrome://extensions/`
2. 找到本扩展，点击「Service Worker」链接查看后台日志
3. 右键扩展图标 →「检查弹出内容」查看弹窗调试信息

### 图标系统

弹窗 UI 使用内联 SVG 图标系统，定义在 `popup/popup.js` 的 `ICONS` 常量中。所有图标均可通过修改对应 SVG 字符串来更换，无需依赖外部资源。

## Star History

<a href="https://www.star-history.com/#Lolitide/VirusDetector&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Lolitide/VirusDetector&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Lolitide/VirusDetector&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Lolitide/VirusDetector&type=date&legend=top-left" />
 </picture>
</a>
---

## License

MIT
