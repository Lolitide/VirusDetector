# Virus Detector - 银狐木马检测

> Chrome/Edge 浏览器扩展，实时检测银狐木马（Silver Fox Trojan）钓鱼与仿冒网站。

[![Manifest](https://img.shields.io/badge/Manifest-V3-blue)](https://developer.chrome.com/docs/extensions/mv3/)
[![Version](https://img.shields.io/badge/Version-2.2.4-orange)](https://github.com)

---

## 功能简介

通过 8 项检测对访问的网站进行实时安全评估。当总分达到 100 分阈值时，自动触发红色警告、桌面通知、下载拦截和警告弹窗。

| 规则 | 最高加分 | 检测内容 |
| ---- | -------- | -------- |
| 域名仿冒 | **60** | 5 层递进匹配（子串包含、段级关键词、可疑 TLD、关键词堆叠、编辑距离） |
| 压缩包下载 | **40** | 从可疑站点下载压缩包（`.zip` `.rar` `.7z` 等）自动取消并加分 |
| ICP 备案缺失 | **50** | 对所有网站检测 ICP 备案号（含 beian.gov.cn 等政府链接提取） |
| 链接分析 | **70** | Part A（同页链接/死链/重复链接）+ Part B（下载按钮/压缩包链接） |
| 代码工程化 | **60** | 三信号组合判定（DOM复杂度+框架检测+外部资源），2信号+20，3信号+30；推广页Emoji密度检测最高+30 |
| 域名年龄评分 | **60** | 基于 RDAP 协议（RFC 9083）的 S 型衰减函数计分，新注册域名更可疑 |
| 域名年龄减分 | **-20** | 注册时间长的域名可抵消部分可疑分数（条件：当前分数 ≥ 20） |
| 下载链接跨域 | **20** | 跨域下载 +10，下载链接域名新注册（< 90 天）+10 |

**附加功能**：

- **可信平台白名单** — Wiki / 博客 / 代码托管等 UGC 平台的注册域自动跳过仿冒检测，避免误报
- **用户白名单** — 信任的网站可加入白名单，跳过所有检测
- **官方网站早期退出** — 域名+ICP 均通过检测后自动跳过后续规则
- **下载拦截** — 危险网站自动注入拦截脚本，禁用下载按钮和危险链接
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
│   ├── domain-database.js             # 121 品牌域名数据库 + 仿冒检测（5 层匹配）
│   ├── rdap-client.js                 # RDAP 注册信息查询客户端（IANA 引导文件 + 注册局 RDAP + rdap.ss 备用代理）
│   ├── whois-client.js                # 统一域名查询入口（RDAP 主 + WhoisCX 回退，PSL 域名提取 + 缓存 + 错误归一化）
│   ├── cache-manager.js               # chrome.storage.local 缓存管理（24h TTL）
│   ├── similarity.js                  # SimHash 64 位文本相似度 + 海明距离
│   └── icp-utils.js                   # ICP 备案号正则匹配（覆盖 34 个省级行政区简称）
├── content/
│   └── content-script.js              # 内容脚本 —— 链接采集、ICP 扫描、页面度量采集
├── popup/
│   ├── popup.html                     # 工具栏弹窗 UI
│   ├── popup.css                      # 弹窗样式（深色主题、SVG 图标系统）
│   └── popup.js                       # 弹窗控制逻辑 —— 状态渲染、白名单操作
├── warning/
│   ├── warning.html                   # 独立警告窗口 UI
│   ├── warning.css                    # 警告窗口样式
│   └── warning.js                     # 警告窗口控制 —— 关闭危险页面、跳转安全页面
└── utils/
    ├── constants.js                   # 评分常量、可疑 TLD 模式、下载关键词、阈值配置
    ├── url-utils.js                   # 域名解析、PSL 主域提取、DoH DNS 查询
    ├── messaging.js                   # chrome.runtime 消息通信封装
    └── trusted-platforms.js          # 可信平台白名单 —— UGC 平台跳过仿冒检测
```

### 技术特点

- **零依赖**：纯原生 JavaScript（ES Modules），无需 Node.js 构建
- **Manifest V3**：使用 Service Worker 事件驱动架构
- **通信模型**：Background (Service Worker) ↔ Content Script ↔ Popup 三方消息传递
- **算法**：SimHash 64 位 + Levenshtein 编辑距离用于文本相似度与域名仿冒检测

---

## 实现方式

### 防御策略

#### 1. 域名仿冒检测（规则一 | 60 分）

采用 5 层递进式匹配，任一层命中即判定为仿冒：

```text
策略1   子串包含   → pc-huorong.com.cn 包含 huorong.com → 命中
策略2   段级关键词 → deepseek-go.com 拆分 → "deepseek" 命中品牌关键词
策略3   可疑TLD    → huorong-download.xyz → .xyz 为可疑 TLD + 含品牌关键词
策略3.5 关键词堆叠 → google-google-cn-google.hl.cn → "google" 在段中出现 3 次
策略4   编辑距离   → qq.om 与 qq.com 的 Levenshtein 距离 = 1 → 命中
```

域名数据库覆盖 **119 个**品牌，包含 20 个类别：安全软件、浏览器、即时通讯、输入法、办公、视频、音乐、云存储、AI Chat、下载工具、压缩工具、电商、地图出行、支付、开发者工具、系统工具、游戏平台、游戏加速器、新闻资讯、政务服务。

#### 2. 下载拦截（规则二 | 最高 40 分）

通过 `chrome.downloads.onCreated` 监听下载事件：

- 检测到压缩包文件（含 33 种扩展名）→ 规则二触发
- 若域名已有 >= 30 分嫌疑 → **+40 分**并取消下载
- 弱信号 → **+10 分**（仅记录，不取消）

高危时自动注入拦截脚本到页面：

- 禁用所有含"下载 / Download"文本的按钮和链接
- 拦截指向 `.exe` `.zip` `.rar` `.msi` `.apk` 等危险文件的点击
- 移除 `<a download>` 属性
- 页面顶部注入红色警告横幅
- 使用 `MutationObserver` 持续监控动态加载的按钮（30 秒窗口）

#### 3. ICP 备案号检测（规则三 | 50 分）

对所有网站进行 ICP 备案号检测，使用正则匹配覆盖中国全部 34 个省级行政区简称：

- 完整的 ICP 备案号格式：`{省份}ICP{备|证}{6-8位数字}号`
- 同时识别公安备案号：`{省份}公网安备{10+位数字}号`
- Content Script 通过 6 层扫描获取页面中所有可能包含备案号的文本：footer 元素、ICP/beian 命名元素、底部 30% 区域、所有 `<a>` 链接（含 beian.gov.cn / beian.miit.gov.cn 等政府备案链接）、position:fixed 底部固定栏、TreeWalker 全文本节点遍历（上限 50000 节点）

#### 4. 链接分析（规则四 | 最高 70 分）

Part A（先执行，可叠加）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| A-1 同页链接 | >= 3 个链接指向当前页（完整 URL 完全一致） | +20 |
| A-2 死链 | >= 1 个指向不存在子页面的链接（HEAD 请求验证） | +20 |
| A-3 重复链接 | >= 4 个不同元素指向同一个链接 | +20 |
| A-3 附加 | 该重复链接为下载链接（含 download/down 等关键词） | +10 |

Part B（仅当 Part A 为 0 时执行）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| B-a 下载按钮 | 外链绑定在下载按钮上 | +10 |
| B-b 压缩包链接 | 外链指向压缩包格式文件 | +10 |

#### 5. 代码工程化检测（规则五 | 60 分）

包含两个独立子规则，分数可叠加：

##### 子规则 A：三信号组合判定

前提：页面文本 > 500 字符（排除空白/占位页面）。

- **信号1** — DOM节点数 < 100（页面结构过于简单，不受HTML格式化影响）
- **信号2** — 无主流框架痕迹（HTML标记 + window全局变量双重检测）
- **信号3** — 外部资源去重总数 < 5（脚本+样式+图片+字体+媒体，不含同源资源）

组合判定：3/3 = +30（高度可疑），2/3 = +20（中度可疑），0-1 = 0。

##### 子规则 B：关键词预筛选 + Emoji 密度检测（最高 +30 分）

先通过推广/产品关键词（"下载""产品""软件""download""product""software"等 49 个中英文关键词）预筛选确认页面是否为推广性质，再计算 Emoji 密度并通过分段线性映射加分：

- pageText 长度 < 100 字符 → 跳过（0 分）
- 关键词匹配数 < 阈值（默认 1） → 跳过（0 分，非推广页面）
- 计算密度：`density = (emojiCount / pageText.length) × 1000`（个/千字符）
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

#### 8. 下载链接跨域检测（RDAP 协议 | 最高 20 分）

检测下载文件链接的域名是否与当前页面跨域：

1. **同主域名** → 不加分（0 分）
2. **跨域**（不同主域名）→ +10 分
3. **跨域 + 新注册域名**（`valid_days` < 365 且 `creation_days` < 90）→ 再 +10 分

此规则在下载事件触发时异步执行，与规则二（压缩包下载）协同工作。

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

### 评分体系

```text
规则一  域名仿冒        +60 ──→
规则二  压缩包下载      +40 ──→
规则三  ICP 备案缺失    +50 ──→
规则四  链接分析        +70 ──→  初步总分 ──→ 总分 >= 100 ?
规则五  代码工程化      +60 ──→                ├── YES → 红色徽章 + 桌面通知 + 警告弹窗 + 下载拦截注入
域名年龄评分            +60 ──→                └── NO  → 绿色徽章显示分数
域名年龄减分            -20 ──→
下载链接跨域            +20 ──→

优化：
  - 可信平台白名单：注册域命中 → 规则一自动跳过，避免 UGC 平台误报
  - 规则一 + 规则三均安全 → 跳过规则四/五（官方网站早期退出）
  - 域名年龄减分仅在当前总分 >= 20 时应用（避免低分网站过度减分）
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

12 种消息类型覆盖 Background ↔ Content Script ↔ Popup 三方通信：

| 消息类型 | 方向 | 用途 |
| -------- | ---- | ---- |
| `PAGE_ANALYSIS_RESULT` | Content → Background | 页面分析数据上报 |
| `REQUEST_PAGE_TEXT` | Background → Content | 请求重新采集页面数据 |
| `GET_TAB_STATE` | Popup → Background | 查询当前标签页状态 |
| `ADD_TO_WHITELIST` | Popup → Background | 添加域名到白名单 |
| `REMOVE_FROM_WHITELIST` | Popup → Background | 从白名单移除域名 |
| `CHECK_WHITELIST` | Popup → Background | 查询域名是否在白名单 |

---

## 所需权限

| 权限 | 用途 |
| ---- | ---- |
| `activeTab` | 读取当前活跃标签页信息 |
| `storage` | 持久化评分状态、白名单、缓存 |
| `downloads` | 监听下载事件、取消危险下载 |
| `scripting` | 注入 Content Script 与下载拦截脚本 |
| `alarms` | 定时任务支持 |
| `notifications` | 桌面风险通知 |
| `webNavigation` | 监听页面导航以触发分析 |
| `<all_urls>` | 全部网站覆盖（检测与注入所需） |

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
