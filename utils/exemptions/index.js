/**
 * Virus Detector — 统一豁免名单 (Unified Exemptions)
 * ─────────────────────────────────────────────────────────────────────────
 * 把所有「静态豁免 / 白名单」集中到本文件夹，方便统一维护、避免重复登记。
 *
 * 两类语义不同，请按用途分别填写（不要用同一个域名同时充当两种用途时产生歧义）：
 *
 *   1. ICP_EXEMPT_DOMAINS
 *      外国 / 非中文站点，确定【不需要 ICP 备案】。
 *      → 规则三（ICP 备案）对这类域名直接跳过（中性，不计分）。
 *      典型：google.com、github.com、wikipedia.org、steam 等全球站点，
 *            以及 .edu / .gov / .ac.* / .gov.* 等教育/政府 TLD。
 *
 *   2. TRUSTED_PLATFORMS
 *      Wiki / 代码托管 / 博客 / 文档 / 建站等 UGC 平台。
 *      → 规则一（域名仿冒官网）对这类平台的子页面跳过，
 *        避免把合法的 fandom/github.io/notion 等子页误判为仿冒。
 *      注意：仅跳过仿冒检测，其他安全规则（下载/链接/代码工程化等）仍生效。
 *
 * 说明：
 *   - 用户在「选项页」手动添加的域名白名单（chrome.storage.local）不在本文件，
 *     运行时单独管理，请勿在此登记用户白名单。
 *   - 非中国品牌的官方域名会在启动时由 domain-database 动态并入 ICP_EXEMPT_DOMAINS
 *     （见 icp-utils.registerNonChineseBrandDomains），无需在此手抄。
 *   - 若同一域名同时出现在两个集合，属正常（它既可免 ICP 又是可信平台），
 *     不会出现逻辑冲突；本文件统一维护即可避免「漏改一处」的重复维护问题。
 */

// ==================== 1. ICP 豁免：外国站点（不需要 ICP 备案） ====================
export const ICP_EXEMPT_DOMAINS = new Set([
  // —— 全球科技巨头 ——
  'google.com', 'google.com.hk', 'google.co.jp', 'google.co.uk',
  'youtube.com', 'youtu.be', 'yt.be',
  'microsoft.com', 'live.com', 'outlook.com', 'office.com',
  'apple.com', 'icloud.com', 'mac.com',
  'amazon.com', 'amazon.co.jp', 'amazon.co.uk', 'amazon.de',
  'meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
  'threads.net',

  // —— 社交媒体 / 论坛 ——
  'twitter.com', 'x.com', 't.co',
  'reddit.com', 'redd.it',
  'discord.com', 'discord.gg',
  'telegram.org', 't.me',
  'signal.org',
  'linkedin.com',
  'pinterest.com',
  'tumblr.com',
  'snapchat.com',
  'tiktok.com',
  'quora.com',
  'medium.com',

  // —— 开发者平台 ——
  'github.com', 'github.io',
  'gitlab.com',
  'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com', 'serverfault.com',
  'superuser.com', 'askubuntu.com',
  'npmjs.com', 'npmjs.org',
  'pypi.org', 'python.org',
  'rubygems.org',
  'crates.io',
  'docker.com', 'docker.io',
  'kubernetes.io',
  'sourceforge.net',
  'codepen.io',
  'jsfiddle.net',
  'codesandbox.io',
  'replit.com',
  'vercel.com', 'vercel.app',
  'netlify.com', 'netlify.app',
  'heroku.com', 'herokuapp.com',
  'cloudflare.com', 'cloudflarepages.dev',
  'firebase.google.com', 'firebaseapp.com',
  'jetbrains.com',

  // —— 科研 ——
  'mathworks.com',

  // —— 百科 / 知识 ——
  'wikipedia.org', 'wikimedia.org', 'wikiwand.com',
  'mozilla.org', 'developer.mozilla.org',
  'w3.org', 'w3schools.com',
  'vndb.org',

  // —— 非中国软件 / 工具 ——
  'firefox.com',
  'rarlab.com', 'win-rar.com',
  '7-zip.org',
  'bandisoft.com', 'bandizip.com',
  'cpuid.com',
  'teamviewer.com', 'teamviewer.cn',
  'anydesk.com', 'anydesk.cn',
  'internetdownloadmanager.com',
  'bitcomet.com',
  'v2ex.com',
  'revouninstaller.com', // 纯英文外国软件站，无需 ICP

  // —— 视频 / 流媒体 ——
  'netflix.com',
  'spotify.com',
  'twitch.tv',
  'vimeo.com',
  'dailymotion.com',
  'disneyplus.com',
  'hbomax.com',
  'hulu.com',
  'primevideo.com',

  // —— 电商（非中国）——
  'ebay.com', 'ebay.co.uk',
  'etsy.com',
  'shopify.com', 'myshopify.com',

  // —— 游戏平台 ——
  'steampowered.com', 'steamcommunity.com', 'steam.com',
  'epicgames.com',
  'minecraft.net',
  'ea.com', 'origin.com',
  'ubisoft.com', 'ubisoftconnect.com',
  'roblox.com',
  'gog.com',
  'humblebundle.com',
  'itch.io',
  'nintendo.com',
  'playstation.com',
  'xbox.com',
  'dlsite.com',

  // —— 云服务 / SaaS ——
  'dropbox.com', 'dropboxusercontent.com',
  'box.com',
  'notion.so', 'notion.com',
  'slack.com',
  'zoom.us', 'zoom.com',
  'atlassian.com', 'jira.com', 'confluence.com', 'trello.com',
  'figma.com',
  'canva.com',
  'miro.com',
  'linear.app',
  'airtable.com',
  'typeform.com',
  'surveymonkey.com',
  'mailchimp.com',
  'sendgrid.net',
  'twilio.com',
  'stripe.com',
  'vultr.com',
  'cloudcone.com',

  // —— AI / 研究 ——
  'openai.com', 'chatgpt.com',
  'anthropic.com', 'claude.ai',
  'huggingface.co',
  'kaggle.com',
  'arxiv.org',
  'deepmind.google.com',

  // —— 操作系统 / 发行版 ——
  'ubuntu.com',
  'debian.org',
  'archlinux.org',
  'fedora.org', 'fedoraproject.org',
  'centos.org',
  'kali.org',
  'linux.org',
  'freebsd.org',
  'gnu.org',
  'apache.org',

  // —— 其他常见全球站点 ——
  'archive.org',
  'change.org',
  'kickstarter.com',
  'patreon.com',
  'paypal.com',
  'wix.com',
  'wordpress.com', 'wordpress.org',
  'blogger.com', 'blogspot.com',
  'weebly.com',
  'godaddy.com',
  'namecheap.com',
  'duckduckgo.com',
  'proton.me', 'protonmail.com',
  'mega.nz', 'mega.io',
  'mediafire.com',

  // —— 教育机构（全局匹配 .edu / .edu.cn / .edu.jp 等）——
  'edu',
  'edu.cn',
  'edu.jp',
  'ac.jp',        // 日本学术机构（如 u-tokyo.ac.jp）
  'ac.cn',        // 中国科研机构（如 cas.ac.cn）
  'ac.kr',        // 韩国学术机构
  'ac.uk',        // 英国学术机构
  'ac.th',        // 泰国学术机构

  // —— 政府机构（全局匹配 .gov / .gov.cn 等）——
  'gov',
  'gov.cn',
  'gov.hk',
  'gov.tw',
  'go.jp',        // 日本政府
  'go.kr',        // 韩国政府
  'gov.uk',       // 英国政府
  'gov.au',       // 澳大利亚政府
  'gov.sg',       // 新加坡政府

  // —— 保留/专用域名（不暴露公网，无需 ICP 备案）——
  // 本地/内网专用（RFC 6761/6762/8375，不暴露公网）
  'local',         // RFC 6762: 局域网 mDNS（打印机/NAS/树莓派）
  'localhost',     // RFC 6761: 本机回环（127.0.0.1）
  'home.arpa',     // RFC 8375: 家庭内网
  'internal',      // ICANN 保留: 企业内部网络
  'test',          // RFC 6761: 开发测试
  // 文档/示例专用（RFC 2606/6761，禁止实际使用）
  'example',       // RFC 6761: 文档示例（www.example.com）
  'example.com',   // RFC 2606: 通用示例域名
  'example.net',   // RFC 2606: 通用示例域名
  'example.org',   // RFC 2606: 通用示例域名
  // 反向解析与基础架构
  'arpa',          // 根域: DNS 基础设施
  'in-addr.arpa',  // RFC 1035: IPv4 反向解析
  'ip6.arpa',      // RFC 3596: IPv6 反向解析
]);

// ==================== 2. 可信平台：UGC 平台（规则一仿冒检测跳过） ====================
export const TRUSTED_PLATFORMS = new Set([
  // ---- Wiki 平台 ----
  'fandom.com',
  'wikia.com',
  'wikimedia.org',
  'miraheze.org',
  'wiki.gg',
  'gamepedia.com',

  // ---- 代码托管 Pages ----
  'github.io',
  'gitlab.io',
  'bitbucket.io',
  'sourceforge.io',
  'codeberg.page',

  // ---- PaaS / 静态站点托管 ----
  'netlify.app',
  'vercel.app',
  'herokuapp.com',
  'pages.dev',          // Cloudflare Pages
  'surge.sh',
  'glitch.me',
  'onrender.com',
  'fly.dev',
  'workers.dev',        // Cloudflare Workers
  'deno.dev',

  // ---- 博客与内容平台 ----
  'medium.com',
  'wordpress.com',
  'blogger.com',
  'blogspot.com',
  'tumblr.com',
  'hatenablog.com',
  'fc2.com',
  'livejournal.com',
  'typepad.com',
  'substack.com',
  'ghost.io',
  'hashnode.dev',
  'dev.to',

  // ---- 文档与知识库 ----
  'readthedocs.io',
  'notion.site',
  'gitbook.io',

  // ---- 建站 / 个人页 ----
  'weebly.com',
  'wixsite.com',
  'jimdo.com',
  'strikingly.com',
  'carrd.co',
  'about.me',
  'linktr.ee',
]);
