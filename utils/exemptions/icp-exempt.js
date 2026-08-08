/**
 * Virus Detector — ICP 备案豁免 (ICP-Exempt Domains)
 * ─────────────────────────────────────────────────────────────────────────
 * 豁免层级：**仅跳过规则三（ICP 备案检测）**，其他 7 条规则照常运行。
 *
 * 说明：
 *   - 非中国品牌的官方域名会在启动时由 domain-database 动态并入本集合
 *     （见 icp-utils.registerNonChineseBrandDomains）
 *   - 用户在「选项页」手动添加的域名白名单不在此文件，运行时单独管理。
 *
 * @module icp-exempt
 */

// ==================== ICP 豁免：外国站点（不需要 ICP 备案） ====================
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
  'redhat.com',

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

  // —— 非中国电商 ——
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
