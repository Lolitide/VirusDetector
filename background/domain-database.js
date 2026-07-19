/**
 * Virus Detector — 域名数据库 & 仿冒检测 (Domain Database)
 *
 * 维护中国常用软件/网站的官方域名对照表，并提供基于关键词段匹配的
 * 域名仿冒检测能力。
 *
 * @module domain-database
 *
 * 数据规模：
 *   - 覆盖 20 个类别（安全软件、浏览器、即时通讯、输入法、办公、视频、
 *     音乐、云存储、AI Chat、下载工具、压缩工具、电商、地图出行、支付、
 *     开发者工具、系统工具、游戏平台、游戏加速器、新闻资讯、政务服务）
 *
 *   注：.edu.cn 教育机构域名由 CERNET 管理，攻击者无法注册，已在 _evaluateRule1 中前置跳过，不再纳入数据库。
 *   - 120 条品牌记录
 *
 * 每条记录包含：
 *   - name             品牌名称
 *   - officialDomains  官方域名列表（用于精确匹配和子域名检测）
 *   - correctUrl       正确官网完整 URL（用于警告弹窗中的"前往官网"）
 *   - keywords         品牌关键词（用于段级匹配）
 *   - isChineseBrand   是否为中国品牌（用于 ICP 检测逻辑）
 *
 * 预处理：
 *   - keywordToEntries：关键词 → 品牌记录列表 映射（O(1) 反查）
 *   - sortedKeywords：按长度降序排列（优先匹配长品牌词，避免短词吞掉长词）
 *
 * 仿冒检测策略（5 规则递进 + 去连字符二次检测，命中即返回）：
 *   A. 精确段匹配    → 标签段完全等于品牌关键词（所有长度）
 *   B. 标签子串包含  → 关键词在任一 label 中出现（仅 kw ≥ 5，任意位置不要求边界）
 *   C. 关键词堆叠    → 同一关键词在所有段中精确出现 ≥ 3 次（所有长度）
 *   D. 约束编辑距离  → Levenshtein ≤ 2 且 lenDiff ≤ 2（仅 kw ≥ 6）
 *
 *   去连字符二次检测：若域名含 - 或 _，去除后重新跑 A/B/C 规则，
 *   覆盖连字符插入 + 子串嵌入的复合变形（如 pay-pal-login.hl.cn）。
 */
export const SOFTWARE_CATEGORIES = {
  SECURITY: '安全软件',
  BROWSER: '浏览器',
  IM_SOCIAL: '即时通讯/社交',
  INPUT_METHOD: '输入法',
  OFFICE: '办公软件',
  VIDEO: '视频网站',
  MUSIC: '音乐软件',
  CLOUD_STORAGE: '云存储/网盘',
  AI_CHAT: 'AI Chat',
  DOWNLOAD_TOOL: '下载工具',
  COMPRESSION: '压缩工具',
  E_COMMERCE: '电商',
  MAP_TRAVEL: '地图/出行',
  PAYMENT: '支付',
  DEVELOPER: '开发者工具',
  SYSTEM_TOOL: '系统工具',
  SIMULATOR: '模拟器',
  GAME: '游戏平台',
  GAME_ACCELERATOR: '游戏加速器',
  NEWS_INFO: '新闻/信息'
};

const DOMAIN_DATABASE = [
  // ========== 安全软件 ==========
  {
    name: '360安全卫士',
    officialDomains: ['360.cn', '360.com'],
    correctUrl: 'https://www.360.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['360', '安全卫士', '360safe', '360安全中心'],
    isChineseBrand: true
  },
  {
    name: '360沙箱云',
    officialDomains: ['ata.360.net'],
    correctUrl: 'https://ata.360.net',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['360沙箱云', '360sandbox', '360沙箱'],
    isChineseBrand: true
  },
  {
    name: '火绒安全',
    officialDomains: ['huorong.cn'],
    correctUrl: 'https://www.huorong.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['火绒', 'huorong', '火绒安全'],
    isChineseBrand: true
  },
  {
    name: '腾讯电脑管家',
    officialDomains: ['guanjia.qq.com', 'gj.qq.com'],
    correctUrl: 'https://guanjia.qq.com',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['电脑管家', '腾讯管家', '腾讯电脑管家', 'QQ电脑管家'],
    isChineseBrand: true
  },
  {
    name: '瑞星杀毒',
    officialDomains: ['antivirus.rising.com.cn'],
    correctUrl: 'https://www.rising.com.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['瑞星', 'rising', '瑞星杀毒'],
    isChineseBrand: true
  },
  {
    name: '金山毒霸',
    officialDomains: ['duba.net', 'ijinshan.com'],
    correctUrl: 'https://www.duba.net',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['金山毒霸', '毒霸', 'duba', 'jinshan', 'ijinshan'],
    isChineseBrand: true
  },
  {
    name: '微步在线',
    officialDomains: ['threatbook.cn', 'threatbook.com'],
    correctUrl: 'https://www.threatbook.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['微步', 'threatbook', '微步在线'],
    isChineseBrand: true
  },
// ========== 浏览器 ==========
  {
    name: '360浏览器',
    officialDomains: ['browser.360.cn', 'se.360.cn', 'chromex.360.cn'],
    correctUrl: 'https://browser.360.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['360浏览器', '360极速浏览器', '360安全浏览器'],
    isChineseBrand: true
  },
  {
    name: 'QQ浏览器',
    officialDomains: ['browser.qq.com', 'liulanqi.qq.com'],
    correctUrl: 'https://browser.qq.com',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['QQ浏览器', 'qq浏览器', '腾讯浏览器'],
    isChineseBrand: true
  },
  {
    name: '搜狗浏览器',
    officialDomains: ['ie.sogou.com'],
    correctUrl: 'https://ie.sogou.com',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['搜狗浏览器', 'sogou浏览器', '搜狗高速浏览器'],
    isChineseBrand: true
  },
  {
    name: '猎豹浏览器',
    officialDomains: ['liebao.cn'],
    correctUrl: 'https://www.liebao.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['猎豹浏览器', 'liebao', '猎豹安全浏览器'],
    isChineseBrand: true
  },
  {
    name: '遨游浏览器',
    officialDomains: ['maxthon.cn', 'maxthon.com'],
    correctUrl: 'https://www.maxthon.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['遨游', 'maxthon', '傲游', '傲游浏览器'],
    isChineseBrand: true
  },
  {
    name: '火狐浏览器',
    officialDomains: ['mozilla.org', 'firefox.com'],
    correctUrl: 'https://www.firefox.com/zh-CN/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['火狐', 'Firefox', 'mozilla', 'Mozilla', '火狐浏览器'],
    isChineseBrand: false
  },
  {
    name: '谷歌搜索',
    officialDomains: ['google.com', 'google.cn', 'google.com.hk', 'googlemail.com', 'gmail.com'],
    correctUrl: 'https://www.google.com/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['google', 'Google', '谷歌', 'guge'],
    isChineseBrand: false
  },
  {
    name: '谷歌浏览器',
    officialDomains: ['google.com', 'google.cn'],
    correctUrl: 'https://www.google.cn/chrome/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['Chrome', 'Google Chrome', '谷歌浏览器', 'chrome', 'google', 'Google'],
    isChineseBrand: false
  },
  {
    name: 'Edge浏览器',
    officialDomains: ['microsoft.com'],
    correctUrl: 'https://www.microsoft.com/zh-cn/edge',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['Edge', 'Microsoft Edge', 'edge浏览器'],
    isChineseBrand: false
  },
  {
    name: 'UC浏览器',
    officialDomains: ['uc.cn', 'ucweb.com'],
    correctUrl: 'https://www.uc.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['UC浏览器', 'uc浏览器', 'UC', 'uc', 'ucweb', 'UC Browser'],
    isChineseBrand: true
  },
// ========== 即时通讯/社交 ==========
  {
    name: '微信',
    officialDomains: ['weixin.qq.com', 'wechat.com'],
    correctUrl: 'https://weixin.qq.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['微信', 'weixin', 'WeChat', 'wechat'],
    isChineseBrand: true
  },
  {
    name: 'QQ',
    officialDomains: ['im.qq.com', 'qq.com'],
    correctUrl: 'https://im.qq.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['QQ', '腾讯QQ', 'qq'],
    isChineseBrand: true
  },
  {
    name: '钉钉',
    officialDomains: ['dingtalk.com'],
    correctUrl: 'https://www.dingtalk.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['钉钉', 'dingtalk', 'DingTalk'],
    isChineseBrand: true
  },
  {
    name: '飞书',
    officialDomains: ['feishu.cn', 'larkoffice.com'],
    correctUrl: 'https://www.feishu.cn',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['飞书', 'feishu', 'Lark'],
    isChineseBrand: true
  },
  {
    name: '企业微信',
    officialDomains: ['work.weixin.qq.com'],
    correctUrl: 'https://work.weixin.qq.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['企业微信', 'wework', 'WeWork'],
    isChineseBrand: true
  },
  {
    name: 'TIM',
    officialDomains: ['office.qq.com'],
    correctUrl: 'https://office.qq.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['TIM', '腾讯TIM'],
    isChineseBrand: true
  },
  {
    name: '陌陌',
    officialDomains: ['immomo.com'],
    correctUrl: 'https://www.immomo.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['陌陌', 'momo'],
    isChineseBrand: true
  },
  {
    name: 'Soul',
    officialDomains: ['soulapp.cn'],
    correctUrl: 'https://www.soulapp.cn',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['Soul', 'soulapp'],
    isChineseBrand: true
  },
// ========== 输入法 ==========
  {
    name: '搜狗输入法',
    officialDomains: ['pinyin.sogou.com', 'shurufa.sogou.com'],
    correctUrl: 'https://pinyin.sogou.com',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['搜狗输入法', '搜狗拼音', 'sogou输入法', '搜狗拼音输入法', '搜狗', 'sogou'],
    isChineseBrand: true
  },
  {
    name: '百度输入法',
    officialDomains: ['shurufa.baidu.com', 'ime.baidu.com'],
    correctUrl: 'https://shurufa.baidu.com',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['百度输入法', '百度拼音', '百度拼音输入法', '百度手机输入法'],
    isChineseBrand: true
  },
  {
    name: '讯飞输入法',
    officialDomains: ['srf.xunfei.cn'],
    correctUrl: 'https://srf.xunfei.cn',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['讯飞输入法', '讯飞', 'xunfei', '讯飞语音输入法'],
    isChineseBrand: true
  },
  {
    name: 'QQ输入法',
    officialDomains: ['qq.pinyin.cn'],
    correctUrl: 'https://qq.pinyin.cn',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['QQ输入法', 'qq拼音', 'QQ拼音', 'QQ拼音输入法'],
    isChineseBrand: true
  },
  {
    name: '手心输入法',
    officialDomains: ['xinshuru.com'],
    correctUrl: 'https://www.xinshuru.com',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['手心输入法', '手心'],
    isChineseBrand: true
  },
// ========== 办公软件 ==========
  {
    name: 'WPS Office',
    officialDomains: ['wps.cn', 'wps.com', 'kdocs.cn'],
    correctUrl: 'https://www.wps.cn',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['WPS', '金山办公', 'wps', 'WPS Office', '金山文档', 'KOS'],
    isChineseBrand: true
  },
  {
    name: '腾讯文档',
    officialDomains: ['docs.qq.com'],
    correctUrl: 'https://docs.qq.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['腾讯文档'],
    isChineseBrand: true
  },
  {
    name: '石墨文档',
    officialDomains: ['shimo.im'],
    correctUrl: 'https://shimo.im',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['石墨文档', '石墨', 'shimo'],
    isChineseBrand: true
  },
  {
    name: '永中Office',
    officialDomains: ['yozosoft.com'],
    correctUrl: 'https://www.yozosoft.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['永中', 'yozo', '永中Office', '永中软件'],
    isChineseBrand: true
  },
  {
    name: '网易邮箱',
    officialDomains: ['mail.163.com', 'mail.126.com', 'dashi.163.com'],
    correctUrl: 'https://mail.163.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['网易邮箱大师', '163邮箱', '网易邮箱', '网易免费邮箱', '163邮箱大师'],
    isChineseBrand: true
  },
  {
    name: 'autodesk',
    officialDomains: ['autodesk.com', 'autodesk.com.cn'],
    correctUrl: 'https://www.autodesk.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['autodesk', 'Autodesk', '欧特克', '欧特克公司'],
    isChineseBrand: false
  },
  {
    name: '中望CAD',
    officialDomains: ['zwsoft.com', 'zwsoft.cn'],
    correctUrl: 'https://www.zwsoft.cn',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['中望CAD', '中望软件', 'zwsoft', 'ZWSOFT'],
    isChineseBrand: true
  },
  {
    name: 'blender',
    officialDomains: ['blender.org'],
    correctUrl: 'https://www.blender.org',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['blender', 'Blender', 'Blender Foundation'],
    isChineseBrand: false
  },
  {
    name: '网易有道',
    officialDomains: ['youdao.com', 'dict.youdao.com', 'fanyi.youdao.com', 'top.youdao.com'],
    correctUrl: 'https://www.youdao.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['有道', 'youdao', '网易有道', '有道词典', '有道翻译'],
    isChineseBrand: true
  },
  {
    name: '搜狗翻译',
    officialDomains: ['fanyi.sogou.com'],
    correctUrl: 'https://fanyi.sogou.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['搜狗翻译', 'sogou翻译'],
    isChineseBrand: true
  },
  {
    name: 'UU远程',
    officialDomains: ['uuyc.163.com'],
    correctUrl: 'https://uuyc.163.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['UU远程', 'uu远程', '网易uu', '网易uu远程'],
    isChineseBrand: true
  },
// ========== 视频网站 ==========
  {
    name: '腾讯视频',
    officialDomains: ['v.qq.com'],
    correctUrl: 'https://v.qq.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['腾讯视频', 'qq视频'],
    isChineseBrand: true
  },
  {
    name: '爱奇艺',
    officialDomains: ['iqiyi.com', 'iq.com'],
    correctUrl: 'https://www.iqiyi.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['爱奇艺', 'iqiyi', '奇艺'],
    isChineseBrand: true
  },
  {
    name: '优酷',
    officialDomains: ['youku.com'],
    correctUrl: 'https://www.youku.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['优酷', 'youku'],
    isChineseBrand: true
  },
  {
    name: '哔哩哔哩',
    officialDomains: ['bilibili.com'],
    correctUrl: 'https://www.bilibili.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['哔哩哔哩', 'bilibili', 'B站'],
    isChineseBrand: true
  },
  {
    name: '芒果TV',
    officialDomains: ['mgtv.com'],
    correctUrl: 'https://www.mgtv.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['芒果TV', 'mgtv', '芒果台'],
    isChineseBrand: true
  },
  {
    name: '西瓜视频',
    officialDomains: ['ixigua.com'],
    correctUrl: 'https://www.ixigua.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['西瓜视频', 'ixigua'],
    isChineseBrand: true
  },
  {
    name: '搜狐视频',
    officialDomains: ['tv.sohu.com', 'sohu.com'],
    correctUrl: 'https://tv.sohu.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['搜狐视频', 'sohu视频', '搜狐', 'sohu'],
    isChineseBrand: true
  },
// ========== 音乐软件 ==========
  {
    name: '网易云音乐',
    officialDomains: ['music.163.com'],
    correctUrl: 'https://music.163.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['网易云音乐', '网易云', 'cloudmusic', '163音乐'],
    isChineseBrand: true
  },
  {
    name: 'QQ音乐',
    officialDomains: ['y.qq.com', 'music.qq.com'],
    correctUrl: 'https://y.qq.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['QQ音乐', 'qq音乐', '腾讯音乐', 'qqmusic'],
    isChineseBrand: true
  },
  {
    name: '酷狗音乐',
    officialDomains: ['kugou.com'],
    correctUrl: 'https://www.kugou.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['酷狗', 'kugou', '酷狗音乐'],
    isChineseBrand: true
  },
  {
    name: '酷我音乐',
    officialDomains: ['kuwo.cn'],
    correctUrl: 'https://www.kuwo.cn',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['酷我', 'kuwo', '酷我音乐'],
    isChineseBrand: true
  },
  {
    name: '汽水音乐',
    officialDomains: ['qishui.com', 'qishui.douyin.com'],
    correctUrl: 'https://www.qishui.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['汽水音乐', '汽水', 'qishui', '抖音音乐'],
    isChineseBrand: true
  },
  {
    name: '咪咕音乐',
    officialDomains: ['music.migu.cn', 'migu.cn'],
    correctUrl: 'https://music.migu.cn',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['咪咕音乐', '咪咕', 'migu', '中国移动音乐', 'migumusic'],
    isChineseBrand: true
  },
  {
    name: '苹果音乐',
    officialDomains: ['music.apple.com'],
    correctUrl: 'https://music.apple.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['苹果音乐', 'apple music', 'Apple Music'],
    isChineseBrand: false
  },
// ========== 云存储/网盘 ==========
  {
    name: '百度网盘',
    officialDomains: ['pan.baidu.com'],
    correctUrl: 'https://pan.baidu.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['百度网盘', '百度云盘', 'baidupan', 'baiduyun'],
    isChineseBrand: true
  },
  {
    name: '阿里云盘',
    officialDomains: ['aliyundrive.com', 'alipan.com'],
    correctUrl: 'https://www.aliyundrive.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['阿里云盘', 'aliyundrive', 'alipan'],
    isChineseBrand: true
  },
  {
    name: '腾讯微云',
    officialDomains: ['weiyun.com'],
    correctUrl: 'https://www.weiyun.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['微云', 'weiyun'],
    isChineseBrand: true
  },
  {
    name: '115网盘',
    officialDomains: ['115.com'],
    correctUrl: 'https://www.115.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['115网盘', '115', '115云盘'],
    isChineseBrand: true
  },
  {
    name: '天翼云盘',
    officialDomains: ['cloud.189.cn'],
    correctUrl: 'https://cloud.189.cn',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['天翼云盘', '天翼云', '电信云盘'],
    isChineseBrand: true
  },
  {
    name: '夸克网盘',
    officialDomains: ['pan.quark.cn'],
    correctUrl: 'https://pan.quark.cn',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['夸克网盘', '夸克', '夸克云盘'],
    isChineseBrand: true
  },
  {
    name: '迅雷云盘',
    officialDomains: ['pan.xunlei.com'],
    correctUrl: 'https://pan.xunlei.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['迅雷云盘', '迅雷网盘', '迅雷云'],
    isChineseBrand: true
  },
// ========== AI Chat ==========
  {
    name: '文心一言',
    officialDomains: ['yiyan.baidu.com', 'chat.baidu.com'],
    correctUrl: 'https://yiyan.baidu.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['文心一言', 'yiyan', '文心'],
    isChineseBrand: true
  },
  {
    name: '通义千问',
    officialDomains: ['tongyi.aliyun.com', 'qianwen.aliyun.com', 'qianwen.com', 'dashscope.console.aliyun.com'],
    correctUrl: 'https://tongyi.aliyun.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['通义千问', 'tongyi', 'qianwen', '阿里', '千问', '百炼'],
    isChineseBrand: true
  },
  {
    name: '豆包',
    officialDomains: ['doubao.com', 'volcengine.com'],
    correctUrl: 'https://www.doubao.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['豆包', 'doubao', '字节跳动', 'AI对话', '火山引擎'],
    isChineseBrand: true
  },
  {
    name: '讯飞星火',
    officialDomains: ['xinghuo.xfyun.cn', 'agent.xfyun.cn'],
    correctUrl: 'https://xinghuo.xfyun.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['讯飞星火', 'xinghuo', 'xfyun', '科大讯飞', '星火', '星辰Agent'],
    isChineseBrand: true
  },
  {
    name: '360智脑',
    officialDomains: ['chat.360.com', 'ai.360.com', 'ai.360.cn'],
    correctUrl: 'https://ai.360.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['360智脑', '智脑', '360', 'ai.360'],
    isChineseBrand: true
  },
  {
    name: 'Kimi',
    officialDomains: ['moonshot.cn', 'kimi.com', 'platform.kimi.com', 'platform.kimi.ai', 'kimi.ai'],
    correctUrl: 'https://kimi.moonshot.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['Kimi', 'kimi', 'moonshot', '月之暗面'],
    isChineseBrand: true
  },
  {
    name: 'DeepSeek',
    officialDomains: ['chat.deepseek.com', 'deepseek.com', 'platform.deepseek.com'],
    correctUrl: 'https://chat.deepseek.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['DeepSeek', 'deepseek', '深度求索'],
    isChineseBrand: true
  },
  {
    name: '智谱清言',
    officialDomains: ['chatglm.cn', 'bigmodel.cn', 'open.bigmodel.cn', 'chat.z.ai'],
    correctUrl: 'https://chatglm.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['智谱清言', 'chatglm', '智谱', 'GLM', '清言', 'bigmodel'],
    isChineseBrand: true
  },
  {
    name: 'ChatGPT',
    officialDomains: ['openai.com', 'chatgpt.com', 'platform.openai.com'],
    correctUrl: 'https://chatgpt.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['ChatGPT', 'chatgpt', 'OpenAI', 'openai'],
    isChineseBrand: false
  },
// ========== 下载工具 ==========
  {
    name: '迅雷',
    officialDomains: ['xunlei.com', 'dl.xunlei.com', 'mobile.xunlei.com'],
    correctUrl: 'https://www.xunlei.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['迅雷', 'xunlei', 'Thunder', '迅雷下载'],
    isChineseBrand: true
  },
  {
    name: 'IDM下载器',
    officialDomains: ['internetdownloadmanager.com', 'secure.internetdownloadmanager.com'],
    correctUrl: 'https://www.internetdownloadmanager.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['IDM', 'Internet Download Manager', 'IDM下载工具'],
    isChineseBrand: false
  },
  {
    name: '比特彗星',
    officialDomains: ['bitcomet.com', 'wiki-zh.bitcomet.com'],
    correctUrl: 'https://www.bitcomet.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['比特彗星', 'BitComet', 'bitcomet', 'BitComet下载', 'BT下载客户端'],
    isChineseBrand: false
  },
// ========== 压缩工具 ==========
  {
    name: 'WinRAR',
    officialDomains: ['rarlab.com', 'win-rar.com', 'winrar.com.cn'],
    correctUrl: 'https://www.rarlab.com',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['WinRAR', 'winrar', 'rar'],
    isChineseBrand: false
  },
  {
    name: '7-Zip',
    officialDomains: ['7-zip.org'],
    correctUrl: 'https://www.7-zip.org',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['7-Zip', '7zip', '7z'],
    isChineseBrand: false
  },
  {
    name: 'Bandizip',
    officialDomains: ['bandisoft.com', 'bandizip.com'],
    correctUrl: 'https://www.bandisoft.com',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['Bandizip', 'bandizip', 'bandisoft'],
    isChineseBrand: false
  },
  {
    name: '好压',
    officialDomains: ['haozip.2345.cc'],
    correctUrl: 'https://haozip.2345.cc',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['好压', 'haozip', '2345好压'],
    isChineseBrand: true
  },
  {
    name: '360压缩',
    officialDomains: ['yasuo.360.cn'],
    correctUrl: 'https://yasuo.360.cn',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['360压缩', '360yasuo', '360zip'],
    isChineseBrand: true
  },
// ========== 电商 ==========
  {
    name: '淘宝',
    officialDomains: ['taobao.com', 'tmall.com'],
    correctUrl: 'https://www.taobao.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['淘宝', 'taobao', '天猫', 'tmall', '淘'],
    isChineseBrand: true
  },
  {
    name: '京东',
    officialDomains: ['jd.com'],
    correctUrl: 'https://www.jd.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['京东', 'jd', 'JD', '京东商城'],
    isChineseBrand: true
  },
  {
    name: '拼多多',
    officialDomains: ['pinduoduo.com'],
    correctUrl: 'https://www.pinduoduo.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['拼多多', 'pinduoduo', '拼多多商城'],
    isChineseBrand: true
  },
  {
    name: '美团',
    officialDomains: ['meituan.com'],
    correctUrl: 'https://www.meituan.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['美团', 'meituan', '美团网'],
    isChineseBrand: true
  },
  {
    name: '苏宁易购',
    officialDomains: ['suning.com'],
    correctUrl: 'https://www.suning.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['苏宁', 'suning', '苏宁易购'],
    isChineseBrand: true
  },
  {
    name: '闲鱼',
    officialDomains: ['goofish.com'],
    correctUrl: 'https://www.goofish.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['闲鱼', 'goofish', 'xianyu'],
    isChineseBrand: true
  },
// ========== 地图/出行 ==========
  {
    name: '百度地图',
    officialDomains: ['map.baidu.com'],
    correctUrl: 'https://map.baidu.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['百度地图'],
    isChineseBrand: true
  },
  {
    name: '高德地图',
    officialDomains: ['amap.com', 'gaode.com', 'www.autonavi.com', 'ditu.amap.com', 'mobile.amap.com'],
    correctUrl: 'https://www.amap.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['高德地图', '高德', 'amap', 'gaode', 'autonavi', '高德软件'],
    isChineseBrand: true
  },
  {
    name: '滴滴出行',
    officialDomains: ['didiglobal.com'],
    correctUrl: 'https://www.didiglobal.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['滴滴', 'didi', '滴滴打车', '滴滴快车', 'DiDi'],
    isChineseBrand: true
  },
  {
    name: '腾讯地图',
    officialDomains: ['map.qq.com'],
    correctUrl: 'https://map.qq.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['腾讯地图', 'qq地图'],
    isChineseBrand: true
  },
// ========== 支付 ==========
  {
    name: '支付宝',
    officialDomains: ['alipay.com', 'alipayplus.com', 'open.alipay.com', 'p.alipay.com'],
    correctUrl: 'https://www.alipay.com',
    category: SOFTWARE_CATEGORIES.PAYMENT,
    keywords: ['支付宝', 'alipay', 'zhifubao'],
    isChineseBrand: true
  },
  {
    name: '微信支付',
    officialDomains: ['pay.weixin.qq.com', 'api.mch.weixin.qq.com', 'api2.mch.weixin.qq.com', 'payapp.weixin.qq.com', 'action.weixin.qq.com', 'api.wechatpay.cn', 'api2.wechatpay.cn'],
    correctUrl: 'https://pay.weixin.qq.com',
    category: SOFTWARE_CATEGORIES.PAYMENT,
    keywords: ['微信支付', 'weixin支付', 'wechatpay', 'wechat pay'],
    isChineseBrand: true
  },
  {
    name: '阿里云',
    officialDomains: ['aliyun.com', 'aliyuncs.com', 'alibabacloud.com'],
    correctUrl: 'https://www.aliyun.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['阿里云', 'aliyun', 'alibaba cloud'],
    isChineseBrand: true
  },
  {
    name: '腾讯',
    officialDomains: ['tencent.com', 'tencent.com.cn', 'qq.com'],
    correctUrl: 'https://www.tencent.com',
    category: SOFTWARE_CATEGORIES.IM_SOCIAL,
    keywords: ['腾讯', 'tencent', '腾讯公司', 'Tencent'],
    isChineseBrand: true
  },
  {
    name: '腾讯云',
    officialDomains: ['cloud.tencent.com', 'tencentcloud.com'],
    correctUrl: 'https://cloud.tencent.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['腾讯云', 'tencent云', 'tencent cloud'],
    isChineseBrand: true
  },
  {
    name: '华为云',
    officialDomains: ['huaweicloud.com'],
    correctUrl: 'https://www.huaweicloud.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['华为云', 'huaweicloud', 'HUAWEI CLOUD'],
    isChineseBrand: true
  },
  {
    name: '百度智能云',
    officialDomains: ['cloud.baidu.com', 'intl.cloud.baidu.com'],
    correctUrl: 'https://cloud.baidu.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['百度智能云', 'baidu cloud'],
    isChineseBrand: true
  },
  {
    name: 'CSDN',
    officialDomains: ['csdn.net'],
    correctUrl: 'https://www.csdn.net',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['CSDN', 'csdn', '中国软件开发者网络'],
    isChineseBrand: true
  },
  {
    name: '开源中国',
    officialDomains: ['oschina.net'],
    correctUrl: 'https://www.oschina.net',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['开源中国', 'oschina', 'OSCHINA', 'OSC'],
    isChineseBrand: true
  },
  {
    name: '码云 Gitee',
    officialDomains: ['gitee.com'],
    correctUrl: 'https://gitee.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['Gitee', 'gitee', '码云'],
    isChineseBrand: true
  },
  {
    name: '掘金',
    officialDomains: ['juejin.cn'],
    correctUrl: 'https://juejin.cn',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['掘金', 'juejin', '稀土'],
    isChineseBrand: true
  },
  {
    name: 'V2EX',
    officialDomains: ['v2ex.com'],
    correctUrl: 'https://www.v2ex.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['V2EX', 'v2ex'],
    isChineseBrand: false
  },
  {
    name: 'Github',
    officialDomains: ['github.com', 'github.blog', 'hellogithub.com'],
    correctUrl: 'https://www.github.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['Github', 'GitHub', 'hellogithub', 'github'],
    isChineseBrand: false
  },
  {
    name: 'GitLab',
    officialDomains: ['gitlab.com'],
    correctUrl: 'https://gitlab.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['GitLab', 'gitlab'],
    isChineseBrand: false
  },
// ========== 系统工具 ==========
  {
    name: '驱动精灵',
    officialDomains: ['drivergenius.com'],
    correctUrl: 'https://www.drivergenius.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['驱动精灵', 'drivergenius', '驱动之家', '驱动下载'],
    isChineseBrand: true
  },
  {
    name: '鲁大师',
    officialDomains: ['ludashi.com'],
    correctUrl: 'https://www.ludashi.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['鲁大师', 'ludashi'],
    isChineseBrand: true
  },
  {
    name: 'CPU-Z',
    officialDomains: ['cpuid.com'],
    correctUrl: 'https://www.cpuid.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['CPU-Z', 'cpuz', 'cpuid'],
    isChineseBrand: false
  },
  {
    name: 'ToDesk',
    officialDomains: ['todesk.com', 'todeskai.com'],
    correctUrl: 'https://www.todesk.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['ToDesk', 'todesk', '远程桌面', '远程控制'],
    isChineseBrand: true
  },
  {
    name: '向日葵远程控制',
    officialDomains: ['sunlogin.oray.com', 'oray.com'],
    correctUrl: 'https://sunlogin.oray.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['向日葵', 'sunlogin', 'Oray', 'oray', '远程控制', '贝锐'],
    isChineseBrand: true
  },
  {
    name: 'TeamViewer',
    officialDomains: ['teamviewer.com'],
    correctUrl: 'https://www.teamviewer.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['TeamViewer', 'teamviewer', '远程协助', '远程支持'],
    isChineseBrand: false
  },
  {
    name: 'AnyDesk',
    officialDomains: ['anydesk.com'],
    correctUrl: 'https://anydesk.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['AnyDesk', 'anydesk', '远程桌面', '远程访问'],
    isChineseBrand: false
  },
  {
    name: '联想',
    officialDomains: ['lenovo.com.cn', 'lenovo.com'],
    correctUrl: 'https://www.lenovo.com.cn',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['联想', 'lenovo', 'Lenovo'],
    isChineseBrand: true
  },

  // ========== 模拟器 ==========
  {
    name: '雷电模拟器',
    officialDomains: ['ldmnq.com', 'leidian.co'],
    correctUrl: 'https://www.ldmnq.com',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['雷电模拟器', '雷电', 'LDPlayer', 'ldplayer'],
    isChineseBrand: true
  },
  {
    name: '夜神模拟器',
    officialDomains: ['yeshen.com', 'bignox.com'],
    correctUrl: 'https://www.yeshen.com',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['夜神模拟器', '夜神', 'Nox', 'nox', 'NoxPlayer'],
    isChineseBrand: true
  },
  {
    name: '逍遥模拟器',
    officialDomains: ['memuplay.com', 'xyaz.cn'],
    correctUrl: 'https://www.memuplay.com',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['逍遥模拟器', '逍遥', 'memu'],
    isChineseBrand: true
  },
  {
    name: 'MuMu模拟器',
    officialDomains: ['mumu.163.com'],
    correctUrl: 'https://mumu.163.com',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['MuMu模拟器', 'MuMu', 'mumu', '网易模拟器'],
    isChineseBrand: true
  },
  {
    name: '腾讯手游助手',
    officialDomains: ['syzs.qq.com'],
    correctUrl: 'https://syzs.qq.com',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['腾讯手游助手', '手游助手', 'Tencent Gaming Buddy', '腾讯模拟器'],
    isChineseBrand: true
  },
  {
    name: '蓝叠模拟器',
    officialDomains: ['bluestacks.cn', 'bluestacks.com'],
    correctUrl: 'https://www.bluestacks.cn',
    category: SOFTWARE_CATEGORIES.SIMULATOR,
    keywords: ['蓝叠模拟器', '蓝叠', 'BlueStacks', 'bluestacks'],
    isChineseBrand: true
  },

  // ========== 游戏平台 ==========
  {
    name: '4399小游戏',
    officialDomains: ['4399.com', '4399.cn'],
    correctUrl: 'https://www.4399.com',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['4399', '4399小游戏', '4399游戏'],
    isChineseBrand: true
  },
  {
    name: 'WeGame',
    officialDomains: ['wegame.com.cn', 'wegame.com'],
    correctUrl: 'https://www.wegame.com.cn',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['WeGame', 'wegame', '腾讯游戏平台', 'TGP'],
    isChineseBrand: true
  },
  {
    name: 'Minecraft',
    officialDomains: ['minecraft.net', 'minecraft.wiki', 'mojang.com', 'planetminecraft.com'],
    correctUrl: 'https://www.minecraft.net',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['Minecraft', 'minecraft', '我的世界', 'Mojang'],
    isChineseBrand: false
  },
  {
    name: '蒸汽平台',
    officialDomains: ['steamchina.com', 'steampowered.com', 'steamdb.info'],
    correctUrl: 'https://store.steamchina.com',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['蒸汽平台', 'steamchina', '完美世界', 'Steam中国', 'Steam', 'steam'],
    isChineseBrand: true
  },
  {
    name: '网易游戏',
    officialDomains: ['game.163.com', 'neteasegames.com'],
    correctUrl: 'https://game.163.com',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['网易游戏', 'netease游戏', 'Netease Games'],
    isChineseBrand: true
  },
// ========== 游戏加速器 ==========
  {
    name: '网易UU加速器',
    officialDomains: ['uu.163.com'],
    correctUrl: 'https://uu.163.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['UU加速器', '网易UU', '网易加速器', 'uu accelerator', '网易UU加速器'],
    isChineseBrand: true
  },
  {
    name: '迅游加速器',
    officialDomains: ['xunyou.com'],
    correctUrl: 'https://www.xunyou.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['迅游', 'xunyou', '迅游加速器', '迅游网游加速器'],
    isChineseBrand: true
  },
  {
    name: '雷神加速器',
    officialDomains: ['leigod.com'],
    correctUrl: 'https://www.leigod.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['雷神', 'leigod', 'leishen', '雷神加速器', '雷神网游加速器'],
    isChineseBrand: true
  },
  {
    name: '奇游加速器',
    officialDomains: ['qiyou.cn'],
    correctUrl: 'https://www.qiyou.cn',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['奇游', 'qiyou', '奇游加速器', '奇游电竞加速器'],
    isChineseBrand: true
  },
  {
    name: '月轮加速器',
    officialDomains: ['yuelun.com'],
    correctUrl: 'https://www.yuelun.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['月轮', 'yuelun', '月轮加速器', '月轮网游加速器'],
    isChineseBrand: true
  },
  {
    name: '鲜牛加速器',
    officialDomains: ['xianniu.com'],
    correctUrl: 'https://www.xianniu.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['鲜牛', 'xianniu', '鲜牛加速器', '鲜牛网游加速器'],
    isChineseBrand: true
  },
  {
    name: '薄荷加速器',
    officialDomains: ['jiasu.bohe.com'],
    correctUrl: 'https://jiasu.bohe.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['薄荷', 'bohe', '薄荷加速器', '薄荷BOHE'],
    isChineseBrand: true
  },
  {
    name: '斧牛加速器',
    officialDomains: ['fnjiasu.com'],
    correctUrl: 'https://www.fnjiasu.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['斧牛', 'funiu', '斧牛加速器', 'fnjiasu', '斧牛网游加速器'],
    isChineseBrand: true
  },
  {
    name: '小黑盒加速器',
    officialDomains: ['xiaoheihe.cn', 'acc.xiaoheihe.cn'],
    correctUrl: 'https://acc.xiaoheihe.cn',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['小黑盒', 'xiaoheihe', '黑盒加速器', '小黑盒加速器'],
    isChineseBrand: true
  },
  {
    name: '腾讯网游加速器',
    officialDomains: ['tmgalite.qq.com'],
    correctUrl: 'https://tmgalite.qq.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['腾讯加速器', 'QQ加速器', '腾讯网游加速器'],
    isChineseBrand: true
  },
  {
    name: 'NN加速器',
    officialDomains: ['nn.com'],
    correctUrl: 'https://www.nn.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['NN加速器', 'nnjsq', '雷神NN', 'NN', 'nn.com'],
    isChineseBrand: true
  },
  {
    name: 'AK加速器',
    officialDomains: ['akspeedy.com'],
    correctUrl: 'https://ak.akspeedy.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['AK加速器', 'akjsq', 'AK', 'akspeedy'],
    isChineseBrand: true
  },
  {
    name: 'mitce',
    officialDomains: ['mitce.io', 'mitce.com'],
    correctUrl: 'https://www.mitce.io',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['mitce', 'mitce机场'],
    isChineseBrand: false
  },
  {
    name: 'clash',
    officialDomains: ['clash.wiki', 'clash.guide','clashofficial.com', 'clashverge.dev', 'flclashx.com', 'clashsource.com', 'clash.la'],
    correctUrl: 'https://github.com/clash-version/clash-download',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['clash', 'clash verge', 'clash wiki', 'clash guide', 'clash官方', 'clash下载', 'flclashx', 'FlClash', 'Hiddify Next', 'ClashMi', 'ClashBox'],
    isChineseBrand: false
  },
// ========== 新闻/信息 ==========
  {
    name: '今日头条',
    officialDomains: ['toutiao.com'],
    correctUrl: 'https://www.toutiao.com',
    category: SOFTWARE_CATEGORIES.NEWS_INFO,
    keywords: ['今日头条', '头条', 'toutiao'],
    isChineseBrand: true
  },
  {
    name: '百度',
    officialDomains: ['baidu.com'],
    correctUrl: 'https://www.baidu.com',
    category: SOFTWARE_CATEGORIES.NEWS_INFO,
    keywords: ['百度', 'baidu', 'Baidu'],
    isChineseBrand: true
  },
  {
    name: '知乎',
    officialDomains: ['zhihu.com'],
    correctUrl: 'https://www.zhihu.com',
    category: SOFTWARE_CATEGORIES.NEWS_INFO,
    keywords: ['知乎', 'zhihu'],
    isChineseBrand: true
  },
  {
    name: 'msn',
    officialDomains: ['msn.com','msn.cn'],
    correctUrl: 'https://www.msn.com',
    category: SOFTWARE_CATEGORIES.NEWS_INFO,
    keywords: ['msn', 'MSN'],
    isChineseBrand: false
  }
];

// ==================== 快速索引构建 ====================

/** 域名字符串 → 条目映射（精确匹配） */
const domainToEntry = new Map();

/** 软件名称 → 条目映射 */
const entryByName = new Map();

/** 所有官方域名的扁平集合 */
const allOfficialDomains = new Set();

// ==================== 工具函数 ====================

/**
 * Levenshtein 编辑距离（仅用于规则 D 的长关键词 typo 检测）。
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function _levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = Math.min(
        m[i - 1][j] + 1, m[i][j - 1] + 1,
        m[i - 1][j - 1] + (a[j - 1] === b[i - 1] ? 0 : 1)
      );
    }
  }
  return m[b.length][a.length];
}

/** 最长公共前缀长度 */
function longestCommonPrefix(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i++;
  return i;
}

/** 最长公共后缀长度 */
function longestCommonSuffix(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}

// ==================== detectSpoof 预处理 ====================

/** 关键词 → 品牌记录列表 映射（同一关键词可能属于多个品牌） */
const keywordToEntries = new Map();

/** 所有去重关键词，按长度从长到短排序（优先匹配长品牌词） */
let sortedKeywords = [];

/** 短关键词（length ≤ 3），仅参与精确段匹配和堆叠检测 */
const shortKeywords = new Set();

/** 长关键词（length ≥ 4），参与所有检测规则 */
const longKeywords = new Set();

/**
 * 将字符串按分隔符 `-` 和 `_` 拆分为段数组。
 * 例："deepseek-go" → ["deepseek", "go"]；"google" → ["google"]
 */
function splitIntoSegments(label) {
  return label.split(/[-_]/);
}

function buildIndex() {
  for (const entry of DOMAIN_DATABASE) {
    entryByName.set(entry.name, entry);

    for (const domain of entry.officialDomains) {
      const normalized = domain.replace(/^www\./i, '').toLowerCase();
      domainToEntry.set(normalized, entry);
      allOfficialDomains.add(normalized);
    }
  }

  // 构建关键词 → 品牌 映射
  for (const entry of DOMAIN_DATABASE) {
    for (const keyword of entry.keywords) {
      const kw = keyword.toLowerCase();
      if (!keywordToEntries.has(kw)) {
        keywordToEntries.set(kw, []);
      }
      keywordToEntries.get(kw).push(entry);
    }
  }

  // 收集所有去重关键词，按长度分组
  const allKw = [...keywordToEntries.keys()];
  sortedKeywords = allKw.sort((a, b) => b.length - a.length);

  for (const kw of allKw) {
    if (kw.length <= 3) {
      shortKeywords.add(kw);
    } else {
      longKeywords.add(kw);
    }
  }
}

buildIndex();

// ==================== 公共API ====================

export class DomainDatabase {
  /**
   * 精确匹配：当前域名是否是官方域名
   */
  static findByDomain(hostname) {
    const normalized = hostname.replace(/^www\./i, '').toLowerCase();
    if (domainToEntry.has(normalized)) {
      return domainToEntry.get(normalized);
    }
    // 检查是否是官方域名的子域名
    for (const [domain, entry] of domainToEntry) {
      if (normalized.endsWith('.' + domain)) {
        return entry;
      }
    }
    return null;
  }

  /**
   * 核心方法：检测域名仿冒
   *
   * 5 规则递进 + 去连字符二次检测（按关键词长度从长到短遍历，命中即返回）：
   *   A. 精确段匹配（所有长度）：任一 label 段完全等于关键词
   *   B. 标签子串包含（仅 kw ≥ 5）：关键词在任一 label 中出现，不要求分隔符边界
   *   C. 关键词堆叠（所有长度）：同一关键词在所有段中精确出现 ≥ 3 次
   *   D. 约束编辑距离（仅 kw ≥ 6，dist ≤ 2，lenDiff ≤ 2）：Levenshtein 相似匹配
   *
   *   去连字符二次检测：若域名含 - 或 _，去除后重新跑 A/B/C，
   *   覆盖 pay-pal-login.hl.cn 等连字符 + 子串嵌入复合变形
   *
   * @param {string} hostname - 当前页面的主机名（已由调用方转为小写）
   * @returns {Object|null} 仿冒信息 { entry, officialDomain, correctUrl, matchType, matchedBy }
   */
  static detectSpoof(hostname) {
    // 1. 输入规范化：去 www + 小写
    const normalized = hostname.replace(/^www\./i, '').toLowerCase();

    // 1.5 官方域名守卫：若当前域名本身就是官方域名（或其子域名），
    // 则直接返回 null，避免将官方网站误判为仿冒。
    // 此检查覆盖 _evaluateRule1 中用 mainDomain（注册域）查 findByDomain
    // 但完整 hostname 是子域名官方域的场景。
    if (this.findByDomain(normalized)) {
      return null;
    }

    /**
     * 对一组 labels/segments 执行规则 A/B/C，任一命中即返回结果。
     * @param {string[]} labels       标签数组
     * @param {string[]} allSegs      所有段平铺数组
     * @param {string[][]} labelSegs  每个 label 的段数组
     * @param {'original'|'dehyphened'} source 来源标记
     * @returns {Object|null}
     */
    const _checkRules = (labels, allSegs, labelSegs, source) => {
      for (const kw of sortedKeywords) {
        // ---- 规则 A：精确段匹配（所有长度关键词） ----
        for (const segs of labelSegs) {
          for (const seg of segs) {
            if (seg === kw) {
              const entry = keywordToEntries.get(kw)[0];
              return {
                entry,
                officialDomain: entry.officialDomains[0],
                correctUrl: entry.correctUrl,
                matchType: 'segment_exact_match',
                matchedBy: `段 "${seg}" 精确匹配关键词 "${kw}"` +
                  (source === 'dehyphened' ? '（去连字符）' : '')
              };
            }
          }
        }

        // ---- 规则 B：标签子串包含（仅 kw >= 5，任意位置不需边界） ----
        if (kw.length >= 5) {
          for (const label of labels) {
            if (label.includes(kw)) {
              const entry = keywordToEntries.get(kw)[0];
              return {
                entry,
                officialDomain: entry.officialDomains[0],
                correctUrl: entry.correctUrl,
                matchType: 'substring_include',
                matchedBy: `标签 "${label}" 包含关键词 "${kw}"` +
                  (source === 'dehyphened' ? '（去连字符）' : '')
              };
            }
          }
        }

        // ---- 规则 C：关键词堆叠（所有长度，阈值 ≥3） ----
        let hitCount = 0;
        for (const seg of allSegs) {
          if (seg === kw) hitCount++;
        }
        if (hitCount >= 3) {
          const entry = keywordToEntries.get(kw)[0];
          return {
            entry,
            officialDomain: entry.officialDomains[0],
            correctUrl: entry.correctUrl,
            matchType: 'keyword_stuffing',
            matchedBy: `关键词 "${kw}" 在域名段中重复出现 ${hitCount} 次` +
              (source === 'dehyphened' ? '（去连字符）' : '')
          };
        }
      }
      return null;
    };

    // 2. 构建原始 labels / segments
    const labels = normalized.split('.');
    const allSegments = [];
    const labelSegments = [];
    for (const label of labels) {
      const segs = splitIntoSegments(label);
      labelSegments.push(segs);
      for (const s of segs) allSegments.push(s);
    }

    // 3. 原始域名 → 规则 A/B/C
    let result = _checkRules(labels, allSegments, labelSegments, 'original');
    if (result) return result;

    // 4. 去连字符二次检测（覆盖 pay-pal-login.hl.cn 等复合变形）
    if (normalized.includes('-') || normalized.includes('_')) {
      const deHyphened = normalized.replace(/[-_]/g, '');
      const dhLabels = deHyphened.split('.');
      const dhAllSegs = [];
      const dhLabelSegs = [];
      for (const label of dhLabels) {
        const segs = splitIntoSegments(label);
        dhLabelSegs.push(segs);
        for (const s of segs) dhAllSegs.push(s);
      }
      result = _checkRules(dhLabels, dhAllSegs, dhLabelSegs, 'dehyphened');
      if (result) return result;
    }

    // 5. 规则 D：约束编辑距离（仅 kw >= 6，dist 1-2，lenDiff ≤ 2）
    //    安全护栏：避免把「真实品牌域名」或「两个无关品牌词」误判为仿冒。
    //      (a) 关键词含中文时取其纯 ASCII 核心：若输入标签即等于该核心（如 tencent.com
    //          命中关键词"tencent云"），属真实品牌而非仿冒 → 跳过。
    //      (b) 要求标签与关键词存在≥3字符的连续公共前缀或后缀，确保是"同一词的错别字"
    //          而非两个不同品牌词（如 youdao 与 doubao 仅公共后缀"ao"=2 字符，应判为不同品牌）。
    for (const kw of sortedKeywords) {
      if (kw.length < 6) continue;
      const kwAscii = kw.replace(/[一-鿿]/g, '');
      for (const label of labels) {
        if (Math.abs(label.length - kw.length) > 2) continue;
        if (kwAscii && label === kwAscii) continue; // (a) 真实品牌核心，非仿冒
        const dist = _levenshtein(label, kw);
        if (dist >= 1 && dist <= 2) {
          const lcp = longestCommonPrefix(label, kw);
          const lcs = longestCommonSuffix(label, kw);
          if (Math.max(lcp, lcs) < 3) continue; // (b) 两个不同品牌词，跳过
          const entry = keywordToEntries.get(kw)[0];
          return {
            entry,
            officialDomain: entry.officialDomains[0],
            correctUrl: entry.correctUrl,
            matchType: 'typosquat',
            matchedBy: `Levenshtein 距离 ${dist}: "${label}" ≈ "${kw}"`
          };
        }
      }
    }

    return null;
  }

  /**
   * 检查域名是否为中国品牌（需要ICP备案检查）
   * 条件：.cn 域名 或 数据库中的中国品牌
   */
  static isChineseBrand(domain) {
    const normalized = domain.toLowerCase();
    if (normalized.endsWith('.cn')) return true;

    const entry = this.findByDomain(domain);
    if (entry && entry.isChineseBrand) return true;

    // 对相似域名也检查
    const spoof = this.detectSpoof(domain);
    if (spoof && spoof.entry.isChineseBrand) return true;

    return false;
  }

  /**
   * 获取官方网站的正确URL
   */
  static getCorrectUrl(name) {
    const entry = entryByName.get(name);
    return entry ? entry.correctUrl : null;
  }

  /**
   * 获取所有条目
   */
  static getAllEntries() {
    return DOMAIN_DATABASE;
  }

  /**
   * 检查是否为官方域名
   */
  static isOfficialDomain(hostname) {
    return this.findByDomain(hostname) !== null;
  }
}
