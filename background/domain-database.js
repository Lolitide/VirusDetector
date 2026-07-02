/**
 * Virus Detector — 域名数据库 & 仿冒检测 (Domain Database)
 *
 * 维护中国常用软件/网站的官方域名对照表，并提供基于编辑距离和
 * 子串匹配的域名仿冒检测能力。
 *
 * @module domain-database
 * @version 2.2.4
 *
 * 数据规模：
 *   - 覆盖 20 个类别（安全软件、浏览器、即时通讯、输入法、办公、视频、
 *     音乐、云存储、AI Chat、下载工具、压缩工具、电商、地图出行、支付、
 *     开发者工具、系统工具、游戏平台、游戏加速器、新闻资讯、政务服务）
 *   - 121 条品牌记录
 *
 * 每条记录包含：
 *   - name             品牌名称
 *   - officialDomains  官方域名列表（用于精确匹配和子串包含检测）
 *   - correctUrl       正确官网完整 URL（用于警告弹窗中的"前往官网"）
 *   - keywords         搜索关键词（用于段级匹配）
 *   - isChineseBrand   是否为中国品牌（用于部分检测逻辑）
 *
 * 仿冒检测策略（5 层递进）：
 *   1. 子串包含     → 仿冒域名包含官方域名字符串
 *   2. 段级关键词   → 按 '.' 和 '-' 拆分域名，逐段匹配品牌关键词
 *   3. 可疑 TLD     → 关键词命中 + 域名使用非常见顶级域
 *   3.5 关键词堆叠  → 同一品牌关键词在域名段中重复 >= 3 次（如 google-google-cn-google）
 *   4. 编辑距离     → Levenshtein 距离 1-2 的相似域名
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
  GAME: '游戏平台',
  GAME_ACCELERATOR: '游戏加速器',
  NEWS_INFO: '新闻/信息',
  GOV_SERVICE: '政务服务',
  EDUCATION: '高校/教育'
};

const DOMAIN_DATABASE = [
  // ========== 安全软件 ==========
  {
    name: '360安全卫士',
    officialDomains: ['360.cn', '360safe.com', '360.com'],
    correctUrl: 'https://www.360.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['360', '安全卫士', '360safe'],
    isChineseBrand: true
  },
  {
    name: '火绒安全',
    officialDomains: ['huorong.cn', 'huorong.com'],
    correctUrl: 'https://www.huorong.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['火绒', 'huorong'],
    isChineseBrand: true
  },
  {
    name: '腾讯电脑管家',
    officialDomains: ['guanjia.qq.com', 'pm.qq.com'],
    correctUrl: 'https://guanjia.qq.com',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['电脑管家', '腾讯管家', 'guanjia'],
    isChineseBrand: true
  },
  {
    name: '瑞星杀毒',
    officialDomains: ['rising.com.cn'],
    correctUrl: 'https://www.rising.com.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['瑞星', 'rising'],
    isChineseBrand: true
  },
  {
    name: '金山毒霸',
    officialDomains: ['duba.net', 'ijinshan.com'],
    correctUrl: 'https://www.duba.net',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['金山毒霸', '毒霸', 'duba', 'jinshan'],
    isChineseBrand: true
  },
  {
    name: '微步在线',
    officialDomains: ['threatbook.cn', 'threatbook.com'],
    correctUrl: 'https://www.threatbook.cn',
    category: SOFTWARE_CATEGORIES.SECURITY,
    keywords: ['微步', 'threatbook'],
    isChineseBrand: true
  },

  // ========== 浏览器 ==========
  {
    name: '360浏览器',
    officialDomains: ['browser.360.cn', 'se.360.cn'],
    correctUrl: 'https://browser.360.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['360浏览器', '360极速浏览器'],
    isChineseBrand: true
  },
  {
    name: 'QQ浏览器',
    officialDomains: ['browser.qq.com'],
    correctUrl: 'https://browser.qq.com',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['QQ浏览器', 'qq浏览器'],
    isChineseBrand: true
  },
  {
    name: '搜狗浏览器',
    officialDomains: ['ie.sogou.com'],
    correctUrl: 'https://ie.sogou.com',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['搜狗浏览器', 'sogou浏览器'],
    isChineseBrand: true
  },
  {
    name: '猎豹浏览器',
    officialDomains: ['liebao.cn', 'lb.cn'],
    correctUrl: 'https://www.liebao.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['猎豹浏览器', 'liebao'],
    isChineseBrand: true
  },
  {
    name: '遨游浏览器',
    officialDomains: ['maxthon.cn', 'maxthon.com'],
    correctUrl: 'https://www.maxthon.cn',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['遨游', 'maxthon', '傲游'],
    isChineseBrand: true
  },
  {
    name: '星愿浏览器',
    officialDomains: ['twinkstar.com'],
    correctUrl: 'https://www.twinkstar.com',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['星愿', 'twinkstar'],
    isChineseBrand: true
  },
  {
    name: '火狐浏览器',
    officialDomains: ['mozilla.org', 'firefox.com', 'mozilla.com.cn'],
    correctUrl: 'https://www.mozilla.org/zh-CN/firefox/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['火狐', 'Firefox', 'mozilla', 'Mozilla'],
    isChineseBrand: false
  },
  {
    name: '谷歌搜索',
    officialDomains: ['google.com', 'google.cn', 'google.com.hk'],
    correctUrl: 'https://www.google.com/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['google', 'Google', '谷歌', 'guge'],
    isChineseBrand: false
  },
  {
    name: '谷歌浏览器',
    officialDomains: ['google.com', 'google.cn', 'chrome.google.com'],
    correctUrl: 'https://www.google.com/chrome/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['Chrome', 'Google Chrome', '谷歌浏览器', 'chrome', 'google', 'Google'],
    isChineseBrand: false
  },
  {
    name: 'Edge浏览器',
    officialDomains: ['microsoft.com', 'microsoftedge.com'],
    correctUrl: 'https://www.microsoft.com/edge',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['Edge', 'Microsoft Edge', 'edge浏览器'],
    isChineseBrand: false
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
    officialDomains: ['work.weixin.qq.com', 'wework.cn'],
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
    officialDomains: ['soulapp.cn', 'soul.cn'],
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
    keywords: ['搜狗输入法', '搜狗拼音', 'sogou输入法'],
    isChineseBrand: true
  },
  {
    name: '百度输入法',
    officialDomains: ['shurufa.baidu.com'],
    correctUrl: 'https://shurufa.baidu.com',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['百度输入法', '百度拼音'],
    isChineseBrand: true
  },
  {
    name: '讯飞输入法',
    officialDomains: ['srf.xunfei.cn', 'xunfei.cn'],
    correctUrl: 'https://srf.xunfei.cn',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['讯飞输入法', '讯飞', 'xunfei'],
    isChineseBrand: true
  },
  {
    name: 'QQ输入法',
    officialDomains: ['qq.pinyin.cn'],
    correctUrl: 'https://qq.pinyin.cn',
    category: SOFTWARE_CATEGORIES.INPUT_METHOD,
    keywords: ['QQ输入法', 'qq拼音'],
    isChineseBrand: true
  },
  {
    name: '手心输入法',
    officialDomains: ['xsj.360.cn'],
    correctUrl: 'https://xsj.360.cn',
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
    keywords: ['WPS', '金山办公', 'wps', 'WPS Office'],
    isChineseBrand: true
  },
  {
    name: '腾讯文档',
    officialDomains: ['docs.qq.com'],
    correctUrl: 'https://docs.qq.com',
    category: SOFTWARE_CATEGORIES.OFFICE,
    keywords: ['腾讯文档', 'docs.qq'],
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
    keywords: ['永中', 'yozo', '永中Office'],
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
    keywords: ['爱奇艺', 'iqiyi'],
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
    officialDomains: ['bilibili.com', 'b23.tv'],
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
    keywords: ['芒果TV', 'mgtv'],
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
    officialDomains: ['tv.sohu.com'],
    correctUrl: 'https://tv.sohu.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['搜狐视频', 'sohu视频'],
    isChineseBrand: true
  },

  // ========== 音乐软件 ==========
  {
    name: '网易云音乐',
    officialDomains: ['music.163.com'],
    correctUrl: 'https://music.163.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['网易云音乐', '网易云', 'cloudmusic'],
    isChineseBrand: true
  },
  {
    name: 'QQ音乐',
    officialDomains: ['y.qq.com', 'music.qq.com'],
    correctUrl: 'https://y.qq.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['QQ音乐', 'qq音乐'],
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
    officialDomains: ['qishui.com', 'qishuiyinyue.com'],
    correctUrl: 'https://www.qishui.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['汽水音乐', '汽水', 'qishui', '抖音音乐'],
    isChineseBrand: true
  },
  {
    name: '咪咕音乐',
    officialDomains: ['music.migu.cn'],
    correctUrl: 'https://music.migu.cn',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['咪咕音乐', '咪咕', 'migu', '中国移动音乐'],
    isChineseBrand: true
  },

  // ========== 云存储/网盘 ==========
  {
    name: '百度网盘',
    officialDomains: ['pan.baidu.com'],
    correctUrl: 'https://pan.baidu.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['百度网盘', '百度云', 'baidupan', 'baiduyun'],
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
    keywords: ['115网盘', '115'],
    isChineseBrand: true
  },
  {
    name: '天翼云盘',
    officialDomains: ['cloud.189.cn'],
    correctUrl: 'https://cloud.189.cn',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['天翼云盘', '天翼云'],
    isChineseBrand: true
  },
  {
    name: '夸克网盘',
    officialDomains: ['pan.quark.cn'],
    correctUrl: 'https://pan.quark.cn',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['夸克网盘', '夸克'],
    isChineseBrand: true
  },
  {
    name: '迅雷云盘',
    officialDomains: ['pan.xunlei.com'],
    correctUrl: 'https://pan.xunlei.com',
    category: SOFTWARE_CATEGORIES.CLOUD_STORAGE,
    keywords: ['迅雷云盘'],
    isChineseBrand: true
  },

  // ========== AI Chat ==========
  {
    name: '文心一言',
    officialDomains: ['yiyan.baidu.com'],
    correctUrl: 'https://yiyan.baidu.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['文心一言', 'yiyan'],
    isChineseBrand: true
  },
  {
    name: '通义千问',
    officialDomains: ['tongyi.aliyun.com', 'qianwen.aliyun.com', 'qianwen.com'],
    correctUrl: 'https://tongyi.aliyun.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['通义千问', 'tongyi', 'qianwen'],
    isChineseBrand: true
  },
  {
    name: '豆包',
    officialDomains: ['doubao.com'],
    correctUrl: 'https://www.doubao.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['豆包', 'doubao'],
    isChineseBrand: true
  },
  {
    name: '讯飞星火',
    officialDomains: ['xinghuo.xfyun.cn'],
    correctUrl: 'https://xinghuo.xfyun.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['讯飞星火', 'xinghuo', 'xfyun'],
    isChineseBrand: true
  },
  {
    name: '360智脑',
    officialDomains: ['chat.360.com'],
    correctUrl: 'https://chat.360.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['360智脑', '智脑'],
    isChineseBrand: true
  },
  {
    name: 'Kimi',
    officialDomains: ['kimi.moonshot.cn','kimi.com'],
    correctUrl: 'https://www.kimi.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['Kimi', 'kimi', 'moonshot'],
    isChineseBrand: true
  },
  {
    name: 'DeepSeek',
    officialDomains: ['chat.deepseek.com', 'deepseek.com'],
    correctUrl: 'https://chat.deepseek.com',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['DeepSeek', 'deepseek'],
    isChineseBrand: true
  },
  {
    name: '智谱清言',
    officialDomains: ['chatglm.cn', 'bigmodel.cn'],
    correctUrl: 'https://chatglm.cn',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['智谱清言', 'chatglm', '智谱'],
    isChineseBrand: true
  },

  // ========== 下载工具 ==========
  {
    name: '迅雷',
    officialDomains: ['xunlei.com', 'dl.xunlei.com', 'mobile.xunlei.com'],
    correctUrl: 'https://www.xunlei.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['迅雷', 'xunlei', 'Thunder'],
    isChineseBrand: true
  },
  {
    name: 'IDM下载器',
    officialDomains: ['internetdownloadmanager.com'],
    correctUrl: 'https://www.internetdownloadmanager.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['IDM', 'Internet Download Manager'],
    isChineseBrand: false
  },
  {
    name: '比特彗星',
    officialDomains: ['bitcomet.com'],
    correctUrl: 'https://www.bitcomet.com',
    category: SOFTWARE_CATEGORIES.DOWNLOAD_TOOL,
    keywords: ['比特彗星', 'BitComet', 'bitcomet'],
    isChineseBrand: false
  },

  // ========== 压缩工具 ==========
  {
    name: 'WinRAR',
    officialDomains: ['rarlab.com', 'win-rar.com'],
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
    officialDomains: ['haozip.com'],
    correctUrl: 'https://www.haozip.com',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['好压', 'haozip'],
    isChineseBrand: true
  },
  {
    name: '360压缩',
    officialDomains: ['yasuo.360.cn'],
    correctUrl: 'https://yasuo.360.cn',
    category: SOFTWARE_CATEGORIES.COMPRESSION,
    keywords: ['360压缩', '360yasuo'],
    isChineseBrand: true
  },

  // ========== 电商 ==========
  {
    name: '淘宝',
    officialDomains: ['taobao.com', 'tmall.com'],
    correctUrl: 'https://www.taobao.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['淘宝', 'taobao', '天猫', 'tmall'],
    isChineseBrand: true
  },
  {
    name: '京东',
    officialDomains: ['jd.com'],
    correctUrl: 'https://www.jd.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['京东', 'jd', 'JD'],
    isChineseBrand: true
  },
  {
    name: '拼多多',
    officialDomains: ['pinduoduo.com'],
    correctUrl: 'https://www.pinduoduo.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['拼多多', 'pinduoduo'],
    isChineseBrand: true
  },
  {
    name: '美团',
    officialDomains: ['meituan.com'],
    correctUrl: 'https://www.meituan.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['美团', 'meituan'],
    isChineseBrand: true
  },
  {
    name: '苏宁易购',
    officialDomains: ['suning.com'],
    correctUrl: 'https://www.suning.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['苏宁', 'suning'],
    isChineseBrand: true
  },
  {
    name: '闲鱼',
    officialDomains: ['goofish.com'],
    correctUrl: 'https://www.goofish.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['闲鱼', 'goofish'],
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
    officialDomains: ['amap.com', 'gaode.com'],
    correctUrl: 'https://www.amap.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['高德地图', '高德', 'amap', 'gaode'],
    isChineseBrand: true
  },
  {
    name: '滴滴出行',
    officialDomains: ['didiglobal.com'],
    correctUrl: 'https://www.didiglobal.com',
    category: SOFTWARE_CATEGORIES.MAP_TRAVEL,
    keywords: ['滴滴', 'didi'],
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
    officialDomains: ['alipay.com', 'alipayplus.com'],
    correctUrl: 'https://www.alipay.com',
    category: SOFTWARE_CATEGORIES.PAYMENT,
    keywords: ['支付宝', 'alipay'],
    isChineseBrand: true
  },
  {
    name: '微信支付',
    officialDomains: ['pay.weixin.qq.com'],
    correctUrl: 'https://pay.weixin.qq.com',
    category: SOFTWARE_CATEGORIES.PAYMENT,
    keywords: ['微信支付', 'weixin支付'],
    isChineseBrand: true
  },

  // ========== 开发者工具 ==========
  {
    name: '阿里云',
    officialDomains: ['aliyun.com', 'aliyuncs.com'],
    correctUrl: 'https://www.aliyun.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['阿里云', 'aliyun'],
    isChineseBrand: true
  },
  {
    name: '腾讯云',
    officialDomains: ['cloud.tencent.com'],
    correctUrl: 'https://cloud.tencent.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['腾讯云', 'tencent云'],
    isChineseBrand: true
  },
  {
    name: '华为云',
    officialDomains: ['huaweicloud.com'],
    correctUrl: 'https://www.huaweicloud.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['华为云', 'huaweicloud'],
    isChineseBrand: true
  },
  {
    name: '百度智能云',
    officialDomains: ['cloud.baidu.com'],
    correctUrl: 'https://cloud.baidu.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['百度云', '百度智能云'],
    isChineseBrand: true
  },
  {
    name: 'CSDN',
    officialDomains: ['csdn.net', 'csdn.com'],
    correctUrl: 'https://www.csdn.net',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['CSDN', 'csdn'],
    isChineseBrand: true
  },
  {
    name: '开源中国',
    officialDomains: ['oschina.net'],
    correctUrl: 'https://www.oschina.net',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['开源中国', 'oschina'],
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
    keywords: ['掘金', 'juejin'],
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
    officialDomains: ['github.com'],
    correctUrl: 'https://www.github.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['Github'],
    isChineseBrand: false
  },

  // ========== 系统工具 ==========
  {
    name: '驱动精灵',
    officialDomains: ['drvsky.com', 'mydrivers.com'],
    correctUrl: 'https://www.drvsky.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['驱动精灵', 'drvsky', 'mydrivers'],
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
    officialDomains: ['todesk.com', 'todesk.cn'],
    correctUrl: 'https://www.todesk.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['ToDesk', 'todesk', '远程桌面'],
    isChineseBrand: true
  },
  {
    name: '向日葵远程控制',
    officialDomains: ['sunlogin.com', 'oray.com', 'sunloginoray.com'],
    correctUrl: 'https://sunlogin.oray.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['向日葵', 'sunlogin', 'Oray', 'oray', '远程控制', '贝锐'],
    isChineseBrand: true
  },
  {
    name: 'TeamViewer',
    officialDomains: ['teamviewer.com', 'teamviewer.cn'],
    correctUrl: 'https://www.teamviewer.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['TeamViewer', 'teamviewer', '远程协助'],
    isChineseBrand: false
  },
  {
    name: 'AnyDesk',
    officialDomains: ['anydesk.com', 'anydesk.cn'],
    correctUrl: 'https://anydesk.com',
    category: SOFTWARE_CATEGORIES.SYSTEM_TOOL,
    keywords: ['AnyDesk', 'anydesk', '远程桌面'],
    isChineseBrand: false
  },

  // ========== 游戏平台 ==========
  {
    name: 'WeGame',
    officialDomains: ['wegame.com.cn'],
    correctUrl: 'https://www.wegame.com.cn',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['WeGame', 'wegame'],
    isChineseBrand: true
  },
  {
    name: 'Minecraft',
    officialDomains: ['minecraft.net', 'minecraft.com'],
    correctUrl: 'https://www.minecraft.net',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['Minecraft', 'minecraft', '我的世界'],
    isChineseBrand: false
  },
  {
    name: '蒸汽平台',
    officialDomains: ['steamchina.com'],
    correctUrl: 'https://store.steamchina.com',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['蒸汽平台', 'steamchina'],
    isChineseBrand: true
  },
  {
    name: '网易游戏',
    officialDomains: ['game.163.com', '163.com'],
    correctUrl: 'https://game.163.com',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['网易游戏', 'netease游戏'],
    isChineseBrand: true
  },

  // ========== 游戏加速器 ==========
  {
    name: '网易UU加速器',
    officialDomains: ['uu.163.com', 'uu accelerator.com', 'uuaccel.com'],
    correctUrl: 'https://uu.163.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['UU加速器', '网易UU', '网易加速器', 'uu accelerator'],
    isChineseBrand: true
  },
  {
    name: '迅游加速器',
    officialDomains: ['xunyou.com', 'xunyou.cn'],
    correctUrl: 'https://www.xunyou.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['迅游', 'xunyou', '迅游加速器'],
    isChineseBrand: true
  },
  {
    name: '雷神加速器',
    officialDomains: ['leigod.com', 'leishen.com'],
    correctUrl: 'https://www.leigod.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['雷神', 'leigod', 'leishen', '雷神加速器'],
    isChineseBrand: true
  },
  {
    name: '奇游加速器',
    officialDomains: ['qiyou.cn', 'qiyouu.com'],
    correctUrl: 'https://www.qiyou.cn',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['奇游', 'qiyou', '奇游加速器'],
    isChineseBrand: true
  },
  {
    name: '月轮加速器',
    officialDomains: ['yuelun.com', 'yuelun.cn'],
    correctUrl: 'https://www.yuelun.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['月轮', 'yuelun', '月轮加速器'],
    isChineseBrand: true
  },
  {
    name: '鲜牛加速器',
    officialDomains: ['xianniu.com', 'xianniu.cn'],
    correctUrl: 'https://www.xianniu.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['鲜牛', 'xianniu', '鲜牛加速器'],
    isChineseBrand: true
  },
  {
    name: '薄荷加速器',
    officialDomains: ['bohe.com', 'bohejsq.com'],
    correctUrl: 'https://www.bohejsq.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['薄荷', 'bohe', '薄荷加速器'],
    isChineseBrand: true
  },
  {
    name: '斧牛加速器',
    officialDomains: ['funiu.com', 'funiuacc.com'],
    correctUrl: 'https://www.funiuacc.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['斧牛', 'funiu', '斧牛加速器'],
    isChineseBrand: true
  },
  {
    name: 'GoLink加速器',
    officialDomains: ['golink.com', 'golink.cn'],
    correctUrl: 'https://www.golink.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['GoLink', 'golink'],
    isChineseBrand: true
  },
  {
    name: '小黑盒加速器',
    officialDomains: ['xiaoheihe.cn', 'xiaoheihe.com'],
    correctUrl: 'https://www.xiaoheihe.cn',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['小黑盒', 'xiaoheihe', '黑盒加速器'],
    isChineseBrand: true
  },
  {
    name: '腾讯网游加速器',
    officialDomains: ['jiasu.qq.com', 'game accelerator.qq.com'],
    correctUrl: 'https://jiasu.qq.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['腾讯加速器', 'QQ加速器', '腾讯网游加速器', 'jiasu.qq'],
    isChineseBrand: true
  },
  {
    name: '流星加速器',
    officialDomains: ['liuxing.com', 'lxjsq.com'],
    correctUrl: 'https://www.lxjsq.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['流星', 'liuxing', '流星加速器', 'lxjsq'],
    isChineseBrand: true
  },
  {
    name: 'NN加速器',
    officialDomains: ['nn.com', 'nnjsq.com'],
    correctUrl: 'https://www.nnjsq.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['NN加速器', 'nnjsq', '雷神NN'],
    isChineseBrand: true
  },
  {
    name: 'AK加速器',
    officialDomains: ['akspeedy.com', 'ak加速器.com'],
    correctUrl: 'https://www.akspeedy.com',
    category: SOFTWARE_CATEGORIES.GAME_ACCELERATOR,
    keywords: ['AK加速器', 'akjsq'],
    isChineseBrand: true
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
  // ========== 高校/教育 ==========
  {
    name: '清华大学',
    officialDomains: ['tsinghua.edu.cn'],
    correctUrl: 'https://www.tsinghua.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['清华', 'tsinghua'],
    isChineseBrand: true
  },
  {
    name: '北京大学',
    officialDomains: ['pku.edu.cn'],
    correctUrl: 'https://www.pku.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北大', 'pku'],
    isChineseBrand: true
  },
  {
    name: '浙江大学',
    officialDomains: ['zju.edu.cn'],
    correctUrl: 'https://www.zju.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['浙大', 'zju'],
    isChineseBrand: true
  },
  {
    name: '上海交通大学',
    officialDomains: ['sjtu.edu.cn'],
    correctUrl: 'https://www.sjtu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['上海交大', 'sjtu'],
    isChineseBrand: true
  },
  {
    name: '复旦大学',
    officialDomains: ['fudan.edu.cn'],
    correctUrl: 'https://www.fudan.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['复旦', 'fudan'],
    isChineseBrand: true
  },
  {
    name: '南京大学',
    officialDomains: ['nju.edu.cn'],
    correctUrl: 'https://www.nju.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['南大', 'nju'],
    isChineseBrand: true
  },
  {
    name: '中国科学技术大学',
    officialDomains: ['ustc.edu.cn'],
    correctUrl: 'https://www.ustc.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['中科大', 'ustc'],
    isChineseBrand: true
  },
  {
    name: '华中科技大学',
    officialDomains: ['hust.edu.cn'],
    correctUrl: 'https://www.hust.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['华科', 'hust'],
    isChineseBrand: true
  },
  {
    name: '武汉大学',
    officialDomains: ['whu.edu.cn'],
    correctUrl: 'https://www.whu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['武大', 'whu'],
    isChineseBrand: true
  },
  {
    name: '西安交通大学',
    officialDomains: ['xjtu.edu.cn'],
    correctUrl: 'https://www.xjtu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['西安交大', 'xjtu'],
    isChineseBrand: true
  },
  {
    name: '中山大学',
    officialDomains: ['sysu.edu.cn'],
    correctUrl: 'https://www.sysu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['中大', 'sysu'],
    isChineseBrand: true
  },
  {
    name: '哈尔滨工业大学',
    officialDomains: ['hit.edu.cn'],
    correctUrl: 'https://www.hit.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['哈工大', 'hit'],
    isChineseBrand: true
  },
  {
    name: '北京航空航天大学',
    officialDomains: ['buaa.edu.cn'],
    correctUrl: 'https://www.buaa.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北航', 'buaa'],
    isChineseBrand: true
  },
  {
    name: '北京理工大学',
    officialDomains: ['bit.edu.cn'],
    correctUrl: 'https://www.bit.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北理工', 'bit'],
    isChineseBrand: true
  },
  {
    name: '四川大学',
    officialDomains: ['scu.edu.cn'],
    correctUrl: 'https://www.scu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['川大', 'scu'],
    isChineseBrand: true
  },
  {
    name: '南开大学',
    officialDomains: ['nankai.edu.cn'],
    correctUrl: 'https://www.nankai.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['南开', 'nankai'],
    isChineseBrand: true
  },
  {
    name: '同济大学',
    officialDomains: ['tongji.edu.cn'],
    correctUrl: 'https://www.tongji.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['同济', 'tongji'],
    isChineseBrand: true
  },
  {
    name: '天津大学',
    officialDomains: ['tju.edu.cn'],
    correctUrl: 'https://www.tju.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['天大', 'tju'],
    isChineseBrand: true
  },
  {
    name: '东南大学',
    officialDomains: ['seu.edu.cn'],
    correctUrl: 'https://www.seu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['东南', 'seu'],
    isChineseBrand: true
  },
  {
    name: '中国人民大学',
    officialDomains: ['ruc.edu.cn'],
    correctUrl: 'https://www.ruc.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['人大', 'ruc'],
    isChineseBrand: true
  },
  {
    name: '北京师范大学',
    officialDomains: ['bnu.edu.cn'],
    correctUrl: 'https://www.bnu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北师大', 'bnu'],
    isChineseBrand: true
  },
  {
    name: '华东师范大学',
    officialDomains: ['ecnu.edu.cn'],
    correctUrl: 'https://www.ecnu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['华师大', 'ecnu'],
    isChineseBrand: true
  },
  {
    name: '厦门大学',
    officialDomains: ['xmu.edu.cn'],
    correctUrl: 'https://www.xmu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['厦大', 'xmu'],
    isChineseBrand: true
  },
  {
    name: '吉林大学',
    officialDomains: ['jlu.edu.cn'],
    correctUrl: 'https://www.jlu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['吉大', 'jlu'],
    isChineseBrand: true
  },
  {
    name: '山东大学',
    officialDomains: ['sdu.edu.cn'],
    correctUrl: 'https://www.sdu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['山大', 'sdu'],
    isChineseBrand: true
  },
  {
    name: '大连理工大学',
    officialDomains: ['dlut.edu.cn'],
    correctUrl: 'https://www.dlut.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['大工', 'dlut'],
    isChineseBrand: true
  },
  {
    name: '华南理工大学',
    officialDomains: ['scut.edu.cn'],
    correctUrl: 'https://www.scut.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['华南理工', 'scut'],
    isChineseBrand: true
  },
  {
    name: '西北工业大学',
    officialDomains: ['nwpu.edu.cn'],
    correctUrl: 'https://www.nwpu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['西工大', 'nwpu'],
    isChineseBrand: true
  },
  {
    name: '电子科技大学',
    officialDomains: ['uestc.edu.cn'],
    correctUrl: 'https://www.uestc.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['成电', 'uestc'],
    isChineseBrand: true
  },
  {
    name: '中国农业大学',
    officialDomains: ['cau.edu.cn'],
    correctUrl: 'https://www.cau.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['中国农大', 'cau'],
    isChineseBrand: true
  },
  {
    name: '兰州大学',
    officialDomains: ['lzu.edu.cn'],
    correctUrl: 'https://www.lzu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['兰大', 'lzu'],
    isChineseBrand: true
  },
  {
    name: '重庆大学',
    officialDomains: ['cqu.edu.cn'],
    correctUrl: 'https://www.cqu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['重大', 'cqu'],
    isChineseBrand: true
  },
  {
    name: '中南大学',
    officialDomains: ['csu.edu.cn'],
    correctUrl: 'https://www.csu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['中南', 'csu'],
    isChineseBrand: true
  },
  {
    name: '湖南大学',
    officialDomains: ['hnu.edu.cn'],
    correctUrl: 'https://www.hnu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['湖大', 'hnu'],
    isChineseBrand: true
  },
  {
    name: '东北大学',
    officialDomains: ['neu.edu.cn'],
    correctUrl: 'https://www.neu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['东北', 'neu'],
    isChineseBrand: true
  },
  {
    name: '北京科技大学',
    officialDomains: ['ustb.edu.cn'],
    correctUrl: 'https://www.ustb.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北科大', 'ustb'],
    isChineseBrand: true
  },
  {
    name: '北京交通大学',
    officialDomains: ['bjtu.edu.cn'],
    correctUrl: 'https://www.bjtu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北交大', 'bjtu'],
    isChineseBrand: true
  },
  {
    name: '北京邮电大学',
    officialDomains: ['bupt.edu.cn'],
    correctUrl: 'https://www.bupt.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['北邮', 'bupt'],
    isChineseBrand: true
  },
  {
    name: '国防科技大学',
    officialDomains: ['nudt.edu.cn'],
    correctUrl: 'https://www.nudt.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['国防科大', 'nudt'],
    isChineseBrand: true
  },
  {
    name: '南京航空航天大学',
    officialDomains: ['nuaa.edu.cn'],
    correctUrl: 'https://www.nuaa.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['南航', 'nuaa'],
    isChineseBrand: true
  },
  {
    name: '南京理工大学',
    officialDomains: ['njust.edu.cn'],
    correctUrl: 'https://www.njust.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['南理工', 'njust'],
    isChineseBrand: true
  },
  {
    name: '西安电子科技大学',
    officialDomains: ['xidian.edu.cn'],
    correctUrl: 'https://www.xidian.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['西电', 'xidian'],
    isChineseBrand: true
  },
  {
    name: '武汉理工大学',
    officialDomains: ['whut.edu.cn'],
    correctUrl: 'https://www.whut.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['武理工', 'whut'],
    isChineseBrand: true
  },
  {
    name: '中国地质大学（武汉）',
    officialDomains: ['cug.edu.cn'],
    correctUrl: 'https://www.cug.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['地大', 'cug'],
    isChineseBrand: true
  },
  {
    name: '华中师范大学',
    officialDomains: ['ccnu.edu.cn'],
    correctUrl: 'https://www.ccnu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['华师', 'ccnu'],
    isChineseBrand: true
  },
  {
    name: '上海科技大学',
    officialDomains: ['shanghaitech.edu.cn'],
    correctUrl: 'https://www.shanghaitech.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['上科大', 'shanghaitech'],
    isChineseBrand: true
  },
  {
    name: '南方科技大学',
    officialDomains: ['sustech.edu.cn'],
    correctUrl: 'https://www.sustech.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['南科大', 'sustech'],
    isChineseBrand: true
  },
  {
    name: '上海大学',
    officialDomains: ['shu.edu.cn'],
    correctUrl: 'https://www.shu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['上大', 'shu'],
    isChineseBrand: true
  },
  {
    name: '郑州大学',
    officialDomains: ['zzu.edu.cn'],
    correctUrl: 'https://www.zzu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['郑大', 'zzu'],
    isChineseBrand: true
  },
  {
    name: '云南大学',
    officialDomains: ['ynu.edu.cn'],
    correctUrl: 'https://www.ynu.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['云大', 'ynu'],
    isChineseBrand: true
  },
  {
    name: '西湖大学',
    officialDomains: ['westlake.edu.cn'],
    correctUrl: 'https://www.westlake.edu.cn',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['西湖', 'westlake'],
    isChineseBrand: true
  },
  {
    name: '麻省理工学院',
    officialDomains: ['mit.edu'],
    correctUrl: 'https://www.mit.edu',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['MIT', '麻省'],
    isChineseBrand: false,
    isNonChineseBrand: true
  },
  {
    name: '斯坦福大学',
    officialDomains: ['stanford.edu'],
    correctUrl: 'https://www.stanford.edu',
    category: SOFTWARE_CATEGORIES.EDUCATION,
    keywords: ['Stanford', '斯坦福'],
    isChineseBrand: false,
    isNonChineseBrand: true
  }
];

// ==================== 快速索引构建 ====================

/** 域名字符串 → 条目映射（精确匹配） */
const domainToEntry = new Map();

/** 软件名称 → 条目映射 */
const entryByName = new Map();

/** 所有官方域名的扁平集合 */
const allOfficialDomains = new Set();

/** 所有官方域名的排序数组（用于子串包含检测，长域名优先） */
let sortedOfficialDomains = [];

function buildIndex() {
  for (const entry of DOMAIN_DATABASE) {
    entryByName.set(entry.name, entry);

    for (const domain of entry.officialDomains) {
      const normalized = domain.replace(/^www\./i, '').toLowerCase();
      domainToEntry.set(normalized, entry);
      allOfficialDomains.add(normalized);
    }
  }

  // 按长度降序排列（长域名优先匹配，避免短域名误匹配）
  sortedOfficialDomains = [...allOfficialDomains].sort((a, b) => b.length - a.length);
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
   * 判定逻辑：
   * 1. 当前域名的主机名包含官方域名库中的某个完整域名（子串包含）
   *    例如 pc-huorong.com.cn 包含 huorong.com.cn? No, 但包含 huorong.com?
   *    检查：pc-huorong.com.cn.includes('huorong.cn') → yes, so it's a match
   * 2. 当前域名使用了可疑嵌套后缀且父级部分与官方域名相似
   * 3. 编辑距离辅助判断
   *
   * @param {string} hostname - 当前页面的主机名
   * @returns {Object|null} 仿冒信息 { entry, officialDomain, matchType, matchedBy }
   */
  static detectSpoof(hostname) {
    const normalized = hostname.replace(/^www\./i, '').toLowerCase();

    // 先检查是否是官方域名本身（排除）
    if (domainToEntry.has(normalized)) return null;
    for (const [domain] of domainToEntry) {
      if (normalized.endsWith('.' + domain)) return null;
    }

    // 策略1：子串包含检测（核心）
    // 检查当前域名的各个层级部分是否包含官方域名
    const hostnameParts = normalized.split('.');

    // 生成所有可能的主机名变体用于检查
    const variantsToCheck = [];
    // a) 完整主机名
    variantsToCheck.push(normalized);
    // b) 去掉第一段的变体
    for (let i = 1; i < hostnameParts.length - 1; i++) {
      variantsToCheck.push(hostnameParts.slice(i).join('.'));
    }

    for (const variant of variantsToCheck) {
      for (const officialDomain of sortedOfficialDomains) {
        // 子串包含检测
        if (variant.includes(officialDomain) && variant !== officialDomain) {
          const entry = domainToEntry.get(officialDomain);
          // 确保不是合法子域名
          if (!variant.endsWith('.' + officialDomain)) {
            return {
              entry,
              officialDomain: officialDomain,
              correctUrl: entry.correctUrl,
              matchType: 'substring_containment',
              matchedBy: `${variant} contains ${officialDomain}`
            };
          }
        }
      }
    }

    // 策略2：段级关键词匹配（按 . 和 - 拆分域名逐段比对）
    // 解决 deepseek-go.com、huorong-download.com 等带连字符的钓鱼域名
    // 这类域名子串包含策略失效（deepseek-go.com 不包含 deepseek.com），
    // 但拆分后可以提取出品牌关键词
    const segments = normalized.split(/[.\-]/);
    for (const entry of DOMAIN_DATABASE) {
      for (const keyword of entry.keywords) {
        const kw = keyword.toLowerCase();
        if (kw.length < 4) continue; // 至少4个字符才视为品牌词（避免360/qq等过短关键词误匹配）
        for (const seg of segments) {
          // 精确段匹配 或 段包含关键词 且 关键词长度占比 ≥ 60%（避免短关键词误匹配长段）
          if (seg === kw || (seg.includes(kw) && kw.length / seg.length >= 0.6)) {
            // 排除官方域名
            const isOfficial = entry.officialDomains.some(d => {
              const dn = d.replace(/^www\./i, '').toLowerCase();
              return normalized === dn || normalized.endsWith('.' + dn);
            });
            if (!isOfficial) {
              return {
                entry,
                officialDomain: entry.officialDomains[0],
                correctUrl: entry.correctUrl,
                matchType: 'segment_keyword_match',
                matchedBy: `segment "${seg}" matches keyword "${keyword}" of ${entry.name}`
              };
            }
          }
        }
      }
    }

    // 策略3：关键词 + 可疑TLD组合检测
    const hasSuspiciousTLD = this._hasSuspiciousTLD(normalized);
    if (hasSuspiciousTLD) {
      for (const entry of DOMAIN_DATABASE) {
        for (const keyword of entry.keywords) {
          if (keyword.length >= 3 && normalized.toLowerCase().includes(keyword.toLowerCase())) {
            // 排除官方域名
            const isOfficial = entry.officialDomains.some(d => {
              const dn = d.replace(/^www\./i, '').toLowerCase();
              return normalized === dn || normalized.endsWith('.' + dn);
            });
            if (!isOfficial) {
              return {
                entry,
                officialDomain: entry.officialDomains[0],
                correctUrl: entry.correctUrl,
                matchType: 'keyword_in_suspicious_tld',
                matchedBy: `keyword "${keyword}" in ${normalized} with suspicious TLD`
              };
            }
          }
        }
      }
    }

    // 策略3.5：品牌关键词重复（keyword stuffing）检测
    // 攻击者常在子域名中堆叠品牌词，如 google-google-cn-google.hl.cn
    // 同一品牌关键词在域名段中出现 >=3 次 → 明确钓鱼信号
    for (const entry of DOMAIN_DATABASE) {
      for (const keyword of entry.keywords) {
        const kw = keyword.toLowerCase();
        if (kw.length < 4) continue;
        // 统计关键词在域名段中出现的次数
        let hitCount = 0;
        for (const seg of segments) {
          if (seg === kw || (seg.includes(kw) && kw.length / seg.length >= 0.6)) {
            hitCount++;
          }
        }
        if (hitCount >= 3) {
          // 排除官方域名
          const isOfficial = entry.officialDomains.some(d => {
            const dn = d.replace(/^www\./i, '').toLowerCase();
            return normalized === dn || normalized.endsWith('.' + dn);
          });
          if (!isOfficial) {
            return {
              entry,
              officialDomain: entry.officialDomains[0],
              correctUrl: entry.correctUrl,
              matchType: 'keyword_stuffing',
              matchedBy: `keyword "${keyword}" repeated ${hitCount} times in "${normalized}"`
            };
          }
        }
      }
    }

    // 策略4：编辑距离检测（辅助）
    for (const officialDomain of sortedOfficialDomains) {
      const dist = this._levenshtein(normalized, officialDomain);
      if (dist >= 1 && dist <= 2 && normalized.length >= officialDomain.length - 2
        && normalized.length >= 6) {
        const entry = domainToEntry.get(officialDomain);
        return {
          entry,
          officialDomain,
          correctUrl: entry.correctUrl,
          matchType: 'typosquat',
          matchedBy: `Levenshtein distance ${dist}: ${normalized} ≈ ${officialDomain}`
        };
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

  // ==================== 内部工具方法 ====================

  static _hasSuspiciousTLD(hostname) {
    const SUSPICIOUS = [
      /\.cn\.com$/, /\.cn\.org$/, /\.com\.cn\.com$/,
      /\.top$/, /\.xyz$/, /\.work$/, /\.click$/, /\.link$/,
      /\.download$/, /\.zip$/, /\.review$/, /\.country$/,
      /\.kim$/, /\.gq$/, /\.ml$/, /\.cf$/, /\.ga$/, /\.tk$/
    ];
    return SUSPICIOUS.some(p => p.test(hostname));
  }

  static _levenshtein(a, b) {
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
}
