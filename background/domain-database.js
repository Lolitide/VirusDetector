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
 *   - 140+ 条品牌记录
 *
 *   注：.edu.cn 等政府/教育完全信任后缀由主管部门严格管理，攻击者无法注册，
 *   已在 service-worker.js 的 isFullyTrusted() 前置跳过，不再纳入数据库。
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
 * 仿冒检测策略（分级嫌疑，取代原「命中即判定」硬处理）：
 *
 * STRONG（高置信嫌疑，供评分引擎给高分，但不再单独触发警告）：
 *   S1 强关键词精确段匹配  → 标签段等于长度 ≥ 6 的 ASCII 品牌关键词（deepseek / weixin ...）
 *   S2 官方注册域标签段    → 标签段等于官方域名的注册域标签（长度 ≥ 6，如 qianwenai）
 *   S3 形近字符混淆        → 标签经形近等价类规范化（0↔o、1↔l/i、rn↔m、vv↔w 等）后
 *                            与强关键词/官方标签全等（如 wuy0u.com → wuyou）
 *   S4 关键词堆叠          → 同一关键词在所有段中精确出现 ≥ 3 次（google-google-cn-google.hl.cn）
 *   S5 约束编辑距离        → Levenshtein ≤ 2 且 lenDiff ≤ 2；护栏：公共前后缀 ≥ 4，
 *                            dist=2 时 lenDiff ≤ 1（修复 wuyou→迅游 类误报）
 *   S6 拼音关键词精确段    → 标签段等于中文品牌补充的全拼（tengxun / dingding ...）
 *
 * WEAK（低置信嫌疑，仅给低分，必须联动其他特征才可能触发警告）：
 *   W1 弱关键词精确段匹配  → 标签段等于长度 4-5 的 ASCII 关键词（kdocs / momo / steam ...）
 *   W2 标签子串包含        → 关键词在任一 label 中出现（kw ≥ 5；kw 5-6 字符须在标签边界，
 *                             kw ≥ 7 无限制；lowSpecificity 通用词不参与）
 *
 *   短关键词（≤ 3 字符：qq / jd / rar / 115 / 7z ...）不参与任何段匹配，
 *   仅在「整域注册标签等于关键词」时按 WEAK 处理，消除 qq-zone.com / rar-cn.com 类误报。
 *   去连字符二次检测：若域名含 - 或 _，去除后重跑上述规则（pay-pal-login.hl.cn）。
 *   任一 STRONG 命中优先于 WEAK；同 severity 取先命中者。
 */

import { UrlUtils } from '../utils/url-utils.js';

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
    name: '谷歌',
    officialDomains: ['google.com', 'google.cn', 'googlemail.com', 'gmail.com', 'android.com', 'chromereleases.googleblog.com', 'chromium.org', 'chromium.googlesource.com'],
    correctUrl: 'https://www.google.com/',
    category: SOFTWARE_CATEGORIES.BROWSER,
    keywords: ['google', 'Google', '谷歌'],
    isChineseBrand: false
  },
  {
    name: '谷歌浏览器',
    officialDomains: ['google.com', 'google.cn', 'chrome.com'],
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
    pinyin: ['dingding'],
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
    pinyin: ['aiqiyi'],
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
    pinyin: ['mangguo'],
    isChineseBrand: true
  },
  {
    name: '西瓜视频',
    officialDomains: ['ixigua.com'],
    correctUrl: 'https://www.ixigua.com',
    category: SOFTWARE_CATEGORIES.VIDEO,
    keywords: ['西瓜视频', 'ixigua'],
    pinyin: ['xigua'],
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
    pinyin: ['wangyiyun'],
    isChineseBrand: true
  },
  {
    name: 'QQ音乐',
    officialDomains: ['y.qq.com'],
    correctUrl: 'https://y.qq.com',
    category: SOFTWARE_CATEGORIES.MUSIC,
    keywords: ['QQ音乐', 'qq音乐', 'qqmusic'],
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
    pinyin: ['tianyi'],
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
    officialDomains: ['tongyi.aliyun.com', 'qianwen.aliyun.com', 'qianwen.com', 'dashscope.console.aliyun.com', 'chat.qwen.ai', 'platform.qianwenai.com'],
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
  {
    name: 'Longcat',
    officialDomains: ['longcat.chat'],
    correctUrl: 'https://longcat.ai',
    category: SOFTWARE_CATEGORIES.AI_CHAT,
    keywords: ['Longcat', 'longcat', '龙猫', '美团龙猫'],
    isChineseBrand: true
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
    officialDomains: ['7-zip.org', '7-zip.cn'],
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
    pinyin: ['haoya'],
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
  {
    name: '雷神',
    officialDomains: ['thunderobot.com'],
    correctUrl: 'https://www.thunderobot.com',
    category: SOFTWARE_CATEGORIES.E_COMMERCE,
    keywords: ['雷神', 'thunderobot', '雷神商城', '雷神笔记本', '雷神电脑'],
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
    pinyin: ['tengxun'],
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
    officialDomains: ['github.com', 'github.blog', 'github.akams.cn'],
    correctUrl: 'https://www.github.com',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['Github', 'GitHub', 'github'],
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
  {
    name: 'CC Switch',
    officialDomains: ['ccswitch.io', 'ccswitch.ai'],
    correctUrl: 'https://www.ccswitch.io',
    category: SOFTWARE_CATEGORIES.DEVELOPER,
    keywords: ['cc Switch', 'cc switch'],
    isChineseBrand: true
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
    officialDomains: ['minecraft.net', 'minecraft.wiki', 'mojang.com'],
    correctUrl: 'https://www.minecraft.net',
    category: SOFTWARE_CATEGORIES.GAME,
    keywords: ['Minecraft', 'minecraft', '我的世界', 'Mojang'],
    isChineseBrand: false
  },
  {
    name: '蒸汽平台',
    officialDomains: ['steamchina.com', 'steampowered.com'],
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
    pinyin: ['jinritoutiao'],
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

/**
 * 命名空间归属索引（按命名空间分组、buildIndex 一次性建好）。
 * key = 注册域父级（如 sogou.com，由 officialDomains 经 UrlUtils.getMainDomain 推导），
 * value = 拥有该命名空间的品牌条目。整域 *.sogou.com 都归该品牌所有，
 * 避免 wubi.sogou.com / shouji.sogou.com 等真·子域被误报。
 * 零新增数据、零文件膨胀：父域从既有 officialDomains 现算，无需逐条手写主域名。
 */
const ownedNamespaces = new Map();

/** 所有去重关键词，按长度从长到短排序（优先匹配长品牌词） */
let sortedKeywords = [];

/**
 * 强关键词（长度 ≥ 6 的纯 ASCII 品牌词）：参与 STRONG 判定（S1 段匹配 / S5 typosquat /
 * S3 形近索引）。例：deepseek / weixin / huorong / alipay ...
 */
const strongKeywords = new Set();

/**
 * 弱关键词（长度 4-5 的 ASCII 词）：仅参与 WEAK 判定（W1 段匹配）。
 * 例：kdocs / momo / steam / iqiyi ...
 */
const weakKeywords = new Set();

/**
 * 短关键词（长度 ≤ 3）：不参与任何段匹配，仅在「整域注册标签等于关键词」时按 WEAK 处理。
 * 例：qq / jd / rar / 115 / 7z / uc ...
 */
const shortKeywords = new Set();

/**
 * 拼音关键词（中文品牌补充全拼）：仅参与 STRONG 判定（S6 段精确匹配）。
 * 例：tengxun / dingding / jinritoutiao ...
 */
const pinyinKeywords = new Set();

/**
 * 低特异性关键词（通用英文词）：不参与 W2 substring 判定，仅保留 W1 精确段匹配。
 * 避免 kdocs-team.com → kdocsteam 拼合后 substring 命中 steam 一类误报。
 */
const LOW_SPECIFICITY_KEYWORDS = new Set(['steam', 'edge', 'soul', 'clash']);

/** 官方注册域标签（长度 ≥ 6）→ 品牌条目：S2 官方注册域标签段匹配索引 */
const officialLabelSet = new Map();

/**
 * 形近字符等价类 — 单字符映射（key 为小写字符，value 为规范化 token）。
 * 仅收录高置信形近组：0↔o、1↔l↔i、5↔s、8↔b、9↔g，
 * 以及双字符组 rn↔m、vv↔w、cl↔d（见 HOMOGLYPH_PAIRS）。
 */
const HOMOGLYPH_SINGLE = {
  '0': 'O', 'o': 'O',
  '1': 'I', 'l': 'I', 'i': 'I',
  '5': 'S', 's': 'S',
  '8': 'B', 'b': 'B',
  '9': 'G', 'g': 'G',
  'm': 'M', 'w': 'W', 'd': 'D'
};

/** 形近字符等价类 — 双字符组（优先于单字符匹配） */
const HOMOGLYPH_PAIRS = {
  'rn': 'M',
  'vv': 'W',
  'cl': 'D'
};

/**
 * 形近规范化：将字符串中的形近字符映射为等价类 token。
 * 例："wuy0u" → "wuyou"（0→O）；"paypa1" → "paypal"（1→I）；"rnicrosoft" → "microsoft"（rn→M）。
 * 线性复杂度 O(n)，不进行指数级穷举变形。
 * @param {string} str
 * @returns {string}
 */
function normalizeHomoglyph(str) {
  let out = '';
  let i = 0;
  const lower = str.toLowerCase();
  while (i < lower.length) {
    const two = lower.slice(i, i + 2);
    if (HOMOGLYPH_PAIRS[two]) {
      out += HOMOGLYPH_PAIRS[two];
      i += 2;
      continue;
    }
    const ch = lower[i];
    out += HOMOGLYPH_SINGLE[ch] || ch;
    i++;
  }
  return out;
}

/** 形近规范化索引：normalized label → { entry, original }（S3 形近判定） */
const homoglyphIndex = new Map();

/** 关键词是否为「纯 ASCII 词」（不含中文/空格/连字符等域名中不可出现的字符） */
function isAsciiKeyword(kw) {
  return /^[a-z0-9]+$/.test(kw);
}

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
      // 按命名空间分组（一次性建索引）：整域 *.ns 都归该品牌所有（解决真·子域误报）
      const ns = UrlUtils.getMainDomain(normalized);
      if (!ownedNamespaces.has(ns)) ownedNamespaces.set(ns, entry);

      // S2 官方注册域标签索引：注册域标签长度 ≥ 6 才参与（排除 qq / jd 等短标签）
      const registrable = UrlUtils.getMainDomain(normalized);
      const label = registrable.split('.')[0];
      if (label && label.length >= 6 && !officialLabelSet.has(label)) {
        officialLabelSet.set(label, entry);
      }
    }
  }

  // 构建关键词 → 品牌 映射，并按长度分级
  for (const entry of DOMAIN_DATABASE) {
    for (const keyword of entry.keywords) {
      const kw = keyword.toLowerCase();
      if (!keywordToEntries.has(kw)) {
        keywordToEntries.set(kw, []);
      }
      keywordToEntries.get(kw).push(entry);

      if (isAsciiKeyword(kw)) {
        if (kw.length >= 6) strongKeywords.add(kw);
        else if (kw.length >= 4) weakKeywords.add(kw);
        else shortKeywords.add(kw);
      }
    }
    // 拼音关键词（S6）：仅 ASCII 全拼，长度 ≥ 5 参与
    for (const pinyin of entry.pinyin || []) {
      const py = pinyin.toLowerCase();
      if (isAsciiKeyword(py) && py.length >= 5) {
        pinyinKeywords.add(py);
        if (!keywordToEntries.has(py)) keywordToEntries.set(py, []);
        keywordToEntries.get(py).push(entry);
      }
    }
  }

  // 收集所有去重关键词，按长度排序（与 keywordToEntries 联动，拼音词已并入）
  const allKw = [...keywordToEntries.keys()];
  sortedKeywords = allKw.sort((a, b) => b.length - a.length);

  // S3 形近索引：对强关键词（长度 ≥ 6）与官方注册域标签建立规范化映射。
  // 仅收录规范化后与原文不同的词，避免同词自映射占用索引。
  for (const kw of strongKeywords) {
    const norm = normalizeHomoglyph(kw);
    if (norm !== kw && !homoglyphIndex.has(norm)) {
      homoglyphIndex.set(norm, { entry: keywordToEntries.get(kw)[0], original: kw });
    }
  }
  for (const [label, entry] of officialLabelSet) {
    const norm = normalizeHomoglyph(label);
    if (norm !== label && !homoglyphIndex.has(norm)) {
      homoglyphIndex.set(norm, { entry, original: label });
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
    // 命名空间归属：整域 *.ns 归该品牌（直接查一次性建好的索引，O(1)）
    const ns = UrlUtils.getMainDomain(normalized);
    if (ownedNamespaces.has(ns)) {
      return ownedNamespaces.get(ns);
    }
    return null;
  }

  /**
   * 核心方法：检测域名仿冒（分级嫌疑）
   *
   * 取代原「命中即返回」的硬处理，输出分级嫌疑供评分引擎联动评分：
   *   STRONG（高置信）：
   *     S1 强关键词精确段匹配（kw ≥ 6）   S2 官方注册域标签段（label ≥ 6）
   *     S3 形近字符混淆（等价类规范化全等） S4 关键词堆叠（≥ 3 次）
   *     S5 约束编辑距离（护栏强化）        S6 拼音关键词精确段（tengxun 等）
   *   WEAK（低置信）：
   *     W1 弱关键词精确段匹配（kw 4-5）    W2 标签子串包含（排除通用词）
   *   短关键词（≤ 3）仅整域标签相等时 WEAK。
   *   去连字符二次检测：若域名含 - 或 _，去除后重跑上述规则。
   *
   * @param {string} hostname - 当前页面的主机名（已由调用方转为小写）
   * @returns {Object|null} 仿冒信息 { entry, severity, officialDomain, correctUrl, matchType, matchedBy }
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
     * 对一组 labels 执行全部分级规则，返回命中（strong 优先于 weak，同级别先命中先返回）。
     * @param {string[]} labels 标签数组
     * @param {'original'|'dehyphened'} source 来源标记
     * @returns {Object|null}
     */
    const _evaluate = (labels, source) => {
      const labelSegments = labels.map(splitIntoSegments);
      const allSegments = labelSegments.flat();
      const suffix = source === 'dehyphened' ? '（去连字符）' : '';

      const _build = (entry, severity, matchType, matchedBy) => ({
        entry,
        severity,
        officialDomain: entry.officialDomains[0],
        correctUrl: entry.correctUrl,
        matchType,
        matchedBy
      });

      // ---- STRONG 判定 ----

      // S4 关键词堆叠（kw ≥ 2，覆盖 qq-qq-qq.com 等短词堆叠恶意模式；
      //    中文关键词不会与 ASCII 段相等，天然无害）
      for (const kw of sortedKeywords) {
        if (kw.length < 2) continue;
        let hitCount = 0;
        for (const seg of allSegments) {
          if (seg === kw) hitCount++;
        }
        if (hitCount >= 3) {
          return _build(keywordToEntries.get(kw)[0], 'strong', 'keyword_stuffing',
            `关键词 "${kw}" 在域名段中重复出现 ${hitCount} 次` + suffix);
        }
      }

      // S3 形近字符混淆：仅当段含形近字符时查索引（wuy0u.com → wuyou；a1ipay-login.com 段 a1ipay）
      for (const segs of labelSegments) {
        for (const seg of segs) {
          if (seg.length < 4) continue;
          const normSeg = normalizeHomoglyph(seg);
          if (normSeg === seg) continue;
          const hit = homoglyphIndex.get(normSeg);
          // seg 与 original 相同说明是原词自身（如关键词含 i/l 时规范化自映射），
          // 并非真实形近变体，跳过（如 tongyi.com 不应因 i→I 自命中）
          if (hit && seg !== hit.original) {
            return _build(hit.entry, 'strong', 'homoglyph',
              `形近字符混淆: "${seg}" 规范化后 ≈ "${hit.original}"` + suffix);
          }
        }
      }

      // S1 强关键词精确段匹配（kw ≥ 6，如 deepseek / weixin / huorong）
      for (const kw of strongKeywords) {
        for (const segs of labelSegments) {
          for (const seg of segs) {
            if (seg === kw) {
              return _build(keywordToEntries.get(kw)[0], 'strong', 'segment_exact_match',
                `段 "${seg}" 精确匹配品牌关键词 "${kw}"` + suffix);
            }
          }
        }
      }

      // S6 拼音关键词精确段匹配（tengxun / dingding 等）
      for (const py of pinyinKeywords) {
        for (const segs of labelSegments) {
          for (const seg of segs) {
            if (seg === py) {
              return _build(keywordToEntries.get(py)[0], 'strong', 'pinyin_exact_match',
                `段 "${seg}" 精确匹配品牌拼音 "${py}"` + suffix);
            }
          }
        }
      }

      // S2 官方注册域标签段匹配（段 ≥ 6，如 qianwenai-x.com → 通义千问）
      for (const segs of labelSegments) {
        for (const seg of segs) {
          if (officialLabelSet.has(seg)) {
            const entry = officialLabelSet.get(seg);
            return _build(entry, 'strong', 'official_label_segment',
              `段 "${seg}" 等于「${entry.name}」的官方注册域标签` + suffix);
          }
        }
      }

      // S5 约束编辑距离（仅 kw ≥ 6，dist 1-2，lenDiff ≤ 2）
      //    安全护栏：避免把「真实品牌域名」或「两个无关品牌词」误判为仿冒。
      //      (a) 关键词含中文时取其纯 ASCII 核心：若输入标签即等于该核心（如 tencent.com
      //          命中关键词"tencent云"），属真实品牌而非仿冒 → 跳过。
      //      (b) 要求标签与关键词存在≥4字符的连续公共前缀或后缀，确保是"同一词的错别字"
      //          而非两个不同品牌词（如 wuyou 与 xunyou 仅公共后缀"you"=3 字符，应判为不同词）。
      //      (c) dist=2 时要求 lenDiff ≤ 1，进一步收紧双编辑距离变体。
      //    同时执行「整标签」与「段级」两种粒度：整标签覆盖 firefpx.com 类错拼注册域，
      //    段级覆盖 deepseekk-login.com 类「错拼段 + 修饰段」组合。
      const _typosquat = (target, kw, matchedSeg) => {
        const kwAscii = kw.replace(/[一-鿿]/g, '');
        if (kwAscii && target === kwAscii) return null; // (a) 真实品牌核心，非仿冒
        const lenDiff = Math.abs(target.length - kw.length);
        if (lenDiff > 2) return null;
        const dist = _levenshtein(target, kw);
        if (dist < 1 || dist > 2) return null;
        const lcp = longestCommonPrefix(target, kw);
        const lcs = longestCommonSuffix(target, kw);
        if (Math.max(lcp, lcs) < 4) return null; // (b) 两个不同品牌词，跳过
        if (dist === 2 && lenDiff > 1) return null; // (c) 双编辑距离收紧
        return _build(keywordToEntries.get(kw)[0], 'strong', 'typosquat',
          `Levenshtein 距离 ${dist}: "${matchedSeg}" ≈ "${kw}"` + suffix);
      };
      // 整标签 typosquat（注册域整体错拼）
      for (const kw of strongKeywords) {
        for (const label of labels) {
          const hit = _typosquat(label, kw, label);
          if (hit) return hit;
        }
      }
      // 段级 typosquat（错拼段 + 修饰段，如 deepseekk-login.com）
      for (const kw of strongKeywords) {
        for (const segs of labelSegments) {
          for (const seg of segs) {
            if (seg.length < 4) continue; // 短段不参与编辑距离
            const hit = _typosquat(seg, kw, seg);
            if (hit) return hit;
          }
        }
      }

      // ---- WEAK 判定 ----

      // W1 弱关键词精确段匹配（kw 4-5，如 kdocs / momo / steam）
      for (const kw of weakKeywords) {
        for (const segs of labelSegments) {
          for (const seg of segs) {
            if (seg === kw) {
              return _build(keywordToEntries.get(kw)[0], 'weak', 'segment_exact_match',
                `段 "${seg}" 匹配品牌关键词 "${kw}"` + suffix);
            }
          }
        }
      }

      // 短关键词（≤ 3）：整域注册标签等于关键词时 WEAK（qq.cn / 7z.com 等）
      for (const label of labels) {
        if (shortKeywords.has(label)) {
          return _build(keywordToEntries.get(label)[0], 'weak', 'segment_exact_match',
            `段 "${label}" 匹配品牌关键词` + suffix);
        }
      }

      // W2 标签子串包含（kw ≥ 5，排除 lowSpecificity 通用词）
      for (const kw of sortedKeywords) {
        if (kw.length < 5 || LOW_SPECIFICITY_KEYWORDS.has(kw)) continue;
        for (const label of labels) {
          if (label.includes(kw)) {
            // 短关键词（5-6 字符）须在标签边界位置（开头或结尾），
            // 避免 xbaidux.com 等正常域被误判；长关键词（≥7 字符）允许任意位置
            if (kw.length < 7 && !label.startsWith(kw) && !label.endsWith(kw)) continue;
            return _build(keywordToEntries.get(kw)[0], 'weak', 'substring_include',
              `标签 "${label}" 包含关键词 "${kw}"` + suffix);
          }
        }
      }

      return null;
    };

    // 2. 原始域名 → 全部分级规则
    const labels = normalized.split('.');
    let result = _evaluate(labels, 'original');
    if (result) return result;

    // 3. 去连字符二次检测（覆盖 pay-pal-login.hl.cn 等复合变形；
    //    strong/weak 分级在 _evaluate 内部已统一处理）
    if (normalized.includes('-') || normalized.includes('_')) {
      const deHyphened = normalized.replace(/[-_]/g, '');
      const dhLabels = deHyphened.split('.');
      result = _evaluate(dhLabels, 'dehyphened');
      if (result) return result;
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
