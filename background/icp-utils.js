/**
 * ICP备案号检测工具 — CJK内容识别 + 外国站点豁免 + 正则匹配
 *
 * @module icp-utils
 */

// ==================== 外国网站ICP豁免白名单 ====================
// 这些是全球知名非中国站点，确定不需要ICP备案。
// 名单已统一迁移至 utils/exemptions/index.js（导出 ICP_EXEMPT_DOMAINS），便于集中维护、避免重复登记。
import { ICP_EXEMPT_DOMAINS } from '../utils/exemptions/index.js';

/**
 * 从 domain-database 中动态提取非中国品牌的官方域名并加入豁免集合
 * 调用时机：domain-database 加载完成后
 * @param {string[]} domains - 非中国品牌的官方域名列表
 */
export function registerNonChineseBrandDomains(domains) {
  for (const d of domains) {
    ICP_EXEMPT_DOMAINS.add(d.replace(/^www\./i, '').toLowerCase());
  }
}

// ==================== CJK 字符检测 ====================

/**
 * CJK 统一表意文字 Unicode 范围
 * - U+4E00–U+9FFF   CJK 统一表意文字（常用汉字）
 * - U+3400–U+4DBF   CJK 扩展 A
 * - U+F900–U+FAFF   CJK 兼容表意文字
 */
const CJK_RANGES = [
  [0x4E00, 0x9FFF],
  [0x3400, 0x4DBF],
  [0xF900, 0xFAFF]
];

function isCJKChar(codePoint) {
  return CJK_RANGES.some(([lo, hi]) => codePoint >= lo && codePoint <= hi);
}

// 中国所有省份/自治区/直辖市简称
const PROVINCE_ABBREVIATIONS = [
  '京', // 北京
  '津', // 天津
  '沪', // 上海
  '渝', // 重庆
  '冀', // 河北
  '豫', // 河南
  '云', '滇', // 云南（滇为旧称）
  '辽', // 辽宁
  '黑', // 黑龙江
  '湘', // 湖南
  '皖', // 安徽
  '鲁', // 山东
  '新', // 新疆
  '苏', // 江苏
  '浙', // 浙江
  '赣', // 江西
  '鄂', // 湖北
  '桂', // 广西
  '甘', '陇', // 甘肃（陇为旧称）
  '晋', // 山西
  '蒙', // 内蒙古
  '陕', '秦', // 陕西（秦为旧称）
  '吉', // 吉林
  '闽', // 福建
  '贵', '黔', // 贵州（黔为旧称）
  '粤', // 广东
  '川', '蜀', // 四川（蜀为旧称）
  '青', // 青海
  '藏', // 西藏
  '琼', // 海南
  '宁', // 宁夏
];

// 省份简称正则片段
const PROVINCE_PATTERN = PROVINCE_ABBREVIATIONS.join('|');

// ==================== ICP 备案号黑名单 ====================
// 以下为已知的占位/虚假备案号，匹配到则视为未找到备案
// 常用于模板演示或伪装成已备案的虚假号码
// 涵盖所有省级行政区（31个）的 ICP备/证 格式
const ICP_BLACKLIST = new Set(
  (() => {
    const PROVINCES = [...'京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁'];
    const entries = [];
    for (const p of PROVINCES) {
      for (const t of ['备', '证']) {
        entries.push(`${p}ICP${t}10000000号`);
        entries.push(`${p}ICP${t}10000000号-1`);
      }
    }
    return entries;
  })()
);
// 额外：全零数字（如 00000000 开头）在所有格式下均视为无效
// 该检测在 isBlacklistedIcp() 方法中通过正则完成

/**
 * ICP备案号工具类
 */
export class IcpUtils {
  /**
   * 完整的ICP备案号正则
   * 格式: 省份简称 + ICP备/证 + 6-12位数字 + 号(-附属编号可选)
   * 同时匹配ICP证（经营性）
   * 注：\d{6,12} 兼容旧6位、新8位及近年出现的9-10位备案号
   */
  static ICP_FULL_REGEX = new RegExp(
    `(${PROVINCE_PATTERN})\\s*ICP\\s*[备证]\\s*\\d{6,12}\\s*号(?:\\s*-\\s*\\d+)?`,
    'gi'
  );

  /**
   * 简化匹配：省份简称 + ICP备/证 + 数字
   * 用于宽松匹配（允许缺失"号"字、大小写如 icp/ICP/Icp 均兼容）
   */
  static ICP_SIMPLE_REGEX = new RegExp(
    `(${PROVINCE_PATTERN})\\s*ICP\\s*[备证]\\s*\\d{6,12}`,
    'gi'
  );

  /**
   * 扩展格式：增值电信业务经营许可证等（省份简称 + 许可类型字母 + 数字 + "-" + 6位以上数字）
   * 例：闽B2-20040099-1、粤B2-20201234-3。
   * 这类号码不含 "ICP" 字样（区别于 ICP_FULL/SIMPLE_REGEX），是 4399 等站点的真实备案号格式。
   * 盗用此类号码的钓鱼站（如 app-4399.com.cn）会被原正则漏检，故单独补充匹配。
   * 设计约束：字母与短数字必须出现在主数字段前的连字符之前，且主数字段 ≥6 位，
   * 以避免误匹配车牌（粤A·12345，用中间点且仅 5 位）等普通文本。
   */
  static ICP_LICENSE_REGEX = new RegExp(
    `(${PROVINCE_PATTERN})\\s*[A-Za-z]\\d?\\s*-\\s*\\d{6,}(?:-\\d+)?`,
    'gi'
  );

  /**
   * 公安备案号正则
   * 格式: 省份简称 + 公网安备 + 数字 + 号
   * 允许各段之间有可选空格（如 "沪公网安备 31010502000878号"）
   */
  static POLICE_BEIAN_REGEX = new RegExp(
    `(${PROVINCE_PATTERN})\\s*公网安备\\s*\\d{10,}\\s*号`,
    'g'
  );

  /**
   * 在文本中搜索ICP备案号
   * @param {string} pageText - 页面全文
   * @param {string[]} [domIcpStrings] - 从DOM特定位置提取的文本
   * @returns {{ found: boolean, numbers: string[], source: string }}
   */
  static searchIcpNumber(pageText, domIcpStrings = []) {
    const results = [];
    let source = 'none';

    // 优先检查DOM特定位置（更可靠）
    if (domIcpStrings && domIcpStrings.length > 0) {
      for (const str of domIcpStrings) {
        const matches = str.match(this.ICP_FULL_REGEX);
        if (matches) {
          results.push(...matches);
          source = 'dom_footer';
        }
      }

      // 公安备案号检测（带空格容差）
      if (results.length === 0) {
        for (const str of domIcpStrings) {
          const matches = str.match(this.POLICE_BEIAN_REGEX);
          if (matches) {
            results.push(...matches);
            source = 'dom_footer_police';
          }
        }
      }

      // 如果完整正则和公安备案都没匹配到，尝试简化正则
      if (results.length === 0) {
        for (const str of domIcpStrings) {
          const matches = str.match(this.ICP_SIMPLE_REGEX);
          if (matches) {
            // 为匹配添加"号"字以规范化
            results.push(...matches.map(m => m + '号'));
            source = 'dom_footer_simple';
          }
        }
      }

      // 扩展：经营性许可证格式（闽B2-20040099-1 等，无 ICP 字样）
      if (results.length === 0) {
        for (const str of domIcpStrings) {
          const matches = str.match(this.ICP_LICENSE_REGEX);
          if (matches) {
            results.push(...matches);
            source = 'dom_footer_license';
          }
        }
      }
    }

    // 如果DOM没找到，搜索整个页面文本
    if (results.length === 0 && pageText) {
      const fullMatches = pageText.match(this.ICP_FULL_REGEX);
      if (fullMatches) {
        results.push(...fullMatches);
        source = 'page_text';
      } else {
        const policeMatches = pageText.match(this.POLICE_BEIAN_REGEX);
        if (policeMatches) {
          results.push(...policeMatches);
          source = 'page_text_police';
        } else {
        const simpleMatches = pageText.match(this.ICP_SIMPLE_REGEX);
        if (simpleMatches) {
          results.push(...simpleMatches.map(m => m + '号'));
          source = 'page_text_simple';
        } else {
          const licenseMatches = pageText.match(this.ICP_LICENSE_REGEX);
          if (licenseMatches) {
            results.push(...licenseMatches);
            source = 'page_text_license';
          }
        }
      }
    }
    }

    // 去重
    const unique = [...new Set(results)];

    return {
      found: unique.length > 0,
      numbers: unique,
      source,
      count: unique.length
    };
  }

  /**
   * 检查文本是否包含ICP备案号（模糊匹配）
   * @param {string} text
   * @returns {boolean}
   */
  static hasIcpNumber(text) {
    if (!text) return false;
    // 重置lastIndex
    this.ICP_SIMPLE_REGEX.lastIndex = 0;
    return this.ICP_SIMPLE_REGEX.test(text);
  }

  /**
   * 获取ICP备案号的省份信息
   * @param {string} icpNumber - ICP备案号
   * @returns {{ province: string, isProvincialCapital: boolean }|null}
   */
  static parseIcpNumber(icpNumber) {
    if (!icpNumber) return null;

    for (const abbr of PROVINCE_ABBREVIATIONS) {
      if (icpNumber.startsWith(abbr)) {
        return {
          province: this.getProvinceName(abbr),
          abbreviation: abbr,
          type: icpNumber.includes('ICP证') ? 'commercial' : 'filing'
        };
      }
    }
    return null;
  }

  /**
   * 省份简称 -> 全称映射
   */
  static getProvinceName(abbreviation) {
    const map = {
      '京': '北京', '津': '天津', '沪': '上海', '渝': '重庆',
      '冀': '河北', '豫': '河南', '云': '云南', '滇': '云南',
      '辽': '辽宁', '黑': '黑龙江', '湘': '湖南', '皖': '安徽',
      '鲁': '山东', '新': '新疆', '苏': '江苏', '浙': '浙江',
      '赣': '江西', '鄂': '湖北', '桂': '广西', '甘': '甘肃',
      '陇': '甘肃', '晋': '山西', '蒙': '内蒙古', '陕': '陕西',
      '秦': '陕西', '吉': '吉林', '闽': '福建', '贵': '贵州',
      '黔': '贵州', '粤': '广东', '川': '四川', '蜀': '四川',
      '青': '青海', '藏': '西藏', '琼': '海南', '宁': '宁夏'
    };
    return map[abbreviation] || '未知';
  }

  /**
   * 获取所有省份简称
   * @returns {string[]}
   */
  static getAllProvinceAbbreviations() {
    return [...PROVINCE_ABBREVIATIONS];
  }

  /**
   * 从文本中提取所有可能的备案号候选
   * 包括非标准格式（如仅包含"备案"、"ICP"等关键词）
   * @param {string} text
   * @returns {{ candidates: string[], hasIcpKeyword: boolean }}
   */
  static extractCandidates(text) {
    if (!text) return { candidates: [], hasIcpKeyword: false };

    const hasIcpKeyword = /(?:ICP|icp|备案|beian|BeiAn|BEIAN)/.test(text);
    const candidates = [];

    // 匹配任何包含ICP和数字的行
    const lines = text.split(/[\n\r]+/);
    for (const line of lines) {
      if (/ICP.*\d{4,}/i.test(line) || /\d{4,}.*ICP/i.test(line) ||
          /备案.*\d{4,}/.test(line) || /\d{4,}.*备案/.test(line)) {
        candidates.push(line.trim().substring(0, 200));
      }
    }

    return { candidates, hasIcpKeyword };
  }

  // ==================== CJK 内容检测 & ICP 豁免判定 ====================

  /**
   * 检测页面文本中是否包含显著的中文（CJK）内容。
   *
   * 双重阈值：
   *   - CJK 字符绝对数量 >= 30 且占比 >= 8%
   *   - 或 CJK 字符 >= 500（长中文页面，即使占比低也算）
   *
   * 使用 pageText（前 15000 字符）即可有效判定，
   * 因为中文网站的前几千字符几乎必然包含大量汉字。
   *
   * @param {string} text - 页面文本
   * @returns {{ hasCJK: boolean, cjkCount: number, cjkRatio: number }}
   */
  static detectCJKContent(text) {
    if (!text || text.length === 0) {
      return { hasCJK: false, cjkCount: 0, cjkRatio: 0 };
    }

    const totalChars = text.length;
    let cjkCount = 0;

    for (let i = 0; i < totalChars; i++) {
      if (isCJKChar(text.codePointAt(i))) {
        cjkCount++;
        // 跳过代理对（emoji等），但CJK基本在多语言平面内，不会触发代理对
        // 安全起见处理一下
        if (text.codePointAt(i) > 0xFFFF) i++;
      }
    }

    const cjkRatio = cjkCount / totalChars;
    // 放宽判定：中文钓鱼页常中英混排（大量英文按钮/URL/版本号），
    // 原 0.08 占比阈值会把「有中文但英文更多」的页面误判为非中文，
    // 进而被规则三当成外国站跳过备案检查。改为：
    //   · ≥20 个汉字且占比≥0.02  → 视为中文页面
    //   · 或 ≥120 个汉字（密度很高，无论如何视为中文）
    // 纯英文外国站（如 revouninstaller.com 仅 7 汉字）仍正确判为非中文。
    const hasCJK = (cjkCount >= 20 && cjkRatio >= 0.02) || cjkCount >= 120;

    return { hasCJK, cjkCount, cjkRatio };
  }

  /**
   * 判断域名是否在 ICP 豁免白名单中。
   * 白名单包含约 150 个全球知名非中国域名，
   * 这些站点确定不需要中国 ICP 备案。
   *
   * @param {string} domain - 主机名（如 "www.google.com" 或 "google.com"）
   * @returns {boolean}
   */
  static isIcpExempt(domain) {
    if (!domain) return false;
    const normalized = domain.replace(/^www\./i, '').toLowerCase();

    // 精确匹配
    if (ICP_EXEMPT_DOMAINS.has(normalized)) return true;

    // 后缀匹配：子域名也享受豁免
    // 例如 calendar.google.com → 匹配 google.com
    const parts = normalized.split('.');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(i).join('.');
      if (ICP_EXEMPT_DOMAINS.has(parent)) return true;
    }

    return false;
  }

  /**
   * 检查 ICP 备案号是否在黑名单中（已知占位/虚假号码）
   * @param {string} icpNumber - ICP 备案号
   * @returns {boolean}
   */
  static isBlacklistedIcp(icpNumber) {
    if (!icpNumber) return false;
    const trimmed = icpNumber.trim();
    if (ICP_BLACKLIST.has(trimmed)) return true;
    // 额外检查：数字部分全部为零的号码也视为无效
    if (/\d+/.test(trimmed)) {
      const digits = trimmed.match(/\d+/g);
      if (digits && digits.some(d => /^0{6,}$/.test(d))) return true;
    }
    return false;
  }
}
