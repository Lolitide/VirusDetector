/**
 * Virus Detector — 评分引擎 (Scoring Engine)
 *
 * 实现多规则评分体系，总分 >= 100 分时判定为危险网站。
 *
 * @module scoring-engine
 *
 * 评分规则：
 *   规则一 域名仿冒         → 60 分 | 4 层递进匹配（精确段匹配 → 连字符连接匹配 → 边界包含 → 关键词堆叠）
 *   规则二 压缩包下载       → 最高 40 分 | Phase A 主动扫描跨域压缩包链接（上限 30）+ Phase B 被动下载拦截（上限 40）
 *   规则三 ICP 备案缺失     → 50 分 | 对所有网站检测 ICP 备案号
 *   规则四 链接分析         → 最高 70 分 | Part A (同页/死链/重复链接) + Part B (下载按钮/压缩包链接)
 *   规则五 代码工程化       → 最高 60 分 | 三信号组合判定（DOM复杂度+框架检测+外部资源），2信号+20，3信号+30
 *                              + 子规则：关键词预筛选 + Emoji密度检测（推广页面Emoji滥用），最高+30
 *   域名年龄评分             → 最高 60 分 | 基于 RDAP/WhoisCX 双查询的 S 型衰减函数计分，新注册域名更可疑
 *   域名年龄减分             → 最高 20 分 | 注册时间长的域名可抵消部分可疑分数（需当前分数 >= 20）
 *   下载链接跨域检测         → 最高 30 分 | 跨域 +10，命中黑名单 +20，新注册域名额外 +10
 *   下载域名黑名单           → 加成 | Phase A 主动扫描阶段黑名单链接额外加权，跨域检测提分
 *
 * 优化策略：
 *   - 可信平台白名单：Wiki/博客/代码托管等 UGC 平台的注册域命中后跳过规则一，避免误报
 *   - .edu.cn 教育机构域名前置跳过：CERNET 管理，攻击者无法注册，可信放行
 *   - PSL 统一域名标准化：注册域提取应用于白名单、官方匹配、RDAP/Whois 查询
 *   - 官方网站早期退出：域名+ICP 均确认安全后跳过规则四/五
 *   - 规则四 Part B-b 仅对压缩包链接加分，普通文件链接不再单独计分
 *   - 规则五区分三信号组合：DOM节点数+框架标记+外部资源，避免对正常简单页面误报
 *   - 规则五子规则：先通过推广关键词预筛选确认页面性质，再计算Emoji密度，分段线性映射加分
 *   - RDAP/WhoisCX 查询结果缓存 24 小时，避免重复请求
 *   - 下载域名黑名单：跨站情报复用，用户手动拦截后自动加分，90 天自动清理
 */

import { DomainDatabase } from './domain-database.js';
import { IcpUtils } from './icp-utils.js';
import { WhoisClient } from './whois-client.js';
import { DownloadBlacklist } from './download-blacklist.js';
import { UrlUtils } from '../utils/url-utils.js';
import { TrustedPlatforms } from '../utils/trusted-platforms.js';
import { TrustedDownloadHosts } from '../utils/trusted-download-hosts.js';
import {
  SCORE_THRESHOLD, SCORE_RULE_1, SCORE_RULE_2_HIGH, SCORE_RULE_2_LOW,
  SCORE_RULE_3, SCORE_RULE_3_FAKE, SCORE_RULE_5, SCORE_RULE_5_PARTIAL, RISK_LEVEL,
  SCORE_RULE_4A_SAME_PAGE, SCORE_RULE_4A_DEAD_LINK,
  SCORE_RULE_4A_DUPLICATE_LINK, SCORE_RULE_4A_DOWNLOAD_LINK_BONUS,
  SCORE_RULE_4B_DOWNLOAD_BTN, SCORE_RULE_4B_FILE_LINK, SCORE_RULE_4B_ARCHIVE_LINK,
  RULE_2_DOMAIN_SUSPICION_THRESHOLD,
  SCORE_RULE_2_PROACTIVE_MAX, SCORE_RULE_2_PER_HIGH_RISK, SCORE_RULE_2_PER_LOW_RISK,
  SCORE_RULE_2_TRUSTED_PLATFORM, SCORE_RULE_2_HIJACK,
  SCORE_RULE_2_BATCH_THRESHOLD, SCORE_RULE_2_BATCH_MULTIPLIER,
  SCORE_RULE_2_SUSPICION_MULTIPLIER,
  ARCHIVE_EXTENSIONS, AI_PAGE_THRESHOLDS, SAME_PAGE_LINK_THRESHOLD,
  DUPLICATE_LINK_THRESHOLD, DEAD_LINK_THRESHOLD,
  SCORE_DOMAIN_AGE_MAX, DOMAIN_AGE_DECAY_A, DOMAIN_AGE_DECAY_B,
  SCORE_DOMAIN_AGE_BONUS_MAX, DOMAIN_AGE_BONUS_SCORE_THRESHOLD,
  DOMAIN_AGE_BONUS_MIN_DAYS, DOMAIN_AGE_BONUS_MAX_DAYS,
  EMOJI_KEYWORD_MATCH_THRESHOLD, EMOJI_MIN_TEXT_LENGTH, EMOJI_DENSITY_MAX_SCORE,
  EMOJI_DENSITY_THRESHOLD_LOW, EMOJI_DENSITY_THRESHOLD_HIGH, PROMO_KEYWORDS,
  SCORE_DOWNLOAD_BLACKLIST, SCORE_DOWNLOAD_CROSS_DOMAIN, SCORE_DOWNLOAD_NEW_DOMAIN,
  DOWNLOAD_VALID_DAYS_THRESHOLD, DOWNLOAD_CREATION_DAYS_THRESHOLD
} from '../utils/constants.js';

// ==================== 模块级设置解析 ====================

/** 当前活跃的 settings 对象（evaluateSync/evaluateDomainAgePart 调用前设置，调用后恢复） */
let _activeSettings = null;

/**
 * 安全地板：关键阈值的最低允许值，防止用户误设导致检测完全失效。
 * 关闭检测应使用规则启用开关，而非将分值设为 0。
 */
const SAFETY_FLOORS = {
  scoreThreshold: 20,
  downloadConfirmThreshold: 10,
  rule1_score: 5,
  rule2_highScore: 5,
  rule2_lowScore: 1,
  rule3_score: 5,
  rule3_fakeScore: 5,
  rule4a_samePageScore: 5,
  rule4a_deadLinkScore: 5,
  rule4a_duplicateLinkScore: 5,
  rule4a_downloadBonus: 1,
  rule4b_downloadBtnScore: 1,
  rule4b_archiveLinkScore: 1,
  rule5_fullScore: 5,
  rule5_partialScore: 3,
  domainAge_scoreMax: 5,
  download_blacklistScore: 5,
  download_crossDomainScore: 1,
  download_newDomainScore: 1
};

/**
 * 从活跃 settings 解析配置值，未设置时回退到默认常量。
 * 替代原来的局部 `s()` 函数，解决私有方法无法访问调用者局部变量的作用域问题。
 * 内置安全地板：关键阈值不会被设为低于最低保护值。
 * @param {string} key - 设置键名
 * @param {*} defaultVal - 回退默认值
 */
function resolveSetting(key, defaultVal) {
  let value = (_activeSettings && _activeSettings[key] !== undefined) ? _activeSettings[key] : defaultVal;
  // 安全地板：数值类型的关键阈值不得低于最低保护值
  if (typeof value === 'number' && SAFETY_FLOORS[key] !== undefined) {
    value = Math.max(value, SAFETY_FLOORS[key]);
  }
  return value;
}

/**
 * 设置活跃 settings（供外部模块如 service-worker 在调用私有方法前使用）
 * @param {Object|null} settings
 */
export function setActiveSettings(settings) {
  _activeSettings = settings;
}

export class ScoringEngine {
  /**
   * 对指定标签页执行完整评估
   * @param {Object} ctx - 页面上下文
   * @returns {Object} 评估结果
   */
  static async evaluate(ctx) {
    const {
      url, domain, pageText, textSignals, icpStrings, hasIcpGovLink,
      linkMetrics, downloadState, pageMetrics
    } = ctx;

    // 规则一：域名仿冒检测（可通过设置关闭）
    const result1 = resolveSetting('rule1Enabled', true) ? this._evaluateRule1(domain) : { score: 0, triggered: false, status: 'disabled', detail: '规则一已关闭', detailCN: '域名仿冒: 已关闭' };
    const existingScore = result1.score;

    // 规则三：ICP检测（可通过设置关闭）
    const result3 = resolveSetting('rule3Enabled', true) ? this._evaluateRule3(domain, pageText, icpStrings, hasIcpGovLink, textSignals) : { score: 0, triggered: false, status: 'disabled', detail: '规则三已关闭', detailCN: 'ICP备案: 已关闭' };

    // 优化：域名检测和ICP检测均确认安全 → 跳过规则四/五（官方网站早期退出）
    const isConfirmedOfficial = (
      !result1.triggered && !result3.triggered &&
      result1.status === 'pass' && result3.status === 'pass'
    );

    let result4, result5;
    if (isConfirmedOfficial) {
      result4 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过链接分析',
        detailCN: '链接分析: 官方网站'
      };
      result5 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过代码工程化检查',
        detailCN: '代码工程化: 官方网站'
      };
    } else {
      result4 = resolveSetting('rule4Enabled', true) ? this._evaluateRule4(linkMetrics, domain) : { score: 0, triggered: false, status: 'disabled', detail: '规则四已关闭', detailCN: '链接分析: 已关闭' };
      result5 = this._evaluateRule5(pageMetrics, domain, pageText, textSignals);
    }

    // 规则二：Phase A 主动扫描 + Phase B 被动检测
    // 官方网站跳过下载检测（与规则四/五一致，避免对官网的正常压缩包下载产生误报）
    let result2;
    if (isConfirmedOfficial) {
      result2 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过下载检测',
        detailCN: '下载检测: 官方网站',
        fileName: null, proactiveHits: 0, proactiveScore: 0, reactiveTriggered: false
      };
    } else {
      result2 = resolveSetting('rule2Enabled', true) ? await this._evaluateRule2(downloadState, linkMetrics, existingScore, result1.matchedEntry, ctx.resourceGraph || null) : { score: 0, triggered: false, status: 'disabled', detail: '规则二已关闭', detailCN: '下载检测: 已关闭', fileName: null, proactiveHits: 0, proactiveScore: 0, reactiveTriggered: false };
    }

    // 域名年龄评分（Whois API）：非官方域名时调用，基于注册天数 S 型衰减计分
    let domainAgeResult = { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名年龄: 未检测', creationDays: -1 };
    if (!isConfirmedOfficial) {
      domainAgeResult = await this._evaluateDomainAge(domain);
    }

    // 计算初步总分（减分前）
    const preliminaryScore = result1.score + result2.score + result3.score +
      result4.score + result5.score + domainAgeResult.score;

    // 域名年龄减分（Whois API）：仅当初步总分 >= 阈值时应用，基于注册时长抵消可疑性
    let ageBonusResult = { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名减分: 未应用', bonusScore: 0 };
    if (!isConfirmedOfficial && preliminaryScore >= resolveSetting('domainAgeBonus_scoreThreshold', DOMAIN_AGE_BONUS_SCORE_THRESHOLD)) {
      ageBonusResult = await this._evaluateDomainAgeBonus(domain, preliminaryScore, domainAgeResult);
    }

    // 最终总分 = 初步总分 - 减分分值（减分用负数表示，相加即为减法）
    const totalScore = preliminaryScore + ageBonusResult.score;
    const isSuspicious = totalScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD);

    return {
      totalScore,
      isSuspicious,
      riskLevel: isSuspicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE,
      breakdown: {
        rule1: result1, rule2: result2, rule3: result3, rule4: result4, rule5: result5,
        domainAge: domainAgeResult, ageBonus: ageBonusResult
      },
      matchedEntry: result1.matchedEntry || null,
      correctUrl: result1.correctUrl || null,
      officialName: result1.officialName || null,
      timestamp: Date.now()
    };
  }

  /**
   * 同步评估（不含 Whois 查询）：规则一~五。
   * 用于快速首屏响应（目标 < 500ms），Whois 结果通过 evaluateDomainAgePart 异步补充。
   *
   * @param {Object} ctx - 页面上下文（与 evaluate() 相同）
   * @returns {Object} { totalScore, isSuspicious, riskLevel, breakdown, matchedEntry, correctUrl, officialName,
   *                     isConfirmedOfficial, preliminaryScore, domainAgeResult, timestamp }
   */
  static async evaluateSync(ctx, settings = null) {
    const {
      url, domain, pageText, icpStrings, hasIcpGovLink,
      linkMetrics, downloadState, pageMetrics
    } = ctx;


    // 设置模块级 _activeSettings，使私有方法可通过 resolveSetting() 读取
    const prevSettings = _activeSettings;
    _activeSettings = settings;
    // 规则一：域名仿冒检测（可通过设置关闭）
    const result1 = resolveSetting('rule1Enabled', true) ? this._evaluateRule1(domain) : { score: 0, triggered: false, status: 'disabled', detail: '规则一已关闭', detailCN: '域名仿冒: 已关闭' };
    const existingScore = result1.score;

    // 规则三：ICP检测（可通过设置关闭）
    const result3 = resolveSetting('rule3Enabled', true) ? this._evaluateRule3(domain, pageText, icpStrings, hasIcpGovLink) : { score: 0, triggered: false, status: 'disabled', detail: '规则三已关闭', detailCN: 'ICP备案: 已关闭' };

    // 官方站点早期退出
    const isConfirmedOfficial = (
      !result1.triggered && !result3.triggered &&
      result1.status === 'pass' && result3.status === 'pass'
    );

    let result4, result5;
    if (isConfirmedOfficial) {
      result4 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过链接分析',
        detailCN: '链接分析: 官方网站'
      };
      result5 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过代码工程化检查',
        detailCN: '代码工程化: 官方网站'
      };
    } else {
      result4 = resolveSetting('rule4Enabled', true) ? this._evaluateRule4(linkMetrics, domain) : { score: 0, triggered: false, status: 'disabled', detail: '规则四已关闭', detailCN: '链接分析: 已关闭' };
      result5 = resolveSetting('rule5Enabled', true) ? this._evaluateRule5(pageMetrics, domain, pageText) : { score: 0, triggered: false, status: 'disabled', detail: '规则五已关闭', detailCN: '代码工程化: 已关闭' };
    }

    // 规则二：Phase A 主动扫描 + Phase B 被动检测
    let result2;
    if (isConfirmedOfficial) {
      result2 = {
        score: 0, triggered: false, status: 'pass',
        detail: '官方网站，跳过下载检测',
        detailCN: '下载检测: 官方网站',
        fileName: null, proactiveHits: 0, proactiveScore: 0, reactiveTriggered: false
      };
    } else {
      result2 = resolveSetting('rule2Enabled', true) ? await this._evaluateRule2(downloadState, linkMetrics, existingScore, result1.matchedEntry, ctx.resourceGraph || null) : { score: 0, triggered: false, status: 'disabled', detail: '规则二已关闭', detailCN: '下载检测: 已关闭', fileName: null, proactiveHits: 0, proactiveScore: 0, reactiveTriggered: false };
    }

    // 域名年龄：从缓存读取（不发起网络请求），供异步阶段复用
    const domainAgeResultCached = WhoisClient.getCached(domain);

    // 初步总分（不含域名年龄加减分）
    const preliminaryScore = result1.score + result2.score + result3.score +
      result4.score + result5.score;

    // 基于缓存快速计算（如果缓存命中）
    let domainAgeResult = { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名年龄: 等待查询', creationDays: -1 };
    let ageBonusResult = { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名减分: 等待查询', bonusScore: 0 };

    if (!isConfirmedOfficial && domainAgeResultCached && domainAgeResultCached.creationDays >= 0) {
      // 缓存命中：同步计算域名年龄评分
      const x = domainAgeResultCached.creationDays;
      const denominator = 1 + Math.pow(x / (60 * resolveSetting('domainAge_decayB', DOMAIN_AGE_DECAY_B)), resolveSetting('domainAge_decayA', DOMAIN_AGE_DECAY_A));
      const rawScore = resolveSetting('domainAge_scoreMax', SCORE_DOMAIN_AGE_MAX) / denominator;
      const score = Math.floor(rawScore);
      if (score > 0) {
        domainAgeResult = {
          score, triggered: true, status: 'pass',
          detail: `域名注册仅${x}天（Whois缓存），可疑加分+${score}`,
          detailCN: `域名年龄: 注册仅${x}天，可疑 +${score}`,
          creationDays: x
        };
      } else {
        domainAgeResult = {
          score: 0, triggered: false, status: 'pass',
          detail: `域名注册${x}天（Whois缓存），年龄正常`,
          detailCN: `域名年龄: 已注册${x}天`,
          creationDays: x
        };
      }

      // 缓存命中时可同步计算减分
      if (preliminaryScore + domainAgeResult.score >= resolveSetting('domainAgeBonus_scoreThreshold', DOMAIN_AGE_BONUS_SCORE_THRESHOLD)) {
        const creationDays = x;
        let bonusScore = 0;
        if (creationDays < resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS)) {
          bonusScore = 0;
        } else if (creationDays < resolveSetting('domainAgeBonus_maxDays', DOMAIN_AGE_BONUS_MAX_DAYS)) {
          bonusScore = Math.floor(
            SCORE_DOMAIN_AGE_BONUS_MAX * (creationDays - resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS)) /
            (resolveSetting('domainAgeBonus_maxDays', DOMAIN_AGE_BONUS_MAX_DAYS) - resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS))
          );
        } else {
          bonusScore = SCORE_DOMAIN_AGE_BONUS_MAX;
        }
        if (bonusScore > 0) {
          const effectiveBonus = Math.min(bonusScore, preliminaryScore + domainAgeResult.score);
          ageBonusResult = {
            score: -effectiveBonus, triggered: true, status: 'pass',
            detail: `域名注册${creationDays}天，年龄减分-${effectiveBonus}`,
            detailCN: `域名减分: 已注册${creationDays}天，年龄抵消 -${effectiveBonus}`,
            bonusScore: effectiveBonus
          };
        }
      }
    }

    // 最终总分（缓存命中时已含域名年龄，缓存未命中时仅含规则一~五）
    const totalScore = preliminaryScore + domainAgeResult.score + ageBonusResult.score;
    const isSuspicious = totalScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD);

    return {
      totalScore,
      isSuspicious,
      riskLevel: isSuspicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE,
      breakdown: {
        rule1: result1, rule2: result2, rule3: result3, rule4: result4, rule5: result5,
        domainAge: domainAgeResult, ageBonus: ageBonusResult
      },
      matchedEntry: result1.matchedEntry || null,
      correctUrl: result1.correctUrl || null,
      officialName: result1.officialName || null,
      // 供异步阶段使用
      isConfirmedOfficial,
      preliminaryScore: preliminaryScore + domainAgeResult.score,  // 含缓存域名年龄
      _syncDomainAgeResult: domainAgeResult,
      timestamp: Date.now()
    };
    _activeSettings = prevSettings;
  }

  /**
   * 异步补充 Whois 域名年龄评分（不阻塞主流程）。
   * 在 evaluateSync() 之后调用，发起实际网络请求获取域名注册信息。
   *
   * @param {string} domain - 页面域名
   * @param {number} preliminaryScore - evaluateSync 返回的初步总分（含缓存域名年龄）
   * @param {Object} syncDomainAgeResult - evaluateSync 返回的 _syncDomainAgeResult
   * @param {boolean} isConfirmedOfficial - 是否为官方站点
   * @returns {Promise<Object>} { domainAgeResult, ageBonusResult, totalScore, isSuspicious, riskLevel }
   */
  static async evaluateDomainAgePart(domain, preliminaryScore, syncDomainAgeResult, isConfirmedOfficial, settings = null) {
    let domainAgeResult = syncDomainAgeResult || { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名年龄: 未检测', creationDays: -1 };
    let ageBonusResult = { score: 0, triggered: false, status: 'pass', detail: '', detailCN: '域名减分: 未应用', bonusScore: 0 };

    // 设置模块级 _activeSettings
    const prevSettings = _activeSettings;
    _activeSettings = settings;

    if (isConfirmedOfficial) {
      return { domainAgeResult, ageBonusResult, totalScore: preliminaryScore, isSuspicious: false, riskLevel: RISK_LEVEL.SAFE };
    }

    // 缓存未命中 → 发起 Whois 查询
    if (syncDomainAgeResult.creationDays < 0) {
      const whoisResult = await WhoisClient.lookup(domain);

      if (!whoisResult) {
        const errInfo = WhoisClient.lastError;
        const errPhase = errInfo ? ` [${errInfo.phase}]` : '';
        const errMsg = errInfo ? `: ${errInfo.message}` : '';
        domainAgeResult = {
          score: 0, triggered: false, status: 'neutral',
          detail: `Whois API 查询失败${errPhase}${errMsg} (${domain})`,
          detailCN: `域名年龄: API 查询失败${errPhase}`,
          creationDays: -1
        };
        return { domainAgeResult, ageBonusResult, totalScore: preliminaryScore, isSuspicious: preliminaryScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD), riskLevel: preliminaryScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD) ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE };
      }

      if (whoisResult.creationDays < 0) {
        domainAgeResult = {
          score: 0, triggered: false, status: 'neutral',
          detail: `Whois API 返回的域名注册天数未知 (${domain})`,
          detailCN: '域名年龄: 注册时间未知',
          creationDays: -1
        };
        return { domainAgeResult, ageBonusResult, totalScore: preliminaryScore, isSuspicious: preliminaryScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD), riskLevel: preliminaryScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD) ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE };
      }

      const x = whoisResult.creationDays;
      const denominator = 1 + Math.pow(x / (60 * resolveSetting('domainAge_decayB', DOMAIN_AGE_DECAY_B)), resolveSetting('domainAge_decayA', DOMAIN_AGE_DECAY_A));
      const rawScore = resolveSetting('domainAge_scoreMax', SCORE_DOMAIN_AGE_MAX) / denominator;
      const score = Math.floor(rawScore);

      if (score > 0) {
        domainAgeResult = {
          score, triggered: true, status: 'pass',
          detail: `域名注册仅${x}天（Whois），可疑加分+${score}（raw=${rawScore.toFixed(2)}）`,
          detailCN: `域名年龄: 注册仅${x}天，可疑 +${score}`,
          creationDays: x
        };
      } else {
        domainAgeResult = {
          score: 0, triggered: false, status: 'pass',
          detail: `域名注册${x}天（Whois），年龄正常`,
          detailCN: `域名年龄: 已注册${x}天`,
          creationDays: x
        };
      }
    }

    // 计算新的初步总分（含域名年龄加分）
    const newPreliminaryScore = preliminaryScore - (syncDomainAgeResult.score || 0) + domainAgeResult.score;

    // 域名年龄减分
    if (newPreliminaryScore >= resolveSetting('domainAgeBonus_scoreThreshold', DOMAIN_AGE_BONUS_SCORE_THRESHOLD) && domainAgeResult.creationDays >= 0) {
      const creationDays = domainAgeResult.creationDays;
      let bonusScore = 0;
      if (creationDays < resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS)) {
        bonusScore = 0;
      } else if (creationDays < resolveSetting('domainAgeBonus_maxDays', DOMAIN_AGE_BONUS_MAX_DAYS)) {
        bonusScore = Math.floor(
          resolveSetting('domainAgeBonus_max', SCORE_DOMAIN_AGE_BONUS_MAX) * (creationDays - resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS)) /
          (resolveSetting('domainAgeBonus_maxDays', DOMAIN_AGE_BONUS_MAX_DAYS) - resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS))
        );
      } else {
        bonusScore = SCORE_DOMAIN_AGE_BONUS_MAX;
      }

      if (bonusScore > 0) {
        const effectiveBonus = Math.min(bonusScore, newPreliminaryScore);
        ageBonusResult = {
          score: -effectiveBonus, triggered: true, status: 'pass',
          detail: `域名注册${creationDays}天，年龄减分-${effectiveBonus}（原始bonus=${bonusScore}，减分前=${newPreliminaryScore}）`,
          detailCN: `域名减分: 已注册${creationDays}天，年龄抵消 -${effectiveBonus}`,
          bonusScore: effectiveBonus
        };
      }
    }

    const totalScore = newPreliminaryScore + ageBonusResult.score;
    const isSuspicious = totalScore >= resolveSetting('scoreThreshold', SCORE_THRESHOLD);

    return {
      domainAgeResult,
      ageBonusResult,
      totalScore,
      isSuspicious,
      riskLevel: isSuspicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE
    };
    _activeSettings = prevSettings;
  }

  // ==================== 规则一：域名仿冒 (60分) ====================
  static _evaluateRule1(domain) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '域名检查: 无异常',
      matchedEntry: null, correctUrl: null, officialName: null
    };

    const mainDomain = UrlUtils.getMainDomain(domain);

    // ---- 教育机构域名前置检查 ----
    // .edu.cn 由 CERNET 管理，仅限教育机构申请，攻击者无法注册，可安全跳过
    if (domain.endsWith('.edu.cn')) {
      result.detail = '教育机构域名（.edu.cn），跳过域名仿冒检测';
      result.detailCN = '域名: 教育机构域名';
      return result;
    }

    // ---- 可信平台白名单前置检查 ----
    if (TrustedPlatforms.isTrusted(mainDomain)) {
      result.detail = `可信平台（${mainDomain}），跳过域名仿冒检测`;
      result.detailCN = `域名: 可信平台（${mainDomain}）`;
      return result;
    }

    // 精确匹配官方域名（使用 PSL 注册域）→ 安全
    const official = DomainDatabase.findByDomain(mainDomain);
    if (official) {
      result.detail = '官方网站，域名匹配';
      result.detailCN = '域名: 官方网站';
      return result;
    }

    // 检测域名仿冒（使用完整 hostname，子域名中可能含品牌关键词）
    const spoof = DomainDatabase.detectSpoof(domain);
    if (spoof) {
      result.score = resolveSetting('rule1_score', SCORE_RULE_1);  // +60
      result.triggered = true;
      result.matchedEntry = spoof.entry;
      result.correctUrl = spoof.correctUrl;
      result.officialName = spoof.entry.name;
      result.detail = `域名仿冒检测: ${spoof.matchedBy}`;
      result.detailCN = `域名仿冒: 疑似冒充「${spoof.entry.name}」(${spoof.correctUrl})`;
      return result;
    }

    return result;
  }

  /**
   * 获取 CJK 内容判定结果。
   * 新版本优先使用 Content Script 本地计算的派生指标，避免传输/持久化页面正文。
   * @param {string} pageText - 兼容旧消息的页面正文
   * @param {Object|null} textSignals - 派生文本指标
   * @returns {{hasCJK: boolean, cjkCount: number, cjkRatio: number}}
   */
  static _getCjkResult(pageText, textSignals) {
    if (textSignals && typeof textSignals === 'object' &&
        typeof textSignals.hasCJK === 'boolean') {
      return {
        hasCJK: textSignals.hasCJK,
        cjkCount: Number(textSignals.cjkCount || 0),
        cjkRatio: Number(textSignals.cjkRatio || 0)
      };
    }
    return IcpUtils.detectCJKContent(pageText || '');
  }

  // ==================== 规则二：压缩包下载 (最高 40 分) ====================
  /**
   * 规则二：压缩包下载检测（两阶段递进评分）
   *
   * Phase A — 主动检测（页面扫描，L0）：
   *   扫描页面上所有跨域压缩包下载链接，根据风险分类和数量计算得分。
   *   上限 30 分。域名嫌疑越高、链接越多，得分越重。
   *
   * Phase B — 被动检测（实际下载，L3 兜底）：
   *   用户实际触发了压缩包下载。域名嫌疑高 → +40，低 → +10。
   *
   * 最终得分 = max(Phase A, Phase B)，实现"主动可提前、被动可升级"。
   *
   * @param {Object} downloadState - 下载事件状态（被动数据）
   * @param {Object} linkMetrics   - 链接分析数据（主动数据，来自 Content Script）
   * @param {number} existingSuspicionScore - 其他规则已累计的分数
   * @returns {Promise<Object>} 评分结果
   */
  static async _evaluateRule2(downloadState, linkMetrics, existingSuspicionScore, matchedEntry, resourceGraph = null) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '下载检测: 未检测到压缩包',
      fileName: null,
      proactiveHits: 0,
      proactiveScore: 0,
      reactiveTriggered: false
    };

    // ═══════════════════════════════════════════════
    // Phase A — 主动检测（基于页面扫描）
    // ═══════════════════════════════════════════════

    // 优先使用 ResourceGraph 数据（新版），linkMetrics 作为回退（旧版）
    let archiveLinks;
    if (resourceGraph && resourceGraph.discoveredArchives && resourceGraph.discoveredArchives.length > 0) {
      // 从 ResourceGraph 转换归档节点为 Rule2 可用的格式
      archiveLinks = resourceGraph.discoveredArchives.map(function(node) {
        return {
          href: node.url,
          text: (node.metadata && node.metadata.textSnippet) || '',
          isCrossDomain: node.metadata ? node.metadata.isCrossDomain : false,
          hasDownloadKW: false, // Graph 不跟踪下载关键词，默认为 false
          ext: (node.metadata && node.metadata.ext) || '',
          sourceType: node.sourceType || 'resource_graph'
        };
      });
    } else {
      // 回退：使用 linkMetrics（旧版数据源）
      archiveLinks = (linkMetrics && linkMetrics.archiveDownloadLinks)
        ? linkMetrics.archiveDownloadLinks : [];
    }

    if (archiveLinks.length > 0) {
      // 1. 筛选跨域链接（同域不计分，仅跟踪）
      const crossDomainLinks = archiveLinks.filter(l => l.isCrossDomain);

      if (crossDomainLinks.length > 0) {
        // 2. 对每个跨域压缩包链接分类计分（含黑名单+可信平台+劫持检测）
        let baseScore = 0;
        let blacklistBonus = 0;
        let blacklistHits = 0;
        let trustedPlatformCount = 0;
        let hijackCount = 0;

        // 劫持检测前置准备：如果规则一已识别出仿冒目标，收集其官方域名集合
        const officialDomainSet = (matchedEntry && matchedEntry.officialDomains)
          ? new Set(matchedEntry.officialDomains.map(d => d.toLowerCase())) : null;

        for (const link of crossDomainLinks) {
          let downloadDomain;
          try {
            downloadDomain = new URL(link.href, 'http://placeholder').hostname;
          } catch (e) { continue; }

          // 优先级1：黑名单检查（最高优先级，不可绕过）
          if (await DownloadBlacklist.isBlacklisted(downloadDomain)) {
            blacklistBonus += SCORE_RULE_2_PER_HIGH_RISK;
            blacklistHits++;
            continue;
          }

          // 优先级2：可信下载平台 → 降权
          if (TrustedDownloadHosts.isTrusted(downloadDomain)) {
            baseScore += SCORE_RULE_2_TRUSTED_PLATFORM;  // +3
            trustedPlatformCount++;
            continue;
          }

          // 优先级3：官网下载链接劫持检测
          // 条件：规则一已命中仿冒 且 下载链接域名不在被仿冒品牌的官方域名列表中
          if (officialDomainSet) {
            try {
              const dlMainDomain = UrlUtils.getMainDomain(downloadDomain);
              if (!officialDomainSet.has(dlMainDomain) &&
                  ![...officialDomainSet].some(od => downloadDomain.endsWith('.' + od))) {
                hijackCount++;
                // 劫持链接不参与常规分类计分，单独计入劫持加分（下方统一处理）
                continue;
              }
            } catch (e) { /* 域名提取失败，走常规分类 */ }
          }

          // 优先级4：常规分类
          if (link.hasDownloadKW) {
            baseScore += SCORE_RULE_2_PER_HIGH_RISK;  // 🔴 高危：跨域+下载关键词
          } else {
            baseScore += SCORE_RULE_2_PER_LOW_RISK;   // 🟠 中危：跨域+无下载关键词
          }
        }

        // 官网劫持加分：每个非官方下载链接 +30（硬上限 60），不参与批量/嫌疑加权
        let hijackScore = 0;
        if (resolveSetting('hijackDetection', true) && hijackCount > 0) {
          hijackScore = Math.min(hijackCount * resolveSetting('rule2_hijackScore', SCORE_RULE_2_HIJACK), 60);
        }

        // 3. 批量加权：≥阈值时基础分翻倍（仅 baseScore 参与，hijackScore/blacklistBonus 独立）
        if (crossDomainLinks.length >= SCORE_RULE_2_BATCH_THRESHOLD) {
          baseScore = Math.floor(baseScore * SCORE_RULE_2_BATCH_MULTIPLIER);
        }

        // 4. 域名嫌疑加权：其他规则已有 ≥30 分时乘 1.5（仅作用于 baseScore）
        if (existingSuspicionScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
          baseScore = Math.floor(baseScore * SCORE_RULE_2_SUSPICION_MULTIPLIER);
        }

        // 5. Phase A 总分 = baseScore(上限30) + blacklistBonus + hijackScore
        const proactiveScore = Math.min(baseScore, SCORE_RULE_2_PROACTIVE_MAX);
        const totalProactiveScore = proactiveScore + blacklistBonus + hijackScore;

        if (totalProactiveScore > 0) {
          result.proactiveScore = totalProactiveScore;
          result.proactiveHits = crossDomainLinks.length;
          result.score = totalProactiveScore;
          result.triggered = true;

          const detailParts = [];
          detailParts.push(crossDomainLinks.length + '个跨域压缩包链接');
          if (crossDomainLinks.length >= SCORE_RULE_2_BATCH_THRESHOLD) {
            detailParts.push('批量分发');
          }
          if (existingSuspicionScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
            detailParts.push('域名已有' + existingSuspicionScore + '分嫌疑');
          }
          if (blacklistHits > 0) {
            detailParts.push(blacklistHits + '个命中下载黑名单');
          }
          if (trustedPlatformCount > 0) {
            detailParts.push(trustedPlatformCount + '个指向可信平台（降权）');
          }
          if (hijackCount > 0) {
            detailParts.push(hijackCount + '个链接疑似劫持（指向非官方域名）');
          }
          result.detail = '页面存在压缩包下载链接: ' + detailParts.join('; ') + ' (+' + totalProactiveScore + ')';
          result.detailCN = '下载检测: 页面有' + crossDomainLinks.length + '个跨域压缩包链接';
          if (blacklistHits > 0) {
            result.detailCN += '（' + blacklistHits + '个命中黑名单）';
          }
          if (hijackCount > 0) {
            result.detailCN += '（' + hijackCount + '个疑似劫持）';
          }
          result.detailCN += ' +' + totalProactiveScore;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // ResourceGraph 专项加分（多级跳转 / 重定向链 / 可执行文件）
    // ═══════════════════════════════════════════════════════
    if (resourceGraph) {
      let graphBonus = 0;
      const graphBonusParts = [];

      // 1. 多级 TXT 跳转：txtDepth > 1 表示存在 TXT→TXT→...→ZIP 链
      if (resourceGraph.txtDepth > 1) {
        const txtBonus = Math.min(15, (resourceGraph.txtDepth - 1) * 8);
        graphBonus += txtBonus;
        graphBonusParts.push('TXT' + resourceGraph.txtDepth + '级跳转');
      }

      // 2. 重定向链：存在 HTTP 30x 重定向
      if (resourceGraph.redirectChain && resourceGraph.redirectChain.length > 0) {
        const redirectBonus = Math.min(10, resourceGraph.redirectChain.length * 3);
        graphBonus += redirectBonus;
        graphBonusParts.push(resourceGraph.redirectChain.length + '次重定向');
      }

      // 3. 可执行文件（受 detectNonArchiveFiles 开关控制）
      if (resolveSetting('detectNonArchiveFiles', false) &&
          resourceGraph.discoveredExecutables && resourceGraph.discoveredExecutables.length > 0) {
        const exeCount = resourceGraph.discoveredExecutables.length;
        const exeBonus = Math.min(20, exeCount * 5);
        graphBonus += exeBonus;
        graphBonusParts.push(exeCount + '个可执行文件');
      }

      if (graphBonus > 0) {
        result.score = Math.max(result.score, graphBonus);
        result.proactiveScore = Math.max(result.proactiveScore, graphBonus);
        if (!result.triggered) result.triggered = true;

        const existingDetail = result.detail ? result.detail + ' | ' : '';
        result.detail = existingDetail + 'ResourceGraph: ' + graphBonusParts.join('; ') + ' (+' + graphBonus + ')';
        if (result.detailCN) {
          result.detailCN += ' | 多级跳转加分+' + graphBonus;
        } else {
          result.detailCN = '下载检测: ' + graphBonusParts.join(', ') + ' +' + graphBonus;
        }
      }
    }

    // ═══════════════════════════════════════════════
    // Phase B — 被动检测（实际下载发生，L3 兜底）
    // ═══════════════════════════════════════════════
    if (downloadState && downloadState.hasDownloadedArchive) {
      result.fileName = downloadState.archiveFileName || '未知文件';
      result.reactiveTriggered = true;

      let reactiveScore;
      if (existingSuspicionScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
        reactiveScore = resolveSetting('rule2_highScore', SCORE_RULE_2_HIGH);  // +40
      } else {
        reactiveScore = resolveSetting('rule2_lowScore', SCORE_RULE_2_LOW);   // +10
      }

      // Phase B 可以覆盖 Phase A（实际下载是更强信号）
      if (reactiveScore > result.score) {
        result.score = reactiveScore;
        result.triggered = true;
        result.detail = '下载压缩包: ' + result.fileName +
          ' (域名已有' + existingSuspicionScore + '分嫌疑)';
        result.detailCN = '下载检测: 从可疑站点下载压缩包 (' + result.fileName + ')';
      }
    }

    return result;
  }

  // ==================== 规则三：ICP备案号缺失 (50分) ====================
  /**
   * 规则三：ICP备案检测（≤50分）
   *
   * 判定链路：
   *   1. 官方域名                          → 0  PASS
   *   2a. ICP + 非黑名单 + 可点击政府链接    → 0  PASS（已核验）
   *   2b. ICP + 缺政府链接 且 页有中文       → +50 TRIGGERED（虚假备案嫌疑）
   *   2c. ICP + 缺政府链接 且 无中文         → +30 TRIGGERED（虚假备案嫌疑）
   *   2d. ICP 号码在黑名单中                → 同 2b/2c（按有无中文判定）
   *   3.  无 ICP + 豁免白名单               → 0  NEUTRAL
   *   4.  无 ICP + 有中文                   → +50 TRIGGERED
   *   5.  无 ICP + 无中文 + 非白名单         → +20 WARN
   */
  static _evaluateRule3(domain, pageText, icpStrings, hasIcpGovLink, textSignals) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '', icpFound: false, icpNumbers: [],
      icpVerified: false, icpBlacklisted: false
    };

    // 1. 官方域名本尊 → 跳过
    const official = DomainDatabase.findByDomain(domain);
    if (official) {
      result.status = 'pass';
      result.detail = '官方网站，ICP检查通过';
      result.detailCN = 'ICP备案: 官方网站';
      return result;
    }

    // 2. 搜索 ICP 备案号（含真实验证）
    const icpResult = IcpUtils.searchIcpNumber(pageText || '', icpStrings);

    if (icpResult.found) {
      const realNumbers = icpResult.numbers.filter(n => !IcpUtils.isBlacklistedIcp(n));
      const hasBlacklisted = realNumbers.length < icpResult.numbers.length;
      result.icpBlacklisted = hasBlacklisted;

      // 2a. 真实验证通过 → 完全安全
      if (realNumbers.length > 0 && hasIcpGovLink) {
        result.status = 'pass';
        result.icpFound = true;
        result.icpVerified = true;
        result.icpNumbers = realNumbers;
        result.detail = `检测到ICP备案号: ${realNumbers[0]}（已核验）`;
        result.detailCN = `ICP备案: 检测到 (${realNumbers[0]})`;
        return result;
      }

      // 2b/2c/2d: ICP 存在但不可核验 → 可疑行为，直接加分
      result.icpFound = true;
      if (realNumbers.length > 0) result.icpNumbers = realNumbers;

      // 根据中文内容判定分数
      const cjkResult = this._getCjkResult(pageText, textSignals);
      if (cjkResult.hasCJK) {
        result.score = SCORE_RULE_3;  // +50 — 中文站用虚假/未核验备案
        result.triggered = true;
        let reason = result.icpBlacklisted ? '备案号疑似虚假' : '备案号缺少可点击核验链接';
        result.detail = `ICP备案疑似虚假（域名${domain}，${reason}，页面含${cjkResult.cjkCount}个中文字符）`;
        result.detailCN = `ICP备案: 虚假/未核验（${reason}）`;
        return result;
      } else {
        result.score = resolveSetting('rule3_fakeScore', SCORE_RULE_3_FAKE);  // +30 — 无中文但显示了虚假备案号
        result.triggered = true;
        let reason = result.icpBlacklisted ? '备案号疑似虚假' : '备案号缺少可点击核验链接';
        result.detail = `ICP备案疑似虚假（域名${domain}，${reason}，页面无中文内容）`;
        result.detailCN = `ICP备案: 虚假/未核验（${reason}）`;
        return result;
      }
    }

    // 3. 未找到 ICP → 判定是否需要备案
    // 3a. 外国站点豁免白名单 → 确定不需要 ICP
    if (IcpUtils.isIcpExempt(domain)) {
      result.status = 'neutral';
      result.detail = `外国站点（${domain}），ICP检查不适用`;
      result.detailCN = 'ICP备案: 外国站点（不适用）';
      return result;
    }

    // 3b. 页面内容检测：有显著中文内容 → 中国站点，必须有 ICP
    const cjkResult = this._getCjkResult(pageText, textSignals);
    if (cjkResult.hasCJK) {
      result.score = SCORE_RULE_3;  // +50
      result.triggered = true;
      result.detail = `未检测到ICP备案号（域名${domain}，页面含${cjkResult.cjkCount}个中文字符，占比${(cjkResult.cjkRatio * 100).toFixed(1)}%）`;
      result.detailCN = 'ICP备案: 未检测到备案号';
      return result;
    }

    // 3c. 不在白名单 + 无 CJK 内容 → 弱信号
    result.score = 20;
    result.status = 'warn';
    result.detail = `无中文内容且非已知外国站点（域名${domain}），缺少ICP为弱信号`;
    result.detailCN = 'ICP备案: 未检测到备案号（弱信号）';

    return result;
  }

  // ==================== 规则四：链接分析 ====================
  /**
   * ┌─ Part A（先执行）:
   * │  ① ≥3个链接指向当前页本身（完整URL完全一致）         → +20
   * │  ② ≥1个死链（指向不存在子页面，非hash/js占位）       → +20
   * │  ③ ≥4个不同元素指向同一个链接                         → +20
   * │     若该链接为下载链接（含down/download等）            → 再+10
   * │  ①+②+③ 可叠加（最高+70）
   * └─ Part B（仅当Part A总分为0时才执行）:
   *     a. 外链绑定在"下载"按钮上       → +10
   *     b. 外链指向压缩包格式文件       → +10
   */
  static _evaluateRule4(linkMetrics, domain) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '链接分析: 正常'
    };

    if (!linkMetrics) {
      result.status = 'neutral';
      result.detail = '未收集到链接数据';
      result.detailCN = '链接分析: 未检测';
      return result;
    }

    let partAScore = 0;
    const partAReasons = [];

    // Part A-①：≥5个链接指向当前页本身（完整URL完全一致）
    if (linkMetrics.samePageLinks >= SAME_PAGE_LINK_THRESHOLD) {
      partAScore += SCORE_RULE_4A_SAME_PAGE;
      partAReasons.push(linkMetrics.samePageLinks + '个链接完全指向当前页');
    }

    // Part A-②：≥DEAD_LINK_THRESHOLD 个死链（HEAD请求验证为不存在子页面）
    if (linkMetrics.deadLinks >= DEAD_LINK_THRESHOLD) {
      partAScore += SCORE_RULE_4A_DEAD_LINK;
      partAReasons.push(linkMetrics.deadLinks + '个死链/不存在子页面');
    }

    // Part A-③：非线性计分 — 重复元素越多，得分对数增长（3个起计，30分封顶）
    //           score = min(30, 8 * log2(n))，其中 n = 指向同一链接的不同元素数
    if (linkMetrics.hasDuplicateLinks && linkMetrics.duplicateLinks) {
      for (const dup of linkMetrics.duplicateLinks) {
        const n = dup.elementCount;
        if (n >= 4) {
          const dupScore = Math.floor(Math.min(30, 8 * Math.log2(n)));
          partAScore += dupScore;
          partAReasons.push(n + '个不同元素指向同一链接');
          // 附加分：该链接为下载链接
          if (dup.isDownloadLink) {
            partAScore += SCORE_RULE_4A_DOWNLOAD_LINK_BONUS;
            partAReasons.push('该重复链接为下载链接');
          }
        }
        break; // 只计一次（取第一个满足条件的）
      }
    }

    if (partAScore > 0) {
      result.score = partAScore;
      result.triggered = true;
      result.detail = '链接异常(Part A): ' + partAReasons.join('; ');
      result.detailCN = '链接分析: ' + partAReasons.join(', ') + ' (+' + partAScore + ')';
      return result;
    }

    // Part A 未触发 → Part B
    let partBScore = 0;
    const partBReasons = [];

    if (linkMetrics.externalWithDownloadText >= 1) {
      partBScore += SCORE_RULE_4B_DOWNLOAD_BTN;
      partBReasons.push(linkMetrics.externalWithDownloadText + '个外链在下载按钮上');
    }
    // Part B-b：仅压缩包链接加分（普通文件链接不再单独计分）
    if (linkMetrics.externalArchiveLinks >= 1) {
      partBScore += SCORE_RULE_4B_ARCHIVE_LINK;
      partBReasons.push(linkMetrics.externalArchiveLinks + '个外链指向压缩包');
    }

    // Part C：页面文本/TXT中的隐藏压缩包链接（多级跳转检测）
    // 仅当 Part A 和 Part B 均未触发强信号时执行，避免与明确证据叠加
    let partCScore = 0;
    const partCReasons = [];

    if (partBScore < 30) {
      // C-a：页面文本中扫描到的跨域压缩包链接（非 <a> 标签，置信度较低，每链接 +5）
      if (linkMetrics.textArchiveUrls && linkMetrics.textArchiveUrls.length > 0) {
        const crossDomainTextUrls = linkMetrics.textArchiveUrls.filter(function(u) { return u.isCrossDomain; });
        if (crossDomainTextUrls.length > 0) {
          const textScore = Math.min(20, crossDomainTextUrls.length * 5);
          partCScore += textScore;
          partCReasons.push('页面文本中发现' + crossDomainTextUrls.length + '个隐藏压缩包链接');
        }
      }

      // C-b：.txt 文件中解析出的跨域压缩包链接（置信度较高，每链接 +8）
      if (linkMetrics.txtDerivedArchiveUrls && linkMetrics.txtDerivedArchiveUrls.length > 0) {
        const crossDomainTxtUrls = linkMetrics.txtDerivedArchiveUrls.filter(function(u) { return u.isCrossDomain; });
        if (crossDomainTxtUrls.length > 0) {
          const txtScore = Math.min(20, crossDomainTxtUrls.length * 8);
          partCScore += txtScore;
          partCReasons.push('.txt文件中发现' + crossDomainTxtUrls.length + '个隐藏压缩包链接');
        }
      }
    }

    if (partCScore > 0) {
      result.score = partBScore + partCScore;
      result.triggered = true;
      const allReasons = partBReasons.concat(partCReasons);
      result.detail = '链接风险(Part B+C): ' + allReasons.join('; ');
      result.detailCN = '链接分析: ' + allReasons.join(', ') + ' (+' + (partBScore + partCScore) + ')';
    } else if (partBScore > 0) {
      result.score = partBScore;
      result.triggered = true;
      result.detail = '外链风险(Part B): ' + partBReasons.join('; ');
      result.detailCN = '链接分析: ' + partBReasons.join(', ') + ' (+' + partBScore + ')';
    } else {
      result.detail = '链接分析未发现异常';
      result.detailCN = '链接分析: 正常';
    }

    return result;
  }

  // ==================== 规则五：代码工程化检测（最高60分） ====================
  /**
   * 检测页面代码质量，基于多信号组合判定体系：
   *
   * 前提：页面文本内容 > 500 字符（排除空白/占位页面，避免误报）
   *
   * 结构信号：
   *   信号1 — DOM节点数 < 100       （页面结构过于简单，不受HTML格式化影响）
   *   信号2 — 无主流框架痕迹         （资源 URL + DOM 特征 + HTML 标记检测）
   *   信号3 — 外部资源去重总数 < 5    （脚本+样式+图片+字体+媒体，不含同源资源）
   *   信号4 — 可疑 JS 引用模式        （模板化语言包/通用脚本路径等克隆式资源布局）
   *
   * 组合判定（信号数替代原OR逻辑，降低对正常简单页面的误报）：
   *   ≥3 个信号命中 → +30 分（高度可疑：经典钓鱼空壳/克隆站特征齐备）
   *   2 个信号命中 → +20 分（中度可疑：两个维度异常）
   *   0-1 信号     →   0 分（证据不足，不单独加分）
   *
   * 设计原则：
   *   - 正常页面几乎不会多个结构信号同时命中（即有外部资源、有框架、DOM复杂）
   *   - 单信号在正常页面中常见（如简单博客无框架），不应处罚
   *   - 钓鱼/AI生成页面通常同时满足多个信号，组合判定可精准识别
   *
   * @param {Object} pageMetrics - 来自 content script 的页面度量
   * @param {string} domain - 页面域名（保留参数，供未来扩展）
   * @param {string} pageText - 页面文本内容（兼容旧消息；新消息使用 textSignals）
   * @param {Object} textSignals - 内容脚本本地计算的派生文本指标
   */
  static _evaluateRule5(pageMetrics, domain, pageText, textSignals) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '代码工程化: 正常',
      metrics: pageMetrics || {}
    };

    if (!pageMetrics) {
      result.status = 'neutral';
      result.detail = '未收集到页面度量信息';
      result.detailCN = '代码工程化: 未检测';
      return result;
    }

    // ---- 子规则 B：关键词预筛选 + Emoji 密度检测（独立于三信号体系） ----
    const emojiDensityResult = resolveSetting('emojiDensityCheck', true)
      ? this._evaluateRule5EmojiDensity(pageText, textSignals)
      : { score: 0, triggered: false, status: 'disabled', detail: 'Emoji密度检测已关闭', detailCN: 'Emoji密度: 已关闭', density: 0 };

    // ---- 子规则 A：结构信号组合判定 ----
    let signalScore = 0;
    let signalDetail = '';
    let signalDetailCN = '';
    let signalTriggered = false;

    if (pageMetrics.textLength >= AI_PAGE_THRESHOLDS.MIN_TEXT_LENGTH) {
      const domNodeCount = pageMetrics.domNodeCount || 0;
      const hasExternal = !!(pageMetrics.hasExternalResources);
      const totalExternal = pageMetrics.totalExternalResources || 0;
      const hasFramework = !!(pageMetrics.hasFrameworkMarkers);
      const suspiciousScriptRefCount = pageMetrics.suspiciousScriptRefCount || 0;

      // 收集命中的信号
      const signals = [];

      // 信号1：DOM节点数过少
      if (domNodeCount > 0 && domNodeCount < AI_PAGE_THRESHOLDS.MIN_DOM_NODES) {
        signals.push(`DOM节点仅${domNodeCount}个`);
      }

      // 信号2：无主流框架痕迹
      if (!hasFramework) {
        signals.push('未检测到主流框架');
      }

      // 信号3：外部资源过少
      if (!hasExternal || totalExternal < AI_PAGE_THRESHOLDS.MIN_EXTERNAL_RESOURCES) {
        signals.push(`外部资源仅${totalExternal}个`);
      }

      // 信号4：克隆站常见的异常 JS 引用路径
      if (suspiciousScriptRefCount > 0) {
        signals.push(`异常JS引用${suspiciousScriptRefCount}个`);
      }

      const signalCount = signals.length;

      // 组合判定
      if (signalCount >= resolveSetting('code_signalsFull', AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_FULL)) {
        signalScore = resolveSetting('rule5_fullScore', SCORE_RULE_5);
        signalTriggered = true;
        signalDetail = `代码工程质量差(${signalCount}个结构信号): ${signals.join('; ')}`;
        signalDetailCN = `代码工程化: 高度可疑 (${signals.join(', ')})`;
      } else if (signalCount >= resolveSetting('code_signalsPartial', AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_PARTIAL)) {
        signalScore = resolveSetting('rule5_partialScore', SCORE_RULE_5_PARTIAL);
        signalTriggered = true;
        signalDetail = `代码工程化弱信号(${signalCount}个结构信号): ${signals.join('; ')}`;
        signalDetailCN = `代码工程化: 中度可疑 (${signals.join(', ')})`;
      } else if (signalCount === 1) {
        signalDetail = `代码工程化基本正常（仅${signals[0]}）`;
        signalDetailCN = '代码工程化: 基本正常';
      } else {
        signalDetail = '代码工程化检测通过（DOM节点' + domNodeCount + '，外部资源' + totalExternal + '个）';
        signalDetailCN = '代码工程化: 正常';
      }
    } else {
      signalDetail = '页面文本内容不足，跳过三信号检测';
      signalDetailCN = '代码工程化: 内容不足';
    }

    // ---- 合并子规则 A + B ----
    const totalScore = signalScore + emojiDensityResult.score;
    result.score = totalScore;
    result.triggered = signalTriggered || emojiDensityResult.triggered;

    // 组装 detail
    const parts = [];
    const partsCN = [];

    if (signalScore > 0 || !emojiDensityResult.triggered) {
      // 三信号有结果，或 emoji 未触发时以三信号为主
      parts.push(signalDetail);
      partsCN.push(signalDetailCN);
    }
    if (emojiDensityResult.triggered) {
      parts.push(emojiDensityResult.detail);
      partsCN.push(emojiDensityResult.detailCN);
    }

    if (totalScore > 0) {
      result.detail = parts.join(' | ');
      result.detailCN = partsCN.join(' | ');
    } else if (parts.length > 0) {
      result.detail = signalDetail;
      result.detailCN = signalDetailCN;
    }

    return result;
  }

  /**
   * 规则五子规则：关键词预筛选 + Emoji 密度检测
   *
   * 先通过推广/产品关键词预筛选确认页面是否为推广性质，
   * 再计算 Emoji 密度并通过分段线性映射得出加分值（上限 30 分）。
   *
   * 判定链路：
   *   1. 文本长度 < 100 字符 → 跳过（0 分）
   *   2. 推广关键词匹配数 < 阈值（默认 1） → 跳过（0 分，非推广页面）
   *   3. 计算 Emoji 密度 density = (emojiCount / textLength) * 1000
   *   4. 分段线性映射：
   *        density < 2.0          → 0 分
   *        2.0 ≤ density < 10.0   → (density - 2) / 8 * 30
   *        density ≥ 10.0          → 30 分（封顶）
   *
   * @param {string} pageText - 页面文本内容（兼容旧消息）
   * @param {Object} textSignals - 内容脚本本地计算的派生文本指标
   * @returns {Object} 包含 score, triggered, detail, detailCN, keywordMatchCount, emojiCount, density 的结果
   */
  static _evaluateRule5EmojiDensity(pageText, textSignals) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: 'Emoji密度: 正常',
      keywordMatchCount: 0, emojiCount: 0, density: 0
    };

    if (textSignals && typeof textSignals === 'object') {
      const textLength = Number(textSignals.textLength || 0);
      if (textLength < resolveSetting('emoji_minTextLength', EMOJI_MIN_TEXT_LENGTH)) {
        result.detail = `页面文本不足${EMOJI_MIN_TEXT_LENGTH}字符，跳过Emoji密度检测`;
        result.detailCN = 'Emoji密度: 文本不足';
        return result;
      }

      const keywordMatchCount = Number(textSignals.promoKeywordMatchCount || 0);
      result.keywordMatchCount = keywordMatchCount;
      if (keywordMatchCount < resolveSetting('emoji_keywordMatchThreshold', EMOJI_KEYWORD_MATCH_THRESHOLD)) {
        result.detail = `推广关键词匹配${keywordMatchCount}个，未达阈值${EMOJI_KEYWORD_MATCH_THRESHOLD}，跳过Emoji密度检测`;
        result.detailCN = 'Emoji密度: 非推广页面';
        return result;
      }

      const emojiCount = Number(textSignals.emojiCount || 0);
      result.emojiCount = emojiCount;
      if (emojiCount === 0) {
        result.detail = `推广关键词匹配${keywordMatchCount}个，但无Emoji字符`;
        result.detailCN = 'Emoji密度: 无Emoji';
        return result;
      }

      const density = Number(textSignals.emojiDensity || 0);
      result.density = Math.round(density * 100) / 100;
      return this._finalizeEmojiDensityResult(result, keywordMatchCount, emojiCount, density);
    }

    // 1. 文本长度不足 → 跳过
    if (!pageText || pageText.length < EMOJI_MIN_TEXT_LENGTH) {
      result.detail = `页面文本不足${EMOJI_MIN_TEXT_LENGTH}字符，跳过Emoji密度检测`;
      result.detailCN = 'Emoji密度: 文本不足';
      return result;
    }

    // 2. 关键词预筛选（大小写不敏感）
    const lowerText = pageText.toLowerCase();
    let keywordMatchCount = 0;
    for (const kw of PROMO_KEYWORDS) {
      if (lowerText.includes(kw.toLowerCase())) {
        keywordMatchCount++;
      }
    }
    result.keywordMatchCount = keywordMatchCount;

    if (keywordMatchCount < resolveSetting('emoji_keywordMatchThreshold', EMOJI_KEYWORD_MATCH_THRESHOLD)) {
      result.detail = `推广关键词匹配${keywordMatchCount}个，未达阈值${EMOJI_KEYWORD_MATCH_THRESHOLD}，跳过Emoji密度检测`;
      result.detailCN = 'Emoji密度: 非推广页面';
      return result;
    }

    // 3. Emoji 密度计算
    // 使用 Unicode 属性转义，覆盖常见 emoji（包括肤色修饰符、零宽连接符序列）
    const emojiRegex = /\p{Emoji_Presentation}|\p{Emoji}️/gu;
    const emojiMatches = pageText.match(emojiRegex) || [];
    const emojiCount = emojiMatches.length;
    result.emojiCount = emojiCount;

    if (emojiCount === 0) {
      result.detail = `推广关键词匹配${keywordMatchCount}个，但无Emoji字符`;
      result.detailCN = 'Emoji密度: 无Emoji';
      return result;
    }

    // density = (emojiCount / textLength) * 1000（单位：个/千字符）
    const density = (emojiCount / pageText.length) * 1000;
    result.density = Math.round(density * 100) / 100;

    return this._finalizeEmojiDensityResult(result, keywordMatchCount, emojiCount, density);
  }

  /**
   * 根据 Emoji 密度完成分段线性映射和详情组装。
   */
  static _finalizeEmojiDensityResult(result, keywordMatchCount, emojiCount, density) {
    let emojiDensityScore = 0;
    if (density < EMOJI_DENSITY_THRESHOLD_LOW) {
      emojiDensityScore = 0;
    } else if (density < EMOJI_DENSITY_THRESHOLD_HIGH) {
      emojiDensityScore = (density - EMOJI_DENSITY_THRESHOLD_LOW) /
        (EMOJI_DENSITY_THRESHOLD_HIGH - EMOJI_DENSITY_THRESHOLD_LOW) *
        EMOJI_DENSITY_MAX_SCORE;
    } else {
      emojiDensityScore = resolveSetting('emoji_densityMaxScore', EMOJI_DENSITY_MAX_SCORE);
    }

    emojiDensityScore = Math.floor(emojiDensityScore);
    result.score = emojiDensityScore;

    if (emojiDensityScore > 0) {
      result.triggered = true;
      result.detail = `推广页面Emoji密度高（匹配${keywordMatchCount}个关键词，${emojiCount}个Emoji，密度${result.density.toFixed(1)}/千字符），+${emojiDensityScore}`;
      result.detailCN = `Emoji密度: ${emojiCount}个Emoji，密度${result.density.toFixed(1)}，+${emojiDensityScore}`;
    } else {
      result.detail = `推广页面Emoji密度低（匹配${keywordMatchCount}个关键词，${emojiCount}个Emoji，密度${result.density.toFixed(1)}/千字符），不加分`;
      result.detailCN = `Emoji密度: 密度${result.density.toFixed(1)}，不加分`;
    }

    return result;
  }

  // ==================== 域名年龄评分（Whois API） ====================
  /**
   * 基于 Whois API 返回的域名注册天数（creation_days），通过 S 型衰减函数
   * 计算可疑加分。新注册的域名（creation_days 小）得分更高。
   *
   * 公式：score = floor(MAX / (1 + (x / (60 * b))^a))
   *   其中 x = creation_days, MAX = SCORE_DOMAIN_AGE_MAX,
   *       a = DOMAIN_AGE_DECAY_A, b = DOMAIN_AGE_DECAY_B
   *
   * 设计原理：
   *   - 新注册域名（x → 0）：分母 → 1，score → MAX（最高可疑）
   *   - 随注册天数增加：分母增大，score 衰减
   *   - 注册很久的域名（x 很大）：分母 → ∞，score → 0
   *
   * @param {string} domain - 当前页面域名
   * @returns {Promise<Object>} 包含 score, triggered, detail, detailCN, creationDays 的结果
   */
  static async _evaluateDomainAge(domain) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '域名年龄: 正常',
      creationDays: -1
    };

    // 调用 Whois API
    const whoisResult = await WhoisClient.lookup(domain);

    // API 真正失败（网络错误、HTTP 异常、解析失败等）
    if (!whoisResult) {
      const errInfo = WhoisClient.lastError;
      const errPhase = errInfo ? ` [${errInfo.phase}]` : '';
      const errMsg = errInfo ? `: ${errInfo.message}` : '';
      result.status = 'neutral';
      result.detail = `Whois API 查询失败${errPhase}${errMsg} (${domain})`;
      result.detailCN = `域名年龄: API 查询失败${errPhase}`;
      return result;
    }

    // API 调用成功，但 creation_days 数据未知或不可靠（如免费 API 返回 0 作为占位值）
    if (whoisResult.creationDays < 0) {
      result.status = 'neutral';
      result.detail = `Whois API 返回的域名注册天数未知 (${domain})`;
      result.detailCN = '域名年龄: 注册时间未知';
      return result;
    }

    const x = whoisResult.creationDays;
    result.creationDays = x;

    // S 型衰减函数：score = floor(MAX / (1 + (x / (60 * b))^a))
    const denominator = 1 + Math.pow(x / (60 * resolveSetting('domainAge_decayB', DOMAIN_AGE_DECAY_B)), resolveSetting('domainAge_decayA', DOMAIN_AGE_DECAY_A));
    const rawScore = resolveSetting('domainAge_scoreMax', SCORE_DOMAIN_AGE_MAX) / denominator;
    const score = (x > 365) ? Math.floor(rawScore) : 0;

    if (score > 0) {
      result.score = score;
      result.triggered = true;
      result.detail = `域名注册仅${x}天（Whois），可疑加分+${score}（raw=${rawScore.toFixed(2)}）`;
      result.detailCN = `域名年龄: 注册仅${x}天，可疑 +${score}`;
    } else {
      result.detail = `域名注册${x}天（Whois），年龄正常`;
      result.detailCN = `域名年龄: 已注册${x}天`;
    }

    return result;
  }

  // ==================== 域名年龄减分（Whois API） ====================
  /**
   * 基于域名注册天数对已累积的可疑分数进行抵消。
   *
   * 减分公式（x = creation_days）：
   *   x < 180             → bonus = 0（新域名不减分）
   *   180 ≤ x < 730       → bonus = floor(MAX_BONUS * (x - 180) / (730 - 180))
   *   x ≥ 730             → bonus = MAX_BONUS（长期注册域名获最大减分）
   *
   * 执行条件：仅当 preliminaryScore >= resolveSetting('domainAgeBonus_scoreThreshold', DOMAIN_AGE_BONUS_SCORE_THRESHOLD) 时调用。
   *
   * @param {string} domain        - 当前页面域名
   * @param {number} preliminaryScore - 应用减分前的可疑总分
   * @param {Object} domainAgeResult   - 域名年龄评分结果（复用 creationDays 避免重复 API 调用）
   * @returns {Promise<Object>} 包含 score（负数）, triggered, detail, detailCN, bonusScore 的结果
   */
  static async _evaluateDomainAgeBonus(domain, preliminaryScore, domainAgeResult) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '域名减分: 未应用',
      bonusScore: 0
    };

    // 优先复用域名年龄评分中的 creationDays，避免重复 API 调用
    let creationDays = domainAgeResult?.creationDays ?? -1;
    if (creationDays < 0) {
      // 不再重试 API：_evaluateDomainAge 已经调用过 WhoisClient，
      // 若 creationDays < 0 说明数据确实不可用（免费 API 对此域名无数据），
      // 重复请求只会浪费 API 配额并增加延迟（速率限制器每两次请求间隔 2s）
      result.status = 'neutral';
      result.detail = `域名注册天数未知，无法应用域名年龄减分`;
      result.detailCN = '域名减分: 注册时间未知';
      return result;
    }

    const x = creationDays;

    // 计算减分分值（正数，表示减去的分数）
    let bonusScore = 0;
    if (x < DOMAIN_AGE_BONUS_MIN_DAYS) {
      bonusScore = 0;
    } else if (x < DOMAIN_AGE_BONUS_MAX_DAYS) {
      bonusScore = Math.floor(
        SCORE_DOMAIN_AGE_BONUS_MAX * (x - DOMAIN_AGE_BONUS_MIN_DAYS) /
        (resolveSetting('domainAgeBonus_maxDays', DOMAIN_AGE_BONUS_MAX_DAYS) - resolveSetting('domainAgeBonus_minDays', DOMAIN_AGE_BONUS_MIN_DAYS))
      );
    } else {
      bonusScore = SCORE_DOMAIN_AGE_BONUS_MAX;
    }

    if (bonusScore > 0) {
      // 减分分值不能超过当前可疑分数（避免分数变为负数）
      const effectiveBonus = Math.min(bonusScore, preliminaryScore);
      result.score = -effectiveBonus; // 负数表示减分
      result.bonusScore = effectiveBonus;
      result.triggered = true;
      result.detail = `域名注册${x}天，年龄减分-${effectiveBonus}（原始bonus=${bonusScore}，减分前=${preliminaryScore}）`;
      result.detailCN = `域名减分: 已注册${x}天，年龄抵消 -${effectiveBonus}`;
    } else {
      result.status = 'neutral';
      result.detail = `域名注册${x}天，不足${DOMAIN_AGE_BONUS_MIN_DAYS}天，不适用减分`;
      result.detailCN = `域名减分: 仅注册${x}天，不适用`;
    }

    return result;
  }

  // ==================== 下载链接跨域检测（Whois API） ====================
  /**
   * 检测下载链接的域名是否与当前页面跨域，以及下载链接域名是否为新注册。
   * 由 Service Worker 的下载事件处理程序调用。
   *
   * 判定逻辑：
   *   1. 从下载 URL 提取域名，通过 PSL 提取主域名进行比较
   *   2. 同主域名 → 不加分（0 分）
   *   3. 跨域 → +10 分（SCORE_DOWNLOAD_CROSS_DOMAIN）
   *   4. 跨域 且 Whois/RDAP 返回 valid_days < 365 且 creation_days < 90 → 再 +10 分
   *
   * @param {string} downloadUrl - 下载文件的完整 URL
   * @param {string} pageDomain   - 当前页面的域名
   * @returns {Promise<Object>} 包含 score, triggered, detail, detailCN, downloadDomain, whoisResult 的结果
   */
  static async evaluateDownloadLink(downloadUrl, pageDomain) {
    const result = {
      score: 0, triggered: false, status: 'pass',
      detail: '', detailCN: '下载链接: 同域下载',
      downloadDomain: '',
      whoisResult: null
    };

    if (!downloadUrl || !pageDomain) return result;

    // 提取下载链接的域名
    let downloadDomain;
    try {
      const urlObj = new URL(downloadUrl);
      downloadDomain = urlObj.hostname.toLowerCase();
    } catch (e) {
      result.status = 'neutral';
      result.detail = '无法解析下载链接URL';
      result.detailCN = '下载链接: URL 解析失败';
      return result;
    }

    result.downloadDomain = downloadDomain;

    // 提取主域名（PSL 去掉子域名）进行比较
    const pageMainDomain = UrlUtils.getMainDomain(pageDomain);
    const downloadMainDomain = UrlUtils.getMainDomain(downloadDomain);

    // 同主域名 → 不跨域，不加分
    if (pageMainDomain === downloadMainDomain) {
      result.detail = `下载链接同域 (${downloadDomain})，不加分`;
      result.detailCN = `下载链接: 同域 (${downloadDomain})`;
      return result;
    }

    // 跨域 → 基础加分（黑名单域名直接给更高分，可信平台降权）
    const isBlacklisted = await DownloadBlacklist.isBlacklisted(downloadDomain);
    const isTrustedPlatform = TrustedDownloadHosts.isTrusted(downloadDomain);

    let baseScore;
    if (isBlacklisted) {
      baseScore = SCORE_DOWNLOAD_BLACKLIST;  // 黑名单20
    } else if (isTrustedPlatform) {
      baseScore = SCORE_RULE_2_TRUSTED_PLATFORM;  // 可信平台3
    } else {
      baseScore = 10;  // 常规跨域10
    }
    result.score = baseScore;
    result.triggered = true;

    if (isBlacklisted) {
      result.detail = `下载链接指向黑名单域名 (${downloadDomain} ≠ ${pageDomain})，+${baseScore}`;
      result.detailCN = `下载链接: 跨域下载 → 黑名单域名 (${downloadDomain}) +${baseScore}`;
    } else if (isTrustedPlatform) {
      result.detail = `下载链接指向可信平台 (${downloadDomain} ≠ ${pageDomain})，降权+${baseScore}`;
      result.detailCN = `下载链接: 跨域下载 → 可信平台 (${downloadDomain}) +${baseScore}`;
    } else {
      result.detail = `下载链接跨域 (${downloadDomain} ≠ ${pageDomain})，+${baseScore}`;
      result.detailCN = `下载链接: 跨域下载 (${downloadDomain}) +${baseScore}`;
    }

    // 查询下载链接域名的 Whois 信息，检查是否为新注册域名
    const whoisResult = await WhoisClient.lookup(downloadDomain);
    result.whoisResult = whoisResult;

    if (whoisResult && whoisResult.creationDays >= 0 && whoisResult.validDays >= 0) {
      // 条件：valid_days < 365 且 creation_days < 90 → 新注册域名额外加分
      if (whoisResult.validDays < resolveSetting('download_validDaysThreshold', DOWNLOAD_VALID_DAYS_THRESHOLD) && whoisResult.creationDays < resolveSetting('download_creationDaysThreshold', DOWNLOAD_CREATION_DAYS_THRESHOLD)) {
        result.score += 10;
        result.detail += `，新注册域名（注册${whoisResult.creationDays}天，剩余${whoisResult.validDays}天）再+10`;
        result.detailCN += `，新注册域名 +10（${whoisResult.creationDays}天）`;
      }
    }

    return result;
  }

  // ==================== 工具方法 ====================

  /**
   * 检测文件是否为压缩包格式
   * 三层检测：文件名扩展名 → 下载URL路径 → MIME类型
   * @param {string} filename - 文件名（可能为空）
   * @param {string} [url=''] - 下载URL（用于回退检测）
   * @param {string} [mime=''] - MIME类型（用于回退检测）
   * @returns {boolean}
   */
  static isArchiveFile(filename, url = '', mime = '') {
    // 第一层：文件名扩展名检测（增加空值安全检查）
    if (filename) {
      const lower = filename.toLowerCase();
      const matchByFilename = ARCHIVE_EXTENSIONS.some(ext => {
        if (ext.startsWith('.')) return lower.endsWith(ext);
        // 处理如 .tar.gz 的复合扩展名
        return lower.endsWith(ext);
      });
      if (matchByFilename) return true;
    }

    // 第二层：下载URL路径检测（去除查询参数后检查扩展名）
    if (url) {
      try {
        const urlObj = new URL(url);
        const pathname = urlObj.pathname.toLowerCase();
        const matchByUrl = ARCHIVE_EXTENSIONS.some(ext => {
          if (ext.startsWith('.')) return pathname.endsWith(ext);
          return pathname.endsWith(ext);
        });
        if (matchByUrl) return true;
      } catch (e) { /* URL解析失败，跳过此层检测 */ }
    }

    // 第三层：MIME类型检测（17种常见压缩包MIME类型）
    if (mime) {
      const ARCHIVE_MIME_TYPES = [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-7z-compressed',
        'application/x-tar',
        'application/gzip',
        'application/x-bzip2',
        'application/x-xz',
        'application/x-compress',
        'application/x-iso9660-image',
        'application/vnd.ms-cab-compressed',
        'application/x-arj',
        'application/x-lzh',
        'application/zstd',
        'application/x-compressed-tar',
        'application/x-gzip',
        'application/x-bzip',
        'application/x-lzma'
      ];
      if (ARCHIVE_MIME_TYPES.includes(mime.toLowerCase())) return true;
    }

    return false;
  }
}
