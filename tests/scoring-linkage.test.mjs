/**
 * 规则三(ICP)/规则五(代码工程化)联动降权行为测试 + 可信档案回归。
 *
 * 覆盖：
 *   - _applyIcpDeductions 降权矩阵（基础 50 / 三因子 / 下限 10）
 *   - _evaluateRule3 无备案分支（3a' .cn / 3b 中文站）集成降权
 *   - _evaluateRule5 结构信号联动降权（减半 / AI 可信归零 / 有嫌疑不降权）
 *   - _evaluateRule1 claimsBrand 输出 + _titleClaimsAnyBrand
 *
 * 注：evaluateSync 内部含 _evaluateRule2 的异步依赖（chrome.storage），
 * 本测试直接调用同步的规则方法（与生产路径同一实现）。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { ScoringEngine } from '../background/scoring-engine.js';
import {
  SCORE_RULE_3, SCORE_RULE3_OLD_DOMAIN_DEDUCT, SCORE_RULE3_NO_CLAIM_DEDUCT,
  SCORE_RULE3_TRUSTED_DEDUCT, SCORE_RULE3_MIN_SCORE
} from '../utils/constants.js';

// ==================== 规则三：_applyIcpDeductions 降权矩阵 ====================

test('规则三降权矩阵 — 无档案保持 50（旧行为兼容）', () => {
  const { score } = ScoringEngine._applyIcpDeductions(null);
  assert.equal(score, SCORE_RULE_3);
});

test('规则三降权矩阵 — 仅老域名 → 50-20=30', () => {
  const { score, notes } = ScoringEngine._applyIcpDeductions({ creationDays: 2000 });
  assert.equal(score, SCORE_RULE_3 - SCORE_RULE3_OLD_DOMAIN_DEDUCT);
  assert.ok(notes.includes('老域名'));
});

test('规则三降权矩阵 — 老域名+无声称 → 30-10=20', () => {
  const { score } = ScoringEngine._applyIcpDeductions({ creationDays: 2000, claimsAnyBrand: false });
  assert.equal(score, SCORE_RULE_3 - SCORE_RULE3_OLD_DOMAIN_DEDUCT - SCORE_RULE3_NO_CLAIM_DEDUCT);
});

test('规则三降权矩阵 — 全降权组合封底 10', () => {
  const { score } = ScoringEngine._applyIcpDeductions({ creationDays: 2000, claimsAnyBrand: false, trustedExternalLinks: 3 });
  assert.equal(score, SCORE_RULE3_MIN_SCORE);
});

test('规则三降权矩阵 — 无声称+AI generator → 50-10-10=30', () => {
  const { score } = ScoringEngine._applyIcpDeductions({ claimsAnyBrand: false, aiGenerator: true });
  assert.equal(score, SCORE_RULE_3 - SCORE_RULE3_NO_CLAIM_DEDUCT - SCORE_RULE3_TRUSTED_DEDUCT);
});

test('规则三降权矩阵 — 新域名+声称品牌不降权 → 50', () => {
  const { score } = ScoringEngine._applyIcpDeductions({ creationDays: 100, claimsAnyBrand: true });
  assert.equal(score, SCORE_RULE_3);
});

// ==================== 规则三：无备案分支集成降权 ====================

test('规则三 3b 分支 — 无声称中文站无备案 → 40（降权 10）', () => {
  const r = ScoringEngine._evaluateRule3(
    'mytool-box.com', undefined, [], false,
    { hasCJK: true, cjkCount: 20, cjkRatio: 0.5 }, null, false,
    { creationDays: -1, claimsAnyBrand: false, aiGenerator: false, trustedExternalLinks: 0 }
  );
  assert.equal(r.score, SCORE_RULE_3 - SCORE_RULE3_NO_CLAIM_DEDUCT);
  assert.equal(r.triggered, true);
  assert.ok(r.detailCN.includes('降权'));
});

test('规则三 3a\' 分支 — .cn 域名无声称无备案 → 40', () => {
  const r = ScoringEngine._evaluateRule3(
    'some-tool.cn', undefined, [], false,
    { hasCJK: false, cjkCount: 0, cjkRatio: 0 }, null, false,
    { creationDays: -1, claimsAnyBrand: false, aiGenerator: false, trustedExternalLinks: 0 }
  );
  assert.equal(r.score, SCORE_RULE_3 - SCORE_RULE3_NO_CLAIM_DEDUCT);
});

test('规则三 3b 分支 — 仿冒+声称品牌无备案 → 50（不降权）', () => {
  const r = ScoringEngine._evaluateRule3(
    'deepseek-login.com', undefined, [], false,
    { hasCJK: true, cjkCount: 30, cjkRatio: 0.6 }, null, true,
    { creationDays: -1, claimsAnyBrand: true, aiGenerator: false, trustedExternalLinks: 0 }
  );
  assert.equal(r.score, SCORE_RULE_3);
  assert.ok(!r.detailCN.includes('降权'));
});

test('规则三 3b 分支 — 开源工具站（老域名+可信外链）→ 下限 10', () => {
  const r = ScoringEngine._evaluateRule3(
    'opensource-tool.net', undefined, [], false,
    { hasCJK: true, cjkCount: 10, cjkRatio: 0.4 }, null, false,
    { creationDays: 1500, claimsAnyBrand: false, aiGenerator: false, trustedExternalLinks: 2 }
  );
  assert.equal(r.score, SCORE_RULE3_MIN_SCORE);
  assert.ok(r.detailCN.includes('老域名'));
  assert.ok(r.detailCN.includes('可信外链'));
});

test('规则三 3b 分支 — AI 工具站（无声称+generator）→ 30', () => {
  const r = ScoringEngine._evaluateRule3(
    'ai-tool-site.com', undefined, [], false,
    { hasCJK: true, cjkCount: 15, cjkRatio: 0.5 }, null, false,
    { creationDays: -1, claimsAnyBrand: false, aiGenerator: true, trustedExternalLinks: 0 }
  );
  assert.equal(r.score, SCORE_RULE_3 - SCORE_RULE3_NO_CLAIM_DEDUCT - SCORE_RULE3_TRUSTED_DEDUCT);
  assert.ok(r.detailCN.includes('AI生成页面'));
});

// ==================== 规则五：结构信号联动降权 ====================

/** 构造命中 2 个强信号 + 2 个弱信号的页面度量（→ 30 分） */
function makePageMetrics(overrides = {}) {
  return {
    textLength: 2000,
    domNodeCount: 50,             // <100 → 强信号1
    hasExternalResources: false,
    totalExternalResources: 2,    // <5 → 弱信号3
    hasFrameworkMarkers: false,   // → 弱信号2
    suspiciousScriptRefCount: 2,  // → 强信号4
    ...overrides
  };
}

test('规则五 — 无档案保持原分 30（旧行为兼容）', () => {
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, null);
  assert.equal(r.score, 30);
});

test('规则五 — 可信档案（无嫌疑+老域名+备案通过+无声称）→ 15（减半）', () => {
  const profile = { domainSuspicion: 'none', claimsBrand: false, creationDays: 1500, icpStatus: 'pass', icpTriggered: false, aiGenerator: false, trustedExternalLinks: 0 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 15);
  assert.ok(r.detailCN.includes('可信降权'));
});

test('规则五 — AI 可信（generator+可信外链）→ 0（归零）', () => {
  const profile = { domainSuspicion: 'none', claimsBrand: false, creationDays: 1500, icpStatus: 'neutral', icpTriggered: false, aiGenerator: true, trustedExternalLinks: 2 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 0);
  assert.equal(r.triggered, false, '归零后不应再视为触发');
});

test('规则五 — 有域名嫌疑不降权 → 30', () => {
  const profile = { domainSuspicion: 'strong', claimsBrand: false, creationDays: 1500, icpStatus: 'pass', icpTriggered: false, aiGenerator: true, trustedExternalLinks: 2 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 30);
});

test('规则五 — 声称品牌不降权 → 30', () => {
  const profile = { domainSuspicion: 'none', claimsBrand: true, creationDays: 1500, icpStatus: 'pass', icpTriggered: false, aiGenerator: true, trustedExternalLinks: 2 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 30);
});

test('规则五 — 新域名不满足老域名条件 → 30（不降权）', () => {
  const profile = { domainSuspicion: 'none', claimsBrand: false, creationDays: 100, icpStatus: 'pass', icpTriggered: false, aiGenerator: false, trustedExternalLinks: 0 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 30);
});

test('规则五 — 无备案触发（icpTriggered）→ 30（不降权）', () => {
  const profile = { domainSuspicion: 'none', claimsBrand: false, creationDays: 1500, icpStatus: 'pass', icpTriggered: true, aiGenerator: false, trustedExternalLinks: 0 };
  const r = ScoringEngine._evaluateRule5(makePageMetrics(), 'example.com', undefined, null, profile);
  assert.equal(r.score, 30);
});

test('规则五 — partial 信号（20 分）可信档案下减半 → 10', () => {
  const pm = makePageMetrics({ domNodeCount: 200, suspiciousScriptRefCount: 1 }); // 强信号1 + 弱信号2 → 20
  const profile = { domainSuspicion: 'none', claimsBrand: false, creationDays: 1500, icpStatus: 'pass', icpTriggered: false, aiGenerator: false, trustedExternalLinks: 0 };
  const r = ScoringEngine._evaluateRule5(pm, 'example.com', undefined, null, profile);
  assert.equal(r.score, 10);
});

// ==================== 规则一 claimsBrand 输出 + _titleClaimsAnyBrand ====================

test('规则一 — claimsBrand 输出（声称被仿冒品牌 → true）', () => {
  const r = ScoringEngine._evaluateRule1('deepseek-login.com', {
    title: 'DeepSeek 官方下载', icpResult: null, linkMetrics: null, creationDays: -1
  });
  assert.equal(r.triggered, true);
  assert.equal(r.claimsBrand, true);
});

test('规则一 — claimsBrand 输出（不声称 → false）', () => {
  const r = ScoringEngine._evaluateRule1('deepseek-login.com', {
    title: '免费小说在线阅读', icpResult: null, linkMetrics: null, creationDays: -1
  });
  assert.equal(r.triggered, true);
  assert.equal(r.claimsBrand, false);
});

test('_titleClaimsAnyBrand — 命中任何品牌关键词', () => {
  assert.equal(ScoringEngine._titleClaimsAnyBrand('DeepSeek 官方下载'), true);
  assert.equal(ScoringEngine._titleClaimsAnyBrand('免费在线工具箱'), false);
  assert.equal(ScoringEngine._titleClaimsAnyBrand(''), false);
  assert.equal(ScoringEngine._titleClaimsAnyBrand(null), false);
});

test('_titleClaimsAnyBrand — 中文短品牌名（微信/QQ音乐）', () => {
  assert.equal(ScoringEngine._titleClaimsAnyBrand('微信官方下载'), true, '微信为 2 字符中文品牌应命中');
  assert.equal(ScoringEngine._titleClaimsAnyBrand('QQ音乐客户端下载'), true, 'QQ音乐含中文品牌名应命中');
  assert.equal(ScoringEngine._titleClaimsAnyBrand('微商朋友圈营销'), false, '「微商」非品牌不应误命中');
});

test('规则一 — claimsBrand 中文短品牌（仿冒微信的 title 声称）', () => {
  const r = ScoringEngine._evaluateRule1('weixin-helper.com', {
    title: '微信官方下载', icpResult: null, linkMetrics: null, creationDays: -1
  });
  assert.equal(r.triggered, true);
  assert.equal(r.claimsBrand, true, '中文品牌名(微信)在 title 中应识别为声称');
});
