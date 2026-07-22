import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEFAULT_WARNING_INTERVENTION_MODE,
  hasConfirmedThreat,
  shouldTriggerWarningFlow,
  shouldUseFullPageWarning
} from '../utils/warning-intervention.js';

const baseSettings = {
  showWarningWindow: true,
  scoreThreshold: 100,
  warningInterventionMode: DEFAULT_WARNING_INTERVENTION_MODE
};

test('关闭安全拦截页后始终保留原网页', () => {
  assert.equal(shouldUseFullPageWarning(
    { ...baseSettings, showWarningWindow: false, warningInterventionMode: 'replace' },
    { score: 500, correctUrl: 'https://official.example/' }
  ), false);
});

test('低于危险警告线时不替换原网页', () => {
  assert.equal(shouldUseFullPageWarning(baseSettings, { score: 99 }), false);
});

test('黑名单和已识别正版官网属于确定威胁', () => {
  const blacklisted = {
    score: 50,
    ruleResults: { siteBlacklist: { triggered: true } }
  };
  const impersonating = {
    score: 50,
    correctUrl: 'https://official.example/'
  };

  assert.equal(hasConfirmedThreat(blacklisted), true);
  assert.equal(hasConfirmedThreat(impersonating), true);
  assert.equal(shouldTriggerWarningFlow(baseSettings, blacklisted), true);
  assert.equal(shouldTriggerWarningFlow(baseSettings, impersonating), true);
  assert.equal(shouldUseFullPageWarning(
    { ...baseSettings, warningInterventionMode: 'absolute' },
    blacklisted
  ), true);
  assert.equal(shouldUseFullPageWarning(
    { ...baseSettings, warningInterventionMode: 'absolute' },
    impersonating
  ), true);
});

test('绝对档对普通高分结果仍保留原网页', () => {
  assert.equal(shouldUseFullPageWarning(
    { ...baseSettings, warningInterventionMode: 'absolute' },
    { score: 500 }
  ), false);
});

test('更低、均衡、更高和替代使用各自的相对阈值', () => {
  const cases = [
    ['low', 119, false],
    ['low', 120, true],
    ['balanced', 149, false],
    ['balanced', 150, true],
    ['high', 179, false],
    ['high', 180, true],
    ['replace', 100, true]
  ];

  for (const [mode, score, expected] of cases) {
    assert.equal(
      shouldUseFullPageWarning({ ...baseSettings, warningInterventionMode: mode }, { score }),
      expected,
      `${mode} @ ${score}`
    );
  }
});

test('干预档位跟随当前检测强度的警告线', () => {
  const strictSettings = {
    ...baseSettings,
    scoreThreshold: 70,
    warningInterventionMode: 'balanced'
  };

  assert.equal(shouldUseFullPageWarning(strictSettings, { score: 119 }), false);
  assert.equal(shouldUseFullPageWarning(strictSettings, { score: 120 }), true);
});
