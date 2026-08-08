/**
 * 风险警告呈现策略。
 * 检测强度负责决定何时进入警告状态，本模块只决定保留原网页还是切换安全拦截页。
 *
 * @module warning-intervention
 */

export const WARNING_INTERVENTION_MODES = Object.freeze({
  absolute: {
    label: '绝对',
    offset: null,
    description: '仅命中站点黑名单，或已识别到对应正版官网时替换原网页。'
  },
  low: {
    label: '更低',
    offset: 20,
    description: '超过当前警告线 20 分后使用安全拦截页。'
  },
  balanced: {
    label: '均衡',
    offset: 50,
    description: '超过当前警告线 50 分后使用安全拦截页，其他风险保留原网页提醒。'
  },
  high: {
    label: '更高',
    offset: 80,
    description: '超过当前警告线 80 分后使用安全拦截页，优先减少误拦截。'
  },
  replace: {
    label: '替代',
    offset: 0,
    description: '达到警告线后立即替换原网页，完全使用安全拦截页。'
  }
});

export const DEFAULT_WARNING_INTERVENTION_MODE = 'balanced';

/**
 * 判断当前结果是否包含可直接确认的威胁证据。
 * @param {Object} tabState 当前标签页检测状态
 * @returns {boolean}
 */
export function hasConfirmedThreat(tabState = {}) {
  return tabState.ruleResults?.siteBlacklist?.triggered === true ||
    Boolean(tabState.correctUrl);
}

export function shouldTriggerWarningFlow(settings = {}, tabState = {}) {
  if (hasConfirmedThreat(tabState)) return true;
  const warningThreshold = Number.isFinite(settings.scoreThreshold)
    ? settings.scoreThreshold
    : 100;
  return (Number(tabState.score) || 0) >= warningThreshold;
}

/**
 * 根据用户选择决定是否使用安全拦截页。
 * @param {Object} settings 当前生效设置
 * @param {Object} tabState 当前标签页检测状态
 * @returns {boolean}
 */
export function shouldUseFullPageWarning(settings = {}, tabState = {}) {
  if (settings.showWarningWindow === false) return false;
  if (hasConfirmedThreat(tabState)) return true;
  if (!shouldTriggerWarningFlow(settings, tabState)) return false;

  const warningThreshold = Number.isFinite(settings.scoreThreshold)
    ? settings.scoreThreshold
    : 100;
  const score = Number(tabState.score) || 0;
  const selected = WARNING_INTERVENTION_MODES[settings.warningInterventionMode]
    || WARNING_INTERVENTION_MODES[DEFAULT_WARNING_INTERVENTION_MODE];
  if (selected.offset === null) return false;
  return score >= warningThreshold + selected.offset;
}
