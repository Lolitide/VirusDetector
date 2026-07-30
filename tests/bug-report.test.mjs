import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  BUG_REPORT_URL,
  buildBugReportUrl,
  buildSettingsSummary,
  formatDiagnosticConfiguration
} from '../utils/bug-report.js';
import { DiagnosticLog, sanitizeDiagnosticText } from '../utils/diagnostics.js';

const optionsScript = readFileSync(new URL('../options/options.js', import.meta.url), 'utf8');
const optionsMarkup = readFileSync(new URL('../options/options.html', import.meta.url), 'utf8');
const issueTemplate = readFileSync(new URL('../.github/ISSUE_TEMPLATE/bug_report.yml', import.meta.url), 'utf8');

test('diagnostic text redacts sensitive URLs, credentials, and local paths', () => {
  const sanitized = sanitizeDiagnosticText(
    'GET https://example.com/account/reset?token=private#code ' +
    'authorization=Bearer-private owner@example.com C:\\Users\\Alice\\secret.log'
  );

  assert.match(sanitized, /https:\/\/\[DOMAIN_REDACTED\]\/\[REDACTED\]/);
  assert.match(sanitized, /authorization=\[REDACTED\]/i);
  assert.match(sanitized, /\[EMAIL_REDACTED\]/);
  assert.match(sanitized, /\[LOCAL_PATH\]/);
  assert.doesNotMatch(sanitized, /example\.com|account\/reset|private|Alice|secret\.log/);
});

test('structured secrets and session logs remain redacted across snapshots', async () => {
  const originalChrome = globalThis.chrome;
  const sessionData = {};
  globalThis.chrome = {
    storage: {
      session: {
        async get(key) { return { [key]: sessionData[key] }; },
        async set(values) { Object.assign(sessionData, values); }
      }
    }
  };
  DiagnosticLog._entries = [];
  DiagnosticLog._writeQueue = Promise.resolve();

  try {
    DiagnosticLog.add('error', [{
      message: 'request failed for private.example.com',
      token: 'private-token'
    }]);
    const logs = await DiagnosticLog.snapshot();

    assert.equal(logs.length, 1);
    assert.match(logs[0].message, /\[DOMAIN_REDACTED\]/);
    assert.match(logs[0].message, /\[REDACTED\]/);
    assert.doesNotMatch(logs[0].message, /private\.example\.com|private-token/);
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});

test('settings diagnostics use an allowlist instead of exporting all settings', () => {
  const summary = buildSettingsSummary({
    sensitivityPreset: 'high',
    rule1Enabled: true,
    icpApiToken: 'must-not-leak',
    customEndpoint: 'https://private.example/token'
  });

  assert.deepEqual(summary, { sensitivityPreset: 'high', rule1Enabled: true });
  assert.doesNotMatch(JSON.stringify(summary), /must-not-leak|private\.example/);
});

test('bug report URL prefills the extension issue form with sanitized diagnostics', () => {
  const reportUrl = buildBugReportUrl({
    extensionVersion: '2.5.1',
    manifestVersion: 3,
    browser: 'Edge 150',
    os: 'Windows (x86-64)',
    locale: 'zh-CN',
    installType: 'manual',
    settings: { rule2Enabled: true },
    storage: { cacheEntries: 4 },
    logs: [{
      time: '2026-07-24T01:02:03.000Z',
      level: 'error',
      message: 'failed https://example.com/private?token=hidden'
    }]
  });
  const parsed = new URL(reportUrl);
  const configuration = parsed.searchParams.get('configuration');

  assert.equal(parsed.origin + parsed.pathname, BUG_REPORT_URL);
  assert.match(BUG_REPORT_URL, /^https:\/\/github\.com\/[^/]+\/[^/]+\/issues\/new$/);
  assert.equal(parsed.searchParams.get('template'), 'bug_report.yml');
  assert.equal(parsed.searchParams.get('environment'), '2.5.1');
  assert.match(configuration, /自动收集的诊断信息/);
  assert.match(configuration, /https:\/\/\[DOMAIN_REDACTED\]\/\[REDACTED\]/);
  assert.doesNotMatch(configuration, /example\.com|\/private|hidden/);
});

test('encoded report URLs discard oldest logs before exceeding the URL budget', () => {
  const reportUrl = buildBugReportUrl({
    extensionVersion: '2.5.1',
    browser: 'Edge 150',
    os: 'Windows',
    logs: Array.from({ length: 40 }, (_, index) => ({
      time: `2026-07-24T01:02:${String(index).padStart(2, '0')}.000Z`,
      level: 'error',
      message: `第 ${index} 条中文错误：${'失败'.repeat(180)}`
    }))
  });

  assert.ok(reportUrl.length <= 12000, `report URL has ${reportUrl.length} characters`);
  assert.match(new URL(reportUrl).searchParams.get('configuration'), /older log entries omitted/);
});

test('settings page exposes the automatic bug-report action', () => {
  assert.match(optionsScript, /id="bug-report-btn"/);
  assert.match(optionsScript, /MSG_TYPES\.GET_DIAGNOSTICS/);
  assert.match(optionsScript, /buildBugReportUrl/);
  assert.doesNotMatch(optionsMarkup, /bug-report-btn/,
    'the action belongs to the dynamically rendered About section');
});

test('bug reports reuse the settings page update-channel detector', () => {
  assert.match(optionsScript, /_getUpdateChannel\s*\(\)\s*\{/,
    'the settings page must define the shared install-channel detector');
  assert.match(optionsScript, /installType:\s*this\._getUpdateChannel\(\)/);
  assert.doesNotMatch(optionsScript, /this\._getInstallType\(\)/,
    'calling an undefined install-type method breaks BUG report generation');
});

test('issue template prominently recommends automatic extension reporting', () => {
  assert.match(issueTemplate, /## 推荐通过插件自动填写/);
  assert.match(issueTemplate, /设置 → 关于 → BUG 上报/);
  assert.match(issueTemplate, /id: configuration/);
  assert.match(issueTemplate, /id: privacy/);
});
