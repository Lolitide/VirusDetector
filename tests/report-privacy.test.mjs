/**
 * 上报隐私测试：断言 service-worker 上报载荷不含 pageUrl 等敏感 URL 信息，
 * buildBody 生成的 issue body 仅保留安全的规则细节（源码切片 + 直接调用断言）。
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildBody } from '../worker/report-issue.js';
import { VERSION } from '../utils/constants.js';

const serviceWorker = readFileSync(new URL('../background/service-worker.js', import.meta.url), 'utf8');

function sourceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

test('public report payload excludes page URLs', () => {
  const report = sourceBetween(
    serviceWorker,
    'async function _postReportToWorker',
    '// ==================== 事件监听 ===================='
  );

  assert.doesNotMatch(report, /pageUrl/);
  assert.doesNotMatch(report, /\burl\s*:/);
  assert.match(report, /ruleResults/);
});

test('public issue body retains safe rule details and ignores raw URL details', () => {
  const sensitiveUrl = 'https://example.com/account/reset?token=private-value#fragment';
  const body = buildBody({
    reportType: 'false_positive',
    domain: 'example.com',
    score: 5,
    version: VERSION,
    timestamp: Date.UTC(2026, 6, 23),
    url: sensitiveUrl,
    ruleResults: {
      domainAge: {
        creationDays: 17,
        detailCN: `域名年龄: 注册仅17天，来源 ${sensitiveUrl}`,
        score: 5,
        triggered: true
      },
      rule2: { detail: `downloaded from ${sensitiveUrl}`, score: 20, triggered: true }
    }
  });

  assert.match(body, /`example\.com`/);
  assert.match(body, /域名年龄 \| 已注册 17 天 \| \+5/);
  assert.match(body, /下载检测 \| 已触发 \| \+20/);
  assert.doesNotMatch(body, /account\/reset/);
  assert.doesNotMatch(body, /private-value/);
  assert.doesNotMatch(body, /downloaded from/);
});
