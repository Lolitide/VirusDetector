import assert from 'node:assert/strict';
import test from 'node:test';

import { DomainDatabase } from '../background/domain-database.js';

// ==================== 官方域名精确匹配 ====================

test('GitLab is registered as an official developer platform', () => {
  const entry = DomainDatabase.findByDomain('gitlab.com');

  assert.ok(entry);
  assert.equal(entry.name, 'GitLab');
  assert.deepEqual(entry.officialDomains, ['gitlab.com']);
  assert.equal(entry.correctUrl, 'https://gitlab.com');
  assert.equal(entry.isChineseBrand, false);
});

// ==================== 子域名 → 命名空间归属 ====================

test('GitLab subdomains resolve to the official GitLab entry', () => {
  assert.equal(DomainDatabase.findByDomain('about.gitlab.com')?.name, 'GitLab');
});

test('wubi.sogou.com — 命名空间归属（搜狗旗下真实子域，不应被误判）', () => {
  // 数据库中 officialDomains 只登记了 ie.sogou.com / pinyin.sogou.com 等具体子域，
  // findByDomain 应通过 ownedNamespaces 索引识别出主域 sogou.com 归属于搜狗品牌。
  const entry = DomainDatabase.findByDomain('wubi.sogou.com');
  assert.ok(entry, 'wubi.sogou.com 应能查到归属品牌');
  // 搜狗旗下有多个 entry（输入法/浏览器/翻译），只要返回其中任一个即可
  assert.ok(entry.name.includes('搜狗'), `名称应含"搜狗"，实际: ${entry.name}`);
});

test('shouji.sogou.com — 命名空间归属（同上）', () => {
  const entry = DomainDatabase.findByDomain('shouji.sogou.com');
  assert.ok(entry, 'shouji.sogou.com 应能查到归属品牌');
  assert.ok(entry.name.includes('搜狗'));
});

test('wubi.sogou.com — 因其命名空间归属搜狗，detectSpoof 不应误报', () => {
  // Guard A (findByDomain) 命中 → detectSpoof 应直接返回 null
  const spoof = DomainDatabase.detectSpoof('wubi.sogou.com');
  assert.equal(spoof, null, 'wubi.sogou.com 不应被误判为仿冒');
});

// ==================== 跨命名空间仿冒检测 ====================

test('GitLab lookalike domains point users to the official website', () => {
  const spoof = DomainDatabase.detectSpoof('gitlab-login.example.com');

  assert.ok(spoof);
  assert.equal(spoof.entry.name, 'GitLab');
  assert.equal(spoof.officialDomain, 'gitlab.com');
  assert.equal(spoof.correctUrl, 'https://gitlab.com');
});

test('sogou.evil.com — 仿冒搜狗（evil.com 不归搜狗所有）', () => {
  // findByDomain → evil.com 不在 ownedNamespaces → null
  // detectSpoof → 标签 "sogou" 精确匹配关键词 "sogou" → Rule A
  const spoof = DomainDatabase.detectSpoof('sogou.evil.com');
  assert.ok(spoof, 'sogou.evil.com 应被检测为仿冒');
  assert.ok(spoof.entry.name.includes('搜狗'), `名称应含"搜狗"，实际: ${spoof.entry.name}`);
  assert.equal(spoof.matchType, 'segment_exact_match');
});

// ==================== Rule B 边界约束 ====================

test('xsogoux.com — 短关键词完全在标签中间，Rule B 不应触发', () => {
  // "sogou" (length=5) 出现在标签 "xsogoux" 中，既非 startsWith 也非 endsWith
  // Rule B 边界约束：kw < 7 且不在边界 → 跳过，避免正常域被误判
  const spoof = DomainDatabase.detectSpoof('xsogoux.com');
  assert.equal(spoof, null, 'xsogoux.com 不应被 Rule B 误判（sogou 不在边界）');
});

test('xbaidux.com — 短关键词完全在标签中间，Rule B 不应触发', () => {
  // "baidu" (length=5) 出现在标签 "xbaidux" 中，既非 startsWith 也非 endsWith
  const spoof = DomainDatabase.detectSpoof('xbaidux.com');
  assert.equal(spoof, null, 'xbaidux.com 不应被 Rule B 误判（baidu 不在边界）');
});

test('sogoutech.com — 短关键词在标签开头，Rule B 应触发', () => {
  // "sogou" (length=5) 出现在标签 "sogoutech" 的开头 → 边界匹配
  // 这是典型的品牌+通用词仿冒模式（sogou + tech）
  const spoof = DomainDatabase.detectSpoof('sogoutech.com');
  assert.ok(spoof, 'sogoutech.com 应被检测为仿冒（sogou 在标签开头）');
  assert.ok(spoof.entry.name.includes('搜狗'));
});

test('shoujisogou.com — 短关键词在标签结尾，Rule B 应触发', () => {
  // "sogou" (length=5) 出现在标签 "shoujisogou" 的结尾 → endsWith → 边界匹配
  const spoof = DomainDatabase.detectSpoof('shoujisogou.com');
  assert.ok(spoof, 'shoujisogou.com 应被检测为仿冒（sogou 在标签结尾）');
  assert.ok(spoof.entry.name.includes('搜狗'));
});

// ==================== 百度子域（已有父域 officialDomain 的情况） ====================

test('map.baidu.com — 父域 baidu.com 在命名空间索引中，子域应能查到归属', () => {
  // baidu.com 的主域出现在多个百度系 entry 的 officialDomains 中，
  // ownedNamespaces 中 baidu.com 归属于最先登记的百度系 entry
  const entry = DomainDatabase.findByDomain('map.baidu.com');
  assert.ok(entry, 'map.baidu.com 应能查到归属品牌');
  assert.ok(entry.name.includes('百度'), `名称应含"百度"，实际: ${entry.name}`);
});

// ==================== 去连字符二次检测 ====================

test('sogou-phish.evil.com — 去连字符后段匹配，应检测为仿冒', () => {
  // labels: ['sogou-phish', 'evil', 'com']
  // segments: [['sogou', 'phish'], ['evil'], ['com']]
  // Rule A: seg='sogou' === kw='sogou' → 匹配
  const spoof = DomainDatabase.detectSpoof('sogou-phish.evil.com');
  assert.ok(spoof, 'sogou-phish.evil.com 应被检测为仿冒搜狗');
  assert.ok(spoof.entry.name.includes('搜狗'));
});
