/**
 * 白名单通配符匹配单元测试（node:test，直接 import 纯函数工具模块）。
 * 覆盖：精确匹配、*.example.com 子域名匹配（含 apex 与多层子域名）、
 * 全匹配 *、规范化（大小写/协议/路径/端口/尾点）、混合列表命中。
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  normalizeWhitelistEntry,
  isWildcardPattern,
  matchWhitelistEntry,
  isWhitelistedDomain
} from '../utils/whitelist-matcher.js';

test('normalizeWhitelistEntry 规范化输入', () => {
  assert.equal(normalizeWhitelistEntry('Example.COM'), 'example.com');
  assert.equal(normalizeWhitelistEntry('https://example.com'), 'example.com');
  assert.equal(normalizeWhitelistEntry('https://Example.com/path?x=1'), 'example.com');
  assert.equal(normalizeWhitelistEntry('http://sub.example.com:8080/'), 'sub.example.com');
  assert.equal(normalizeWhitelistEntry('  *.EXAMPLE.com.  '), '*.example.com');
});

test('isWildcardPattern 识别通配符', () => {
  assert.equal(isWildcardPattern('*.example.com'), true);
  assert.equal(isWildcardPattern('*'), true);
  assert.equal(isWildcardPattern('example.com'), false);
});

test('精确域名匹配（大小写不敏感）', () => {
  assert.equal(matchWhitelistEntry('example.com', 'example.com'), true);
  assert.equal(matchWhitelistEntry('EXAMPLE.COM', 'example.com'), true);
  assert.equal(matchWhitelistEntry('www.example.com', 'example.com'), false);
  assert.equal(matchWhitelistEntry('example.org', 'example.com'), false);
  assert.equal(matchWhitelistEntry('notexample.com', 'example.com'), false);
});

test('*.example.com 匹配 apex 与所有子域名（任意层级）', () => {
  const pattern = '*.example.com';
  // apex 本身
  assert.equal(matchWhitelistEntry('example.com', pattern), true);
  // 单级子域名
  assert.equal(matchWhitelistEntry('www.example.com', pattern), true);
  assert.equal(matchWhitelistEntry('mail.example.com', pattern), true);
  // 多级子域名
  assert.equal(matchWhitelistEntry('a.b.example.com', pattern), true);
  assert.equal(matchWhitelistEntry('x.y.z.example.com', pattern), true);
});

test('*.example.com 不匹配其他域名', () => {
  const pattern = '*.example.com';
  assert.equal(matchWhitelistEntry('example.org', pattern), false);
  assert.equal(matchWhitelistEntry('notexample.com', pattern), false);
  assert.equal(matchWhitelistEntry('myexample.com', pattern), false);
  assert.equal(matchWhitelistEntry('example.com.evil.com', pattern), false);
  assert.equal(matchWhitelistEntry('sub.example.co.uk', pattern), false);
});

test('*.example.com 的边界：形如 *. 视为无效', () => {
  assert.equal(matchWhitelistEntry('example.com', '*.'), false);
  assert.equal(matchWhitelistEntry('anything.com', '*.'), false);
});

test('全匹配 * 命中任意域名', () => {
  assert.equal(matchWhitelistEntry('example.com', '*'), true);
  assert.equal(matchWhitelistEntry('a.b.c.d.example.org', '*'), true);
});

test('isWhitelistedDomain 遍历混合列表', () => {
  const list = ['example.com', '*.trusted.org', '*'];
  assert.equal(isWhitelistedDomain('example.com', list), true);
  assert.equal(isWhitelistedDomain('sub.trusted.org', list), true);
  assert.equal(isWhitelistedDomain('anything.example.net', list), true); // 被 * 命中

  const list2 = ['example.com', '*.trusted.org'];
  assert.equal(isWhitelistedDomain('example.com', list2), true);
  assert.equal(isWhitelistedDomain('www.example.com', list2), false);
  assert.equal(isWhitelistedDomain('sub.trusted.org', list2), true);
  assert.equal(isWhitelistedDomain('evil.com', list2), false);
  assert.equal(isWhitelistedDomain('evil.com', []), false);
  assert.equal(isWhitelistedDomain('evil.com', null), false);
});

test('通配符条目在规范化后仍可命中（大小写/尾点）', () => {
  assert.equal(matchWhitelistEntry('WWW.Example.com', '*.EXAMPLE.com'), true);
  assert.equal(matchWhitelistEntry('www.example.com', '*.example.com.'), true);
});
