/**
 * DomainDatabase 行为测试：断言官方域名精确匹配、子域名命名空间归属、
 * 分级嫌疑仿冒检测（detectSpoof）—— 含 STRONG/WEAK 分级、形近字符混淆、
 * 拼音变体、typosquat 护栏与短关键词治理回归。
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { DomainDatabase } from '../background/domain-database.js';

// ==================== 官方域名精确匹配 ====================

test('GitLab is registered as an official developer platform', () => {
  const entry = DomainDatabase.findByDomain('gitlab.com');
  assert.ok(entry);
  assert.equal(entry.name, 'GitLab');
});

// ==================== 子域名 → 命名空间归属 ====================

test('wubi.sogou.com — 命名空间归属（不应被误判）', () => {
  const entry = DomainDatabase.findByDomain('wubi.sogou.com');
  assert.ok(entry, 'wubi.sogou.com 应通过命名空间索引查到归属品牌');
  assert.ok(entry.name.includes('搜狗'));
});

test('wubi.sogou.com — detectSpoof 返回 null（Guard A 命中）', () => {
  assert.equal(DomainDatabase.detectSpoof('wubi.sogou.com'), null);
});

test('deepseek.com / weixin.qq.com — 官方域名守卫返回 null', () => {
  assert.equal(DomainDatabase.detectSpoof('deepseek.com'), null);
  assert.equal(DomainDatabase.detectSpoof('weixin.qq.com'), null);
});

// ==================== 跨命名空间仿冒检测 ====================

test('sogou.evil.com — 仿冒检测应触发（weak 分级）', () => {
  const spoof = DomainDatabase.detectSpoof('sogou.evil.com');
  assert.ok(spoof, 'evil.com 不归搜狗，应检测为仿冒');
  assert.equal(spoof.severity, 'weak', 'sogou 为 5 字符弱关键词，应为 weak');
  assert.equal(spoof.matchType, 'segment_exact_match');
});

test('gitlab-login.example.com — 仿冒检测应触发（strong 分级）', () => {
  const spoof = DomainDatabase.detectSpoof('gitlab-login.example.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong', 'gitlab 为 6 字符强关键词，应为 strong');
  assert.equal(spoof.entry.name, 'GitLab');
});

test('deepseek-login.com — strong 段匹配', () => {
  const spoof = DomainDatabase.detectSpoof('deepseek-login.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.entry.name, 'DeepSeek');
});

test('google-google-cn-google.hl.cn — 关键词堆叠 strong', () => {
  const spoof = DomainDatabase.detectSpoof('google-google-cn-google.hl.cn');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'keyword_stuffing');
});

// ==================== Rule B 边界约束 ====================

test('xsogoux.com — 短关键词在标签中间，Rule B 不触发', () => {
  assert.equal(DomainDatabase.detectSpoof('xsogoux.com'), null);
});

test('xbaidux.com — 短关键词在标签中间，Rule B 不触发', () => {
  assert.equal(DomainDatabase.detectSpoof('xbaidux.com'), null);
});

test('sogoutech.com — 短关键词在标签开头，Rule B 触发（weak）', () => {
  const spoof = DomainDatabase.detectSpoof('sogoutech.com');
  assert.ok(spoof, 'sogou 在 sogoutech 开头 → 边界匹配');
  assert.equal(spoof.severity, 'weak');
});

// ==================== 去连字符检测 ====================

test('sogou-phish.evil.com — 去连字符后段匹配（weak）', () => {
  const spoof = DomainDatabase.detectSpoof('sogou-phish.evil.com');
  assert.ok(spoof, 'sogou-phish → 段 sogou 匹配关键词');
  assert.equal(spoof.severity, 'weak');
});

// ==================== 误报回归（原硬处理误报用例） ====================

test('wuyou.com — typosquat 护栏强化后不再误报迅游', () => {
  // wuyou vs xunyou 仅公共后缀 "you"=3 < 4 → 护栏拦截
  assert.equal(DomainDatabase.detectSpoof('wuyou.com'), null);
});

test('qq-zone.com / jd-shop.com / rar-cn.com — 短关键词治理后不触发', () => {
  assert.equal(DomainDatabase.detectSpoof('qq-zone.com'), null);
  assert.equal(DomainDatabase.detectSpoof('jd-shop.com'), null);
  assert.equal(DomainDatabase.detectSpoof('rar-cn.com'), null);
});

test('kdocs-team.com — 去连字符拼合不再误报蒸汽平台（steam 为 lowSpecificity）', () => {
  assert.equal(DomainDatabase.detectSpoof('kdocs-team.com'), null);
});

test('tongyi.com — strong 段匹配（联动评分负责抑制，不再错误 homoglyph）', () => {
  const spoof = DomainDatabase.detectSpoof('tongyi.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'segment_exact_match', '不应因 i→I 规范化自命中 homoglyph');
});

// ==================== 短词整域弱匹配 ====================

test('qq.cn / 7z.com — 整域注册标签等于短关键词 → weak', () => {
  const spoofQq = DomainDatabase.detectSpoof('qq.cn');
  assert.ok(spoofQq);
  assert.equal(spoofQq.severity, 'weak');
  const spoof7z = DomainDatabase.detectSpoof('7z.com');
  assert.ok(spoof7z);
  assert.equal(spoof7z.severity, 'weak');
});

// ==================== 形近字符混淆（homoglyph） ====================

test('a1ipay.com / a1ipay-login.com — 1↔l 形近命中支付宝', () => {
  const spoof = DomainDatabase.detectSpoof('a1ipay.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'homoglyph');
  assert.equal(spoof.entry.name, '支付宝');
  const spoofLogin = DomainDatabase.detectSpoof('a1ipay-login.com');
  assert.ok(spoofLogin, '连字符域名应在段级命中形近');
  assert.equal(spoofLogin.matchType, 'homoglyph');
});

test('ta0bao.com — 0↔o 形近命中淘宝', () => {
  const spoof = DomainDatabase.detectSpoof('ta0bao.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'homoglyph');
});

test('we1xin.com — 1↔i 形近命中微信', () => {
  const spoof = DomainDatabase.detectSpoof('we1xin.com');
  assert.ok(spoof);
  assert.equal(spoof.matchType, 'homoglyph');
  assert.equal(spoof.entry.name, '微信');
});

test('rnicrosoft.com — rn↔m 形近命中 microsoft', () => {
  const spoof = DomainDatabase.detectSpoof('rnicrosoft.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'homoglyph');
  assert.equal(spoof.entry.name, 'Edge浏览器');
});

test('hu0rong.com — 形近命中火绒', () => {
  const spoof = DomainDatabase.detectSpoof('hu0rong.com');
  assert.ok(spoof);
  assert.equal(spoof.matchType, 'homoglyph');
  assert.equal(spoof.entry.name, '火绒安全');
});

test('wuy0u.com — 非品牌词形近不变形近命中', () => {
  assert.equal(DomainDatabase.detectSpoof('wuy0u.com'), null);
});

// ==================== typosquat 约束编辑距离 ====================

test('h0urong.com — 非形近位替换由 typosquat 兜底（strong）', () => {
  // u→0 不属于等价类，dist=2 且 lenDiff=0、公共后缀 "rong"=4 → typosquat 命中
  const spoof = DomainDatabase.detectSpoof('h0urong.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'typosquat');
});

test('deepseekk-login.com — 段级 typosquat（错拼段+修饰段，strong）', () => {
  const spoof = DomainDatabase.detectSpoof('deepseekk-login.com');
  assert.ok(spoof, 'deepseekk 段与 deepseek 距离 1、公共前缀 8 → 段级 typosquat 应命中');
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'typosquat');
  assert.equal(spoof.entry.name, 'DeepSeek');
});

test('qq-qq-qq.com / jd-jd-jd.com — 短词堆叠（strong keyword_stuffing）', () => {
  const spoof1 = DomainDatabase.detectSpoof('qq-qq-qq.com');
  assert.ok(spoof1, 'qq 出现 3 次 → 短词堆叠应命中');
  assert.equal(spoof1.severity, 'strong');
  assert.equal(spoof1.matchType, 'keyword_stuffing');
  const spoof2 = DomainDatabase.detectSpoof('jd-jd-jd.com');
  assert.ok(spoof2);
  assert.equal(spoof2.matchType, 'keyword_stuffing');
  assert.equal(spoof2.entry.name, '京东');
});

test('deeрseek.com — 西里尔 р 伪装 deepseek（编辑距离命中）', () => {
  const spoof = DomainDatabase.detectSpoof('dee\u0440seek.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
});

// ==================== 拼音变体（pinyin） ====================

test('tengxun-soft.com — 拼音全拼命中腾讯（strong）', () => {
  const spoof = DomainDatabase.detectSpoof('tengxun-soft.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'pinyin_exact_match');
  assert.equal(spoof.entry.name, '腾讯');
});

test('dingding-chat.com — 拼音全拼命中钉钉', () => {
  const spoof = DomainDatabase.detectSpoof('dingding-chat.com');
  assert.ok(spoof);
  assert.equal(spoof.matchType, 'pinyin_exact_match');
  assert.equal(spoof.entry.name, '钉钉');
});

test('jinritoutiao-news.com — 拼音全拼命中今日头条', () => {
  const spoof = DomainDatabase.detectSpoof('jinritoutiao-news.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.entry.name, '今日头条');
});

// ==================== 官方注册域标签段（official_label_segment） ====================

test('qianwenai-x.com — 官方注册域标签段命中通义千问（strong）', () => {
  const spoof = DomainDatabase.detectSpoof('qianwenai-x.com');
  assert.ok(spoof);
  assert.equal(spoof.severity, 'strong');
  assert.equal(spoof.matchType, 'official_label_segment');
  assert.equal(spoof.entry.name, '通义千问');
});
