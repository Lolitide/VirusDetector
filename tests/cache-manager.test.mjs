/**
 * CacheManager 行为测试：配额治理相关能力。
 *
 * 通过注入 fake chrome.storage.local 验证：
 *   - 官方/可信/完全信任域跳过读写（守卫）
 *   - 正常 set/get 往返 + lastAccess 字段
 *   - 过期条目惰性删除
 *   - cleanup() LRU 裁剪（保留最近 N 条）与统计
 *   - 配额耗尽时紧急清理后重试写入
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { CacheManager } from '../background/cache-manager.js';
import { STORAGE_KEYS, CACHE_LRU_KEEP_COUNT } from '../utils/constants.js';

// ==================== fake chrome.storage.local ====================

const KEY_PREFIX = STORAGE_KEYS.DOMAIN_CACHE;

/** 内存 store；支持注入 set 故障（模拟配额耗尽） */
const store = new Map();
let setFailure = null; // { error, times } — 抛错 N 次后恢复

globalThis.chrome = {
  storage: {
    local: {
      QUOTA_BYTES: 10485760,
      async get(keys) {
        if (keys === null) return Object.fromEntries(store);
        const keyList = Array.isArray(keys) ? keys : [keys];
        const out = {};
        for (const k of keyList) {
          if (store.has(k)) out[k] = store.get(k);
        }
        return out;
      },
      async set(items) {
        if (setFailure) {
          const { error, times } = setFailure;
          if (times > 0) {
            setFailure = { ...setFailure, times: times - 1 };
            throw error;
          }
          setFailure = null;
        }
        for (const [k, v] of Object.entries(items)) store.set(k, v);
      },
      async remove(keys) {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) store.delete(k);
      }
    }
  }
};

function resetStore() {
  store.clear();
  setFailure = null;
}

function putCacheEntry(domain, { timestamp, lastAccess, isMalicious = false }) {
  store.set(KEY_PREFIX + domain, {
    domain,
    score: 30,
    isMalicious,
    correctUrl: null,
    ruleResults: { rule1: { score: 30 } },
    timestamp,
    lastAccess
  });
}

// ==================== 官方/可信域守卫 ====================

test('set() — 官方域名跳过写入', async () => {
  resetStore();
  await CacheManager.set('deepseek.com', { score: 0, isMalicious: false, correctUrl: null, ruleResults: {} });
  assert.equal(store.size, 0, '官方域不应写入缓存');
});

test('set() — 官方子域名跳过写入', async () => {
  resetStore();
  await CacheManager.set('chat.deepseek.com', { score: 0, isMalicious: false, correctUrl: null, ruleResults: {} });
  assert.equal(store.size, 0);
});

test('set() — 可信平台(github.io)跳过写入', async () => {
  resetStore();
  await CacheManager.set('myproject.github.io', { score: 0, isMalicious: false, correctUrl: null, ruleResults: {} });
  assert.equal(store.size, 0, '可信平台不应写入缓存');
});

test('set() — 完全信任域(gov.cn)跳过写入', async () => {
  resetStore();
  await CacheManager.set('example.gov.cn', { score: 0, isMalicious: false, correctUrl: null, ruleResults: {} });
  assert.equal(store.size, 0);
});

test('get() — 官方域名返回 null（即使旧版本已写入）', async () => {
  resetStore();
  putCacheEntry('deepseek.com', { timestamp: Date.now(), lastAccess: Date.now() });
  const r = await CacheManager.get('deepseek.com');
  assert.equal(r, null, '官方域不应命中缓存');
});

test('set/get — 普通域名正常往返并带 lastAccess', async () => {
  resetStore();
  await CacheManager.set('some-soft.example.com', { score: 42, isMalicious: true, correctUrl: 'https://official.example.com', ruleResults: { rule1: { score: 30 } } });
  const entry = store.get(KEY_PREFIX + 'some-soft.example.com');
  assert.ok(entry, '应写入缓存');
  assert.equal(entry.score, 42);
  assert.equal(entry.isMalicious, true);
  assert.ok(entry.timestamp > 0);
  assert.ok(entry.lastAccess > 0, '应带 lastAccess 字段');
  const r = await CacheManager.get('some-soft.example.com');
  assert.equal(r.domain, 'some-soft.example.com');
});

// ==================== 过期惰性删除 ====================

test('get() — 过期条目删除并返回 null', async () => {
  resetStore();
  const longAgo = Date.now() - 48 * 60 * 60 * 1000; // 48 小时前（TTL 24h）
  putCacheEntry('expired.example.com', { timestamp: longAgo, lastAccess: longAgo });
  const r = await CacheManager.get('expired.example.com');
  assert.equal(r, null);
  assert.equal(store.has(KEY_PREFIX + 'expired.example.com'), false, '过期条目应被删除');
});

// ==================== cleanup() LRU 裁剪 ====================

test('cleanup() — 过期条目删除 + LRU 保留最近 N 条', async () => {
  resetStore();
  const now = Date.now();
  // 10 条过期
  for (let i = 0; i < 10; i++) {
    putCacheEntry(`expired-${i}.example.com`, { timestamp: now - 48 * 3600 * 1000, lastAccess: now - 48 * 3600 * 1000 });
  }
  // 130 条存活（lastAccess 递增，i 越大越新）
  for (let i = 0; i < 130; i++) {
    putCacheEntry(`alive-${i}.example.com`, { timestamp: now, lastAccess: now + i });
  }
  const stats = await CacheManager.cleanup({ keepRecentCount: 100 });
  assert.equal(stats.removed, 10 + 30, '删除 10 条过期 + 30 条最旧 LRU');
  assert.equal(stats.kept, 100, '保留最近 100 条');
  assert.equal(stats.total, 140);
  // 最旧 30 条应被删除（alive-0 .. alive-29），最新 100 条保留（alive-30 .. alive-129）
  assert.equal(store.has(KEY_PREFIX + 'alive-0.example.com'), false);
  assert.equal(store.has(KEY_PREFIX + 'alive-29.example.com'), false);
  assert.equal(store.has(KEY_PREFIX + 'alive-30.example.com'), true);
  assert.equal(store.has(KEY_PREFIX + 'alive-129.example.com'), true);
});

test('cleanup() — 默认保留 CACHE_LRU_KEEP_COUNT 条', async () => {
  resetStore();
  const now = Date.now();
  for (let i = 0; i < CACHE_LRU_KEEP_COUNT + 20; i++) {
    putCacheEntry(`d-${i}.example.com`, { timestamp: now, lastAccess: now + i });
  }
  const stats = await CacheManager.cleanup();
  assert.equal(stats.kept, CACHE_LRU_KEEP_COUNT);
  assert.equal(stats.removed, 20);
});

// ==================== 配额紧急清理重试 ====================

test('set() — 配额耗尽时紧急清理后重试写入成功', async () => {
  resetStore();
  const now = Date.now();
  // 预置 120 条存活 + 20 条过期，使配额"写满"
  for (let i = 0; i < 120; i++) {
    putCacheEntry(`old-${i}.example.com`, { timestamp: now, lastAccess: now + i });
  }
  for (let i = 0; i < 20; i++) {
    putCacheEntry(`exp-${i}.example.com`, { timestamp: now - 48 * 3600 * 1000, lastAccess: now - 48 * 3600 * 1000 });
  }
  // 模拟下一次 set 抛 QuotaExceeded（仅一次，重试时恢复）
  setFailure = { error: new Error('Resource::kQuotaBytes quota exceeded'), times: 1 };
  await CacheManager.set('new-domain.example.com', { score: 10, isMalicious: false, correctUrl: null, ruleResults: {} });
  // 写入成功（重试）
  assert.ok(store.has(KEY_PREFIX + 'new-domain.example.com'), '紧急清理后应写入成功');
  // 过期条目已被紧急清理删除
  assert.equal(store.has(KEY_PREFIX + 'exp-0.example.com'), false);
  // LRU 裁剪生效：最旧存活条目被删除（old-0）
  assert.equal(store.has(KEY_PREFIX + 'old-0.example.com'), false);
});

test('set() — 非配额错误不触发紧急清理', async () => {
  resetStore();
  await CacheManager.set('a.example.com', { score: 1, isMalicious: false, correctUrl: null, ruleResults: {} });
  putCacheEntry('keep.example.com', { timestamp: Date.now(), lastAccess: Date.now() });
  setFailure = { error: new Error('random failure'), times: 1 };
  await CacheManager.set('b.example.com', { score: 2, isMalicious: false, correctUrl: null, ruleResults: {} });
  // 非配额错误：写入失败，且不清理其他条目
  assert.equal(store.has(KEY_PREFIX + 'b.example.com'), false);
  assert.equal(store.has(KEY_PREFIX + 'keep.example.com'), true);
});

// ==================== lastAccess 刷新竞态 ====================

test('lastAccess 刷新 — 并发 set 后旧快照不覆盖新结果', async () => {
  resetStore();
  const T1 = Date.now() - 1000;
  const oldEntry = { domain: 'race.example.com', score: 10, isMalicious: false, correctUrl: null, ruleResults: {}, timestamp: T1, lastAccess: T1 - 30 * 60 * 1000 };
  store.set(KEY_PREFIX + 'race.example.com', oldEntry);
  // 触发 get → lastAccess 刷新链启动（读回比对）
  await CacheManager.get('race.example.com');
  // 并发 set：写入新检测结果（新 timestamp）
  await CacheManager.set('race.example.com', { score: 80, isMalicious: true, correctUrl: null, ruleResults: { rule1: { score: 60 } } });
  // 等待 fire-and-forget 刷新链完成（若它错误覆盖，会用旧 score/timestamp 写回）
  await new Promise(r => setTimeout(r, 20));
  const final = store.get(KEY_PREFIX + 'race.example.com');
  assert.equal(final.score, 80, '旧快照不应覆盖新结果');
  assert.equal(final.isMalicious, true);
  assert.notEqual(final.timestamp, T1, 'timestamp 不应回退');
});

// ==================== clearAll / remove / getStats 回归 ====================

test('remove() / clearAll() / getStats() 保持可用', async () => {
  resetStore();
  putCacheEntry('r1.example.com', { timestamp: Date.now(), lastAccess: Date.now(), isMalicious: true });
  putCacheEntry('r2.example.com', { timestamp: Date.now(), lastAccess: Date.now() });
  const stats1 = await CacheManager.getStats();
  assert.equal(stats1.total, 2);
  assert.equal(stats1.malicious, 1);
  await CacheManager.remove('r1.example.com');
  assert.equal(store.has(KEY_PREFIX + 'r1.example.com'), false);
  await CacheManager.clearAll();
  assert.equal(store.size, 0);
});
