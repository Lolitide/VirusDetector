/**
 * 注入函数自包含性测试（防闭包引用回归）。
 *
 * 背景：chrome.scripting.executeScript({ func }) 会把函数源码序列化后在页面
 * MAIN world 执行——函数闭包不保留，任何对模块级常量的直接引用都会在页面
 * 运行时抛 ReferenceError。历史回归：464b333 常量治理把 Part 5 的
 * setTimeout 字面量改为 BLOCKER_OBSERVER_LIFETIME_MS 常量引用，导致
 * injectBlockerFunc 在 Part 5 抛错、Part 6 顶部红色警告横幅永不注入
 * （下载拦截正常、仅条幅消失）。
 *
 * 本测试静态检查所有 executeScript 注入的函数：
 *   1. 函数体引用的每个大写标识符必须是「函数内定义」或「window./extLists./C. 前缀访问」
 *   2. removeDownloadBlockerFunc 必须清理全部注入标志（含 rank，防重新注入被拦截）
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(__dirname, '../background/service-worker.js'), 'utf8');

/** 用括号深度匹配提取函数体（不含外层花括号） */
function extractFuncBody(source, funcName) {
  const start = source.indexOf('function ' + funcName + '(');
  if (start < 0) return null;
  const bodyStart = source.indexOf('{', start);
  let depth = 0;
  for (let i = bodyStart; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return source.slice(bodyStart + 1, i);
    }
  }
  return null;
}

/** 提取通过 executeScript 注入页面执行的函数 */
const INJECTED_FUNCS = ['injectBlockerFunc', 'removeDownloadBlockerFunc'];

test('注入函数可提取（executeScript 序列化前提）', () => {
  for (const name of INJECTED_FUNCS) {
    const body = extractFuncBody(src, name);
    assert.ok(body && body.length > 100, `${name} 应可提取函数体`);
  }
});

test('注入函数不引用模块级常量（闭包不保留，防 ReferenceError 截断后续 Part）', () => {
  for (const name of INJECTED_FUNCS) {
    const body = extractFuncBody(src, name);
    // 函数内定义的大写标识符（var/let/const/function）
    const defined = new Set(
      [...body.matchAll(/\b(?:var|let|const|function)\s+([A-Z][A-Z0-9_]*)/g)].map(m => m[1])
    );
    // 排除注释行后的代码行
    const codeLines = body.split('\n').filter(l => !/^\s*(\/\/|\*)/.test(l));
    const refs = new Set();
    for (const line of codeLines) {
      for (const m of line.matchAll(/\b[A-Z][A-Z0-9_]{3,}\b/g)) refs.add(m[0]);
    }
    // 每个引用必须是：函数内定义，或经 window./extLists./C. 前缀访问
    const unresolved = [...refs].filter(r => {
      if (defined.has(r)) return false;
      const prefixed = new RegExp('\\b(?:window|extLists|C)\\.' + r + '\\b');
      return !prefixed.test(body);
    });
    assert.deepEqual(
      unresolved,
      [],
      `${name} 引用了模块级常量（注入后 ReferenceError）: ${unresolved.join(', ')}`
    );
  }
});

test('removeDownloadBlockerFunc 清理全部注入标志（含 rank，防重新注入被拦截）', () => {
  const body = extractFuncBody(src, 'removeDownloadBlockerFunc');
  assert.ok(body.includes('delete window.__virusDetectorBlockerState'));
  assert.ok(body.includes('delete window.__virusDetectorInjected'));
  assert.ok(
    body.includes('delete window.__virusDetectorInjectedRank'),
    '必须清理 __virusDetectorInjectedRank，否则移除拦截后重新注入被 rank 守卫拦截'
  );
});

test('injectBlockerFunc 的 rank 守卫先于 injected 检查（允许移除后重新注入）', () => {
  const body = extractFuncBody(src, 'injectBlockerFunc');
  const rankCheck = body.indexOf('if (existingRank >= newRank) return;');
  const injectedCheck = body.indexOf('if (window.__virusDetectorBlockerState || window.__virusDetectorInjected) return;');
  assert.ok(rankCheck >= 0 && injectedCheck >= 0);
  assert.ok(rankCheck < injectedCheck, 'rank 检查必须位于 injected 检查之前');
});
