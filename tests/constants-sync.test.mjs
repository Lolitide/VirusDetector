/**
 * constants.js ↔ content-constants.js 一致性同步测试
 *
 * content-constants.js 是经典脚本（content_scripts / 首帧前同步脚本）的常量镜像，
 * 无法 import ES module。本测试按键映射表逐项比对镜像与真源：
 *  - 值不一致 → 失败（防止再次漂移）
 *  - 镜像出现映射表之外的多余键 → 失败（防止镜像无限膨胀、双头维护）
 *  - navigation-guard 的字面量兜底与镜像一致 → 失败（兜底漂移等于行为漂移）
 *  - 归档 URL 正则模板行为一致 → 失败（content-script 内模板与 constants 生成器分叉）
 *  - 深冻结回归（import 方 push 共享数组必须抛错）
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import * as C from '../utils/constants.js';

// ==================== 加载 content-constants.js 到沙箱 ====================

const mirrorSource = readFileSync(new URL('../utils/content-constants.js', import.meta.url), 'utf8');
const sandboxWindow = {};
runInNewContext(mirrorSource, { window: sandboxWindow, console });
const V = sandboxWindow.VT_CONSTANTS;

// ==================== 键映射表（constants.js 路径 → content-constants 键） ====================

/** 数组类：deepEqual 比对 */
const ARRAY_MAP = [
  ['ARCHIVE_EXTENSIONS', 'ARCHIVE_EXTENSIONS'],
  ['EXECUTABLE_EXTENSIONS', 'EXECUTABLE_EXTENSIONS'],
  ['FILE_EXTENSIONS', 'FILE_EXTENSIONS'],
  ['PROMO_KEYWORDS', 'PROMO_KEYWORDS'],
  ['DOWNLOAD_LINK_KEYWORDS', 'DOWNLOAD_LINK_KEYWORDS'],
  ['DOWNLOAD_INTENT_KEYWORDS', 'DOWNLOAD_INTENT_KEYWORDS'],
  ['INTERMEDIATE_PAGE_KEYWORDS', 'INTERMEDIATE_PAGE_KEYWORDS'],
  ['FRAMEWORK_HTML_MARKERS', 'FRAMEWORK_HTML_MARKERS'],
  ['FRAMEWORK_RESOURCE_MARKERS', 'FRAMEWORK_RESOURCE_MARKERS'],
  ['TRUSTED_EXTERNAL_DOMAINS', 'TRUSTED_EXTERNAL_DOMAINS'],
  ['CJK_RANGES', 'CJK_RANGES'],
  ['ADVANCED_ONLY_SECTIONS', 'ADVANCED_ONLY_SECTIONS']
];

/** 标量类：strictEqual 比对 */
const SCALAR_MAP = [
  ['AUTH_HOST_PATTERN_SOURCE', 'AUTH_HOST_PATTERN_SOURCE'],
  ['AUTH_PATH_PATTERN_SOURCE', 'AUTH_PATH_PATTERN_SOURCE'],
  ['AUTH_INTERACTION_PATTERN_SOURCE', 'AUTH_INTERACTION_PATTERN_SOURCE'],
  ['DISABLE_GUARD_EVENT', 'DISABLE_GUARD_EVENT'],
  ['DEAD_LINK_CHECK_MAX', 'DEAD_LINK_CHECK_MAX'],
  ['DEAD_LINK_TIMEOUT_MS', 'DEAD_LINK_TIMEOUT_MS'],
  ['DEAD_LINK_SAMPLE_MAX', 'DEAD_LINK_SAMPLE_MAX'],
  ['TXT_FETCH_LIMIT', 'TXT_FETCH_LIMIT'],
  ['TXT_FETCH_TIMEOUT_MS', 'TXT_FETCH_TIMEOUT_MS'],
  ['DUPLICATE_LINK_THRESHOLD', 'DUPLICATE_LINK_THRESHOLD'],
  ['DOWNLOAD_DENSITY_THRESHOLD', 'DOWNLOAD_DENSITY_THRESHOLD'],
  ['EMOJI_MIN_TEXT_LENGTH', 'EMOJI_MIN_TEXT_LENGTH'],
  ['EMOJI_KEYWORD_MATCH_THRESHOLD', 'EMOJI_KEYWORD_MATCH_THRESHOLD'],
  ['CJK_MIN_COUNT', 'CJK_MIN_COUNT'],
  ['CJK_MIN_RATIO', 'CJK_MIN_RATIO'],
  ['CJK_ABSOLUTE_COUNT', 'CJK_ABSOLUTE_COUNT'],
  ['ATTR_SCAN_LIMIT', 'ATTR_SCAN_LIMIT'],
  ['MAX_NODES', 'MAX_NODES'],
  ['MIN_SCRIPT_LENGTH', 'MIN_SCRIPT_LENGTH'],
  ['RESOLVER_MAX_INLINE_SCRIPT_LENGTH', 'MAX_INLINE_SCRIPT_LENGTH'],
  ['RESOLVER_MAX_PAGE_TEXT_LENGTH', 'MAX_PAGE_TEXT_LENGTH'],
  ['SCAN_DELAY_FIRST_MS', 'SCAN_DELAY_FIRST_MS'],
  ['SCAN_DELAY_SECOND_MS', 'SCAN_DELAY_SECOND_MS'],
  ['IDLE_TIMEOUT_MS', 'IDLE_TIMEOUT_MS'],
  ['EMOJI_REGEX_SOURCE', 'EMOJI_REGEX_SOURCE']
];

/** 嵌套对象类：逐键 strictEqual */
const NESTED_MAP = [
  { constants: 'UI_KEYS', keys: ['THEME', 'MODE', 'ACTIVE_SECTION'] },
  { constants: 'STORAGE_KEYS', keys: ['GLOBAL_SETTINGS'] },
  { constants: 'MSG_TYPES', keys: ['PAGE_ANALYSIS_RESULT', 'CHECK_WHITELIST', 'REQUEST_PAGE_TEXT', 'UPDATE_SETTINGS', 'AUTH_INTERACTION_DETECTED'] }
];

test('content-constants 镜像与 constants.js 真源逐项一致', () => {
  // 注意：镜像在 vm 沙箱 realm 中求值，数组原型与测试进程不同，
  // deepStrictEqual 会因原型不同而误判不等 → 先 JSON 归一化再比较
  for (const [cKey, vKey] of ARRAY_MAP) {
    assert.deepEqual(
      JSON.parse(JSON.stringify(V[vKey])),
      JSON.parse(JSON.stringify(C[cKey])),
      `array mismatch: ${cKey} ↔ ${vKey}`
    );
  }
  for (const [cKey, vKey] of SCALAR_MAP) {
    assert.equal(V[vKey], C[cKey], `scalar mismatch: ${cKey} ↔ ${vKey}`);
  }
  for (const { constants, keys } of NESTED_MAP) {
    for (const key of keys) {
      assert.equal(V[constants][key], C[constants][key], `nested mismatch: ${constants}.${key}`);
    }
  }
});

test('content-constants 不包含映射表之外的多余键（防镜像膨胀）', () => {
  const allowed = new Set([
    ...ARRAY_MAP.map(([, v]) => v),
    ...SCALAR_MAP.map(([, v]) => v),
    ...NESTED_MAP.map(({ constants }) => constants)
  ]);
  for (const key of Object.keys(V)) {
    assert.ok(allowed.has(key), `mirror has unexpected extra key: ${key}`);
  }
  for (const { constants, keys } of NESTED_MAP) {
    assert.deepEqual(Object.keys(V[constants]).sort(), [...keys].sort(), `mirror ${constants} has unexpected keys`);
  }
});

test('navigation-guard 的字面量兜底与镜像一致', () => {
  const guardSource = readFileSync(new URL('../content/navigation-guard.js', import.meta.url), 'utf8');
  // 提取 var ARCHIVE_EXTS = C.ARCHIVE_EXTENSIONS || [...] 中的兜底数组字面量并求值
  const extractArray = (name) => {
    const m = guardSource.match(new RegExp(`var ${name} = C\\.[A-Z_]+ \\|\\| (\\[[\\s\\S]*?\\]);`));
    assert.ok(m, `guard missing ${name}`);
    return runInNewContext(`(${m[1]})`, {});
  };
  // 提取 AUTH 源串兜底字符串字面量并求值
  const extractFallback = (name) => {
    const m = guardSource.match(new RegExp(`C\\.${name} \\|\\| ('[^']*')`));
    assert.ok(m, `guard missing ${name} fallback`);
    return runInNewContext(m[1], {});
  };

  assert.deepEqual(
    JSON.parse(JSON.stringify(extractArray('ARCHIVE_EXTS'))),
    JSON.parse(JSON.stringify(V.ARCHIVE_EXTENSIONS))
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(extractArray('EXECUTABLE_EXTS'))),
    JSON.parse(JSON.stringify(V.EXECUTABLE_EXTENSIONS))
  );
  // 注：guard 只使用 HOST/PATH 两个认证模式（interaction 模式是 content-script 专属，
  // 其一致性由"镜像与真源逐项一致"用例覆盖）
  assert.equal(extractFallback('AUTH_HOST_PATTERN_SOURCE'), V.AUTH_HOST_PATTERN_SOURCE);
  assert.equal(extractFallback('AUTH_PATH_PATTERN_SOURCE'), V.AUTH_PATH_PATTERN_SOURCE);
});

test('归档 URL 提取正则：constants 生成器与 content-script 模板行为等价', () => {
  // content-script 内的拼接模板（与 constants.js buildArchiveUrlPattern 同一规则：
  // 扩展名转义 + 后缀边界 lookahead）。两处同模板 + 同列表 ⇒ 正则源串必须逐字符一致。
  const buildContentScriptPattern = (exts) => new RegExp(
    `https?://[^\\s<>"'{}[\\]|\\\\^\`]+(${exts.map((e) => '\\' + e).join('|')})(?=[?#\\s]|$)`,
    'gi'
  );

  const R1 = C.buildArchiveUrlPattern(C.ARCHIVE_EXTENSIONS);
  const R2 = buildContentScriptPattern(V.ARCHIVE_EXTENSIONS);
  assert.equal(R1.source, R2.source, 'content-script 正则模板已与 constants.js 生成器分叉');

  // 行为等价断言（正/负样本；R1 与 R2 源串一致故只需测一份）
  const sampleRegex = new RegExp(R1.source, R1.flags); // 独立实例，避免 lastIndex 干扰
  const positives = [
    'https://evil.com/a.zip', 'https://evil.com/a.zip?dl=1', 'https://evil.com/a.zip#frag',
    'https://evil.com/a.tar.gz', 'https://evil.com/a.img', 'https://evil.com/a.gz2',
    'https://evil.com/a.dmg', 'http://evil.com/b.7z'
  ];
  const negatives = [
    'https://evil.com/a.zip.bak', 'https://evil.com/a.zipx', 'https://evil.com/page.html',
    'https://evil.com/a.tar.gz.bak'
  ];
  for (const url of positives) {
    sampleRegex.lastIndex = 0;
    assert.ok(sampleRegex.test(url), `positive should match: ${url}`);
  }
  for (const url of negatives) {
    sampleRegex.lastIndex = 0;
    assert.ok(!sampleRegex.test(url), `negative should NOT match: ${url}`);
  }
});

test('constants.js 导出已深冻结（import 方写入必须抛错）', () => {
  // 冻结对象写入抛 TypeError（消息形如 "Cannot add property ... object is not extensible"）
  assert.throws(() => C.ARCHIVE_EXTENSIONS.push('x'), TypeError, 'ARCHIVE_EXTENSIONS 必须冻结');
  assert.throws(() => { C.MSG_TYPES.NEW_KEY = 'y'; }, TypeError, 'MSG_TYPES 必须冻结');
  assert.throws(() => { C.ICP_API_CONFIG.providers.push({}); }, TypeError, 'ICP_API_CONFIG.providers 必须冻结');
  assert.throws(() => C.PROMO_KEYWORDS.pop(), TypeError, 'PROMO_KEYWORDS 必须冻结');
});

test('扩展名并集完整性（历史漂移点回归）', () => {
  for (const ext of ['.gz2', '.img', '.dmg', '.tar.gz', '.tar.bz2', '.tar.xz', '.zst', '.7z']) {
    assert.ok(C.ARCHIVE_EXTENSIONS.includes(ext), `并集缺失 ${ext}`);
  }
  // FILE_EXTENSIONS 派生自两份列表（去重）
  const derived = [...new Set([...C.ARCHIVE_EXTENSIONS, ...C.EXECUTABLE_EXTENSIONS])];
  assert.deepEqual(C.FILE_EXTENSIONS, derived);
});
