import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
const navigationGuard = readFileSync(new URL('../content/navigation-guard.js', import.meta.url), 'utf8');
const contentScript = readFileSync(new URL('../content/content-script.js', import.meta.url), 'utf8');
const serviceWorker = readFileSync(new URL('../background/service-worker.js', import.meta.url), 'utf8');

function sourceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end);
}

function runNavigationGuard(url) {
  const listeners = new Map();
  const document = {
    addEventListener(type, listener) { listeners.set(type, listener); },
    removeEventListener(type, listener) {
      if (listeners.get(type) === listener) listeners.delete(type);
    },
    dispatchEvent(event) {
      listeners.get(event.type)?.(event);
    }
  };
  const originalOpen = function originalOpen() {};
  const window = { location: new URL(url), open: originalOpen };

  runInNewContext(navigationGuard, {
    URL,
    confirm: () => true,
    document,
    window
  });

  return { document, originalOpen, window };
}

test('the MAIN-world guard exits before patching authentication pages', () => {
  const mainWorldScripts = manifest.content_scripts
    .filter((entry) => entry.world === 'MAIN')
    .flatMap((entry) => entry.js || []);
  const gate = navigationGuard.indexOf('isSensitiveAuthenticationUrl(window.location.href)');
  const openPatch = navigationGuard.indexOf('window.open =');

  assert.deepEqual(mainWorldScripts, ['content/navigation-guard.js']);
  assert.notEqual(gate, -1, 'navigation guard must detect authentication URLs');
  assert.notEqual(openPatch, -1, 'ordinary pages retain the original navigation guard');
  assert.ok(gate < openPatch, 'authentication URLs must exit before browser APIs are patched');
  assert.match(navigationGuard, /console/);
});

test('Manifest V3 uses only a service worker background entry', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, 'background/service-worker.js');
  assert.equal(manifest.background.type, 'module');
  assert.equal('scripts' in manifest.background, false);
});

test('navigation guard bypasses auth URLs and can unload for dynamic login', () => {
  for (const url of [
    'https://example.com/login',
    'https://accounts.example.com/home',
    'https://console.example.com/dashboard',
    'https://example.com/security/2fa/challenge'
  ]) {
    const auth = runNavigationGuard(url);
    assert.equal(auth.window.open, auth.originalOpen, url);
  }

  const ordinary = runNavigationGuard('https://example.com/products');
  assert.notEqual(ordinary.window.open, ordinary.originalOpen);
  ordinary.document.dispatchEvent({ type: 'virus-detector:disable-navigation-guard' });
  assert.equal(ordinary.window.open, ordinary.originalOpen);
});

test('authentication pages keep passive analysis but disable active link probes', () => {
  const init = sourceBetween(contentScript, 'async function init()', 'if (document.readyState');

  assert.match(init, /isAuthenticationPage\s*\(/);
  assert.match(init, /checkDeadLinks:\s*_cachedCheckDeadLinks\s*&&\s*!authenticationPage/);
});

test('ordinary page probes retain their count but cannot carry login credentials', () => {
  const linkCollector = sourceBetween(
    contentScript,
    'async function collectLinkMetrics',
    '// ==================== 规则五：页面度量采集'
  );

  assert.match(linkCollector, /uniqueCandidates\.slice\(0,\s*5\)/);
  assert.match(linkCollector, /method:\s*['"]HEAD['"]/);
  assert.match(linkCollector, /credentials:\s*['"]omit['"]/);
  assert.match(linkCollector, /referrerPolicy:\s*['"]no-referrer['"]/);
});

test('whitelisted pages exit before analysis is scheduled', () => {
  const init = sourceBetween(contentScript, 'async function init()', 'if (document.readyState');
  const gate = init.indexOf('shouldSkipPageAnalysis');
  const firstSchedule = init.indexOf('scheduleAnalysis');

  assert.notEqual(gate, -1, 'init must evaluate the whitelist gate');
  assert.notEqual(firstSchedule, -1, 'ordinary pages must still schedule analysis');
  assert.ok(gate < firstSchedule, 'whitelist must be checked before scheduling analysis');
});

test('authentication pages are excluded before the full blocker is injected', () => {
  const wrapper = sourceBetween(
    serviceWorker,
    'async function injectDownloadBlocker',
    'function injectBlockerFunc'
  );
  const fullBlocker = sourceBetween(
    serviceWorker,
    'function injectBlockerFunc',
    '// ==================== 页面分析 ===================='
  );
  const gate = wrapper.indexOf('isSensitiveAuthenticationUrl');
  const injection = wrapper.indexOf('chrome.scripting.executeScript');

  assert.notEqual(gate, -1, 'download blocker must detect authentication URLs');
  assert.notEqual(injection, -1, 'ordinary pages retain script injection');
  assert.ok(gate < injection, 'authentication URLs must exit before script injection');
  assert.match(wrapper, /_authenticationTabs\.has\(tabId\)/);
  assert.match(fullBlocker, /HTMLAnchorElement\.prototype\.click\s*=/);
  assert.match(fullBlocker, /new MutationObserver\s*\(/);
});

test('dynamic login interaction disables both navigation and download blockers', () => {
  assert.match(contentScript, /type:\s*['"]AUTH_INTERACTION_DETECTED['"]/);
  const handler = sourceBetween(
    serviceWorker,
    "case 'AUTH_INTERACTION_DETECTED':",
    'case MSG_TYPES.PAGE_ANALYSIS_RESULT:'
  );

  assert.match(handler, /_authenticationTabs\.add\(tabId\)/);
  assert.match(handler, /removeDownloadBlocker\(tabId\)/);
});

test('adding a site to the whitelist removes an existing page blocker', () => {
  const handler = sourceBetween(
    serviceWorker,
    'case MSG_TYPES.ADD_TO_WHITELIST:',
    'case MSG_TYPES.REMOVE_FROM_WHITELIST:'
  );

  assert.match(handler, /removeDownloadBlocker\s*\(/);
});
