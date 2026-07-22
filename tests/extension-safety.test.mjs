import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
const navigationGuard = readFileSync(new URL('../content/navigation-guard.js', import.meta.url), 'utf8');
const contentScript = readFileSync(new URL('../content/content-script.js', import.meta.url), 'utf8');
const serviceWorker = readFileSync(new URL('../background/service-worker.js', import.meta.url), 'utf8');
const siteAccessManager = readFileSync(new URL('../background/site-access-manager.js', import.meta.url), 'utf8');
const warningHtml = readFileSync(new URL('../warning/warning.html', import.meta.url), 'utf8');
const warningCss = readFileSync(new URL('../warning/warning.css', import.meta.url), 'utf8');
const warningScript = readFileSync(new URL('../warning/warning.js', import.meta.url), 'utf8');
const reportScript = readFileSync(new URL('../warning/report.js', import.meta.url), 'utf8');
const themeInitScript = readFileSync(new URL('../popup/theme-init.js', import.meta.url), 'utf8');

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
  assert.equal(manifest.background.scripts, undefined);
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
  const tabSync = sourceBetween(
    serviceWorker,
    'async function markTabWhitelisted',
    'async function recheckTabAfterWhitelistRemoval'
  );

  assert.match(handler, /whitelistSite\(url, tabs\[0\]\.id\)/);
  assert.match(tabSync, /removeDownloadBlocker\(tabId\)/);
});

test('known threats are checked before navigation without inventing page evidence', () => {
  const preflight = sourceBetween(
    serviceWorker,
    'async function runNavigationPreflight',
    'chrome.webNavigation.onBeforeNavigate.addListener'
  );

  assert.match(serviceWorker, /chrome\.webNavigation\.onBeforeNavigate\.addListener/);
  assert.match(preflight, /isWhitelisted\s*\(/);
  assert.match(preflight, /SiteAccessManager\.isBlacklisted\s*\(/);
  assert.match(preflight, /CacheManager\.get\s*\(/);
  assert.match(preflight, /cached\s*&&\s*cached\.isMalicious/);
  assert.match(preflight, /navigation\.committed/);
  assert.match(preflight, /openWarningPage\(tabId,\s*tabState,\s*stage\)/);
  assert.match(preflight, /isCurrentNavigation/);
  assert.doesNotMatch(preflight, /ScoringEngine\.evaluate/);
});

test('high-risk responses replace the dangerous tab with the warning page', () => {
  const warningFlow = sourceBetween(
    serviceWorker,
    'async function triggerWarningFlow',
    'async function injectDownloadBlocker'
  );
  const warningPage = sourceBetween(
    serviceWorker,
    'async function openWarningPage',
    '// ==================== 页面分析 ===================='
  );

  assert.match(warningFlow, /openWarningPage\(tabId,\s*tabState,\s*['"]postload['"]\)/);
  assert.match(warningPage, /chrome\.tabs\.update\(tabId,\s*\{\s*url:\s*warningUrl/);
  assert.match(warningPage, /originalUrl/);
  assert.match(warningPage, /nonce:\s*createBlockedNonce\(\)/);
  assert.match(warningPage, /safeUrl/);
});

test('the warning page exposes only safe primary actions and confirms trust', () => {
  assert.match(warningHtml, /id="btn-back"[^>]*>回退<\/button>/);
  assert.match(warningHtml, /id="btn-ask-ai"/);
  assert.match(warningHtml, /你确认信任它吗？/);
  assert.match(warningHtml, /是的，我信任它/);
  assert.match(warningHtml, /不，我反悔了/);
  assert.doesNotMatch(warningHtml, /id="risk-score"|威胁评分/);
  assert.doesNotMatch(warningHtml, /关闭此页面|安全建议|此检测有误/);

  assert.match(warningScript, /https:\/\/www\.doubao\.com\/chat\/\?q=/);
  assert.match(warningScript, /type:\s*['"]TRUST_BLOCKED_SITE['"]/);
  assert.match(warningScript, /payload:\s*\{\s*nonce\s*\}/);
  assert.match(warningScript, /type:\s*['"]RETURN_TO_SAFETY['"]/);
  assert.doesNotMatch(warningScript, /window\.history\.go/);
});

test('blocked actions require a trusted extension context', () => {
  const trustHandler = sourceBetween(
    serviceWorker,
    'case MSG_TYPES.TRUST_BLOCKED_SITE:',
    'case MSG_TYPES.RETURN_TO_SAFETY:'
  );
  const warningResources = (manifest.web_accessible_resources || [])
    .flatMap(entry => entry.resources || []);

  assert.equal(warningResources.includes('warning/warning.html'), false);
  assert.match(trustHandler, /requireBlockedContext/);
  assert.match(trustHandler, /message\.payload\?\.nonce/);
  assert.doesNotMatch(trustHandler, /message\.payload\?\.url/);
});

test('stale analysis cannot replace a newer navigation', () => {
  const warningFlow = sourceBetween(
    serviceWorker,
    'async function triggerWarningFlow',
    'async function injectDownloadBlocker'
  );

  assert.match(warningFlow, /isCurrentAnalysisTarget/);
  assert.match(serviceWorker, /_navigationGenerations/);
  assert.match(serviceWorker, /sender\.tab\.url !== url/);
  assert.match(serviceWorker, /analysisDocumentId/);
  assert.match(serviceWorker, /isCurrentAnalysisIdentity/);
  assert.match(serviceWorker, /tabStateMatchesAnalysisIdentity/);
});

test('async Whois and ICP results are bound to one document', () => {
  const whoisUpdate = sourceBetween(
    serviceWorker,
    'async function _applyWhoisUpdate',
    '// ==================== ICP 异步核验 ===================='
  );
  const icpUpdate = sourceBetween(
    serviceWorker,
    'async function _applyIcpUpdate',
    'async function _postReportToWorker'
  );

  assert.match(serviceWorker, /navigationGeneration:\s*tabState\.navigationGeneration/);
  assert.match(serviceWorker, /analysisDocumentId:\s*tabState\.analysisDocumentId/);
  assert.match(whoisUpdate, /isCurrentAnalysisIdentity\(tabId,\s*ctx\)/);
  assert.match(whoisUpdate, /tabStateMatchesAnalysisIdentity\(tabState,\s*ctx\)/);
  assert.match(icpUpdate, /isCurrentAnalysisIdentity\(tabId,\s*snapshot\)/);
  assert.match(icpUpdate, /tabStateMatchesAnalysisIdentity\(tabState,\s*snapshot\)/);
});

test('warning state and reports use the backend blocked context', () => {
  assert.match(serviceWorker, /isWarningPageUrl\(url\) \|\| isReportPageUrl\(url\)\) return/);
  assert.match(serviceWorker, /case MSG_TYPES\.OPEN_BLOCKED_REPORT/);
  assert.match(serviceWorker, /requireBlockedContext\([\s\S]*REPORT_PAGE_URL/);
  assert.match(reportScript, /payload:\s*\{\s*reportType:\s*['"]false_positive['"],\s*nonce/);
  assert.match(reportScript, /if \(!response\?\.success\)/);
});

test('site blacklist changes reconcile every open tab', () => {
  assert.match(serviceWorker, /function syncSiteAccessStateAcrossTabs/);
  assert.match(serviceWorker, /applyBlacklistToTab/);
  assert.match(serviceWorker, /releaseBlacklistFromTab/);
  assert.match(serviceWorker, /changes\[STORAGE_KEYS\.WHITELIST\] \|\| changes\[STORAGE_KEYS\.SITE_BLACKLIST\]/);
});

test('whitelist removal uses only the serialized cross-tab reconciliation queue', () => {
  const handler = sourceBetween(
    serviceWorker,
    'case MSG_TYPES.REMOVE_FROM_WHITELIST:',
    'case MSG_TYPES.CHECK_WHITELIST:'
  );

  assert.match(handler, /syncSiteAccessStateAcrossTabs\(\)/);
  assert.doesNotMatch(handler, /recheckTabAfterWhitelistRemoval/);
});

test('blocked reports fall back to a normal tab when popup creation fails', () => {
  const handler = sourceBetween(
    serviceWorker,
    'case MSG_TYPES.OPEN_BLOCKED_REPORT:',
    '// 下载二次确认'
  );

  assert.match(handler, /try\s*\{[\s\S]*chrome\.windows\.create/);
  assert.match(handler, /catch\s*\{[\s\S]*chrome\.tabs\.create/);
});

test('the warning page inherits light, dark, and automatic extension themes', () => {
  assert.match(warningHtml, /<script src="\.\.\/popup\/theme-init\.js"><\/script>/);
  assert.match(warningHtml, /<html[^>]+style="display: none;"/);
  assert.match(warningCss, /\[data-theme="light"\]/);
  assert.match(warningCss, /\[data-theme="dark"\]/);
  assert.match(themeInitScript, /localStorage\.getItem\(['"]vt_theme['"]\)/);
  assert.match(warningScript, /chrome\.storage\.local\.get\(['"]global_settings['"]\)/);
  assert.match(warningScript, /chrome\.storage\.onChanged\.addListener/);
  assert.match(warningScript, /selectedTheme === ['"]auto['"]/);
  assert.match(warningScript, /prefers-color-scheme:\s*dark/);
});

test('AI handoff shares only the blocked site origin', () => {
  const shareableUrl = sourceBetween(
    warningScript,
    'function getShareableUrl',
    'const params = new URLSearchParams'
  );

  assert.match(shareableUrl, /return parsed\.origin/);
  assert.doesNotMatch(shareableUrl, /parsed\.href/);
  assert.match(warningScript, /https:\/\/www\.doubao\.com\/chat\/\?q=/);
});

test('all site access changes go through one manager', () => {
  assert.match(serviceWorker, /import \{ SiteAccessManager \} from ['"]\.\/site-access-manager\.js['"]/);
  assert.match(siteAccessManager, /class SiteAccessManager/);
  assert.match(siteAccessManager, /addToWhitelist/);
  assert.match(siteAccessManager, /addToBlacklist/);
  assert.match(siteAccessManager, /replaceWhitelist/);
  assert.match(siteAccessManager, /_mutations/);
  assert.doesNotMatch(serviceWorker, /import \{ SiteBlacklist \}/);
  assert.match(warningScript, /changes\.whitelist/);
  assert.match(warningScript, /CHECK_WHITELIST/);
});
