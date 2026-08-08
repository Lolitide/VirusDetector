// wxt content-script entrypoint: page analysis collector.
// Runs at document_idle in the ISOLATED world (default) and collects page metrics,
// link metrics and ICP strings for the scoring engine. Depends on window.VT_CONSTANTS.
import { defineContentScript } from 'wxt/utils/define-content-script';
import '@utils/content-constants.js';
import '@content/content-script.js';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_idle',
  // No `world` → ISOLATED (matches original manifest default).
  main() {},
});
