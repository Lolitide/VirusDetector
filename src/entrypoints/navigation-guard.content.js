// wxt content-script entrypoint: Layer 0 navigation guard.
// Runs at document_start in the MAIN world, BEFORE the page's own scripts, so it
// can hook window.location / window.open. Depends on window.VT_CONSTANTS which is
// injected by `utils/content-constants.js`.
import { defineContentScript } from 'wxt/utils/define-content-script';
import '@utils/content-constants.js';
import '@content/navigation-guard.js';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_start',
  world: 'MAIN',
  // The original module is a self-executing IIFE; importing it runs the guard.
  main() {},
});
