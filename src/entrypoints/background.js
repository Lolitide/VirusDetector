// wxt background service-worker entrypoint.
// All orchestration logic lives in the original module (`background/service-worker.js`);
// importing it runs its side effects (registering chrome.* listeners). We wrap it in
// defineBackground so wxt can apply its background bootstrap (unified browser global, HMR).
import { defineBackground } from 'wxt/utils/define-background';
import '@background/service-worker.js';

export default defineBackground(() => {
  // Logic already executed via the side-effect import above.
});
