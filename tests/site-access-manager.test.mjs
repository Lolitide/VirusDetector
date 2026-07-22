import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';

let store = {};

globalThis.chrome = {
  storage: {
    local: {
      async get(keys) {
        return Object.fromEntries(keys.map(key => [key, structuredClone(store[key])]));
      },
      async set(values) {
        store = { ...store, ...structuredClone(values) };
      }
    }
  }
};

const { SiteAccessManager } = await import('../background/site-access-manager.js');

beforeEach(() => {
  store = { whitelist: [], site_blacklist: {} };
  SiteAccessManager.invalidate();
});

test('normalizes domains and applies parent whitelist entries to subdomains', async () => {
  await SiteAccessManager.replaceWhitelist(['WWW.Example.com', 'example.com']);

  assert.deepEqual(await SiteAccessManager.getWhitelist(), ['example.com']);
  assert.equal(await SiteAccessManager.isWhitelisted('https://login.example.com/path'), true);
});

test('adding a whitelist entry removes an overlapping site blacklist entry', async () => {
  store.site_blacklist = {
    'example.com': { addedAt: 1, addedBy: 'manual', note: '' }
  };
  SiteAccessManager.invalidate();

  await SiteAccessManager.addToWhitelist('https://login.example.com');

  assert.equal(await SiteAccessManager.isWhitelisted('login.example.com'), true);
  assert.equal(await SiteAccessManager.isBlacklisted('login.example.com'), false);
  assert.deepEqual(await SiteAccessManager.getSiteBlacklist(), {});
});

test('adding a blacklist entry removes conflicting whitelist entries', async () => {
  store.whitelist = ['example.com'];
  SiteAccessManager.invalidate();

  await SiteAccessManager.addToBlacklist('login.example.com', { addedBy: 'popup' });

  assert.equal(await SiteAccessManager.isWhitelisted('login.example.com'), false);
  assert.equal(await SiteAccessManager.isBlacklisted('login.example.com'), true);
  assert.deepEqual(await SiteAccessManager.getWhitelist(), []);
});
