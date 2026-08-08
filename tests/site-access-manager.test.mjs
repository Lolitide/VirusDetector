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

test('normalizes domains and keeps whitelist entries scoped to one hostname', async () => {
  await SiteAccessManager.replaceWhitelist(['Example.com']);

  assert.deepEqual(await SiteAccessManager.getWhitelist(), ['example.com']);
  assert.equal(await SiteAccessManager.isWhitelisted('https://example.com/path'), true);
  assert.equal(await SiteAccessManager.isWhitelisted('https://login.example.com/path'), false);
});

test('adding a whitelist entry does not remove a parent hostname blacklist', async () => {
  store.site_blacklist = {
    'example.com': { addedAt: 1, addedBy: 'manual', note: '' }
  };
  SiteAccessManager.invalidate();

  await SiteAccessManager.addToWhitelist('https://login.example.com');

  assert.equal(await SiteAccessManager.isWhitelisted('login.example.com'), true);
  assert.equal(await SiteAccessManager.isBlacklisted('login.example.com'), false);
  assert.deepEqual(await SiteAccessManager.getSiteBlacklist(), {
    'example.com': { addedAt: 1, addedBy: 'manual', note: '' }
  });
});

test('adding a blacklist entry does not remove a parent hostname whitelist', async () => {
  store.whitelist = ['example.com'];
  SiteAccessManager.invalidate();

  await SiteAccessManager.addToBlacklist('login.example.com', { addedBy: 'popup' });

  assert.equal(await SiteAccessManager.isWhitelisted('login.example.com'), false);
  assert.equal(await SiteAccessManager.isBlacklisted('login.example.com'), true);
  assert.deepEqual(await SiteAccessManager.getWhitelist(), ['example.com']);
});

test('keeps www hostnames exact instead of widening them to the parent suffix', async () => {
  await SiteAccessManager.addToWhitelist('https://www.com');

  assert.equal(await SiteAccessManager.isWhitelisted('https://www.com'), true);
  assert.equal(await SiteAccessManager.isWhitelisted('https://example.com'), false);
});

test('shared hosting suffixes never affect sibling hostnames', async () => {
  await SiteAccessManager.addToBlacklist('alice.blogspot.com');
  await SiteAccessManager.addToWhitelist('team.firebaseapp.com');

  assert.equal(await SiteAccessManager.isBlacklisted('bob.blogspot.com'), false);
  assert.equal(await SiteAccessManager.isWhitelisted('other.firebaseapp.com'), false);
});

test('migrates conflicting legacy entries with blacklist priority', async () => {
  store.whitelist = ['example.com'];
  store.site_blacklist = {
    'example.com': { addedAt: 1, addedBy: 'manual', note: '' }
  };
  SiteAccessManager.invalidate();

  const state = await SiteAccessManager.getState('example.com');

  assert.equal(state.isWhitelisted, false);
  assert.equal(state.isBlacklisted, true);
  assert.deepEqual(store.whitelist, []);
});
