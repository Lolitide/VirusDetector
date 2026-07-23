import assert from 'node:assert/strict';
import test from 'node:test';

import { DomainDatabase } from '../background/domain-database.js';

test('GitLab is registered as an official developer platform', () => {
  const entry = DomainDatabase.findByDomain('gitlab.com');

  assert.ok(entry);
  assert.equal(entry.name, 'GitLab');
  assert.deepEqual(entry.officialDomains, ['gitlab.com']);
  assert.equal(entry.correctUrl, 'https://gitlab.com');
  assert.equal(entry.isChineseBrand, false);
});

test('GitLab subdomains resolve to the official GitLab entry', () => {
  assert.equal(DomainDatabase.findByDomain('about.gitlab.com')?.name, 'GitLab');
});

test('GitLab lookalike domains point users to the official website', () => {
  const spoof = DomainDatabase.detectSpoof('gitlab-login.example.com');

  assert.ok(spoof);
  assert.equal(spoof.entry.name, 'GitLab');
  assert.equal(spoof.officialDomain, 'gitlab.com');
  assert.equal(spoof.correctUrl, 'https://gitlab.com');
});

