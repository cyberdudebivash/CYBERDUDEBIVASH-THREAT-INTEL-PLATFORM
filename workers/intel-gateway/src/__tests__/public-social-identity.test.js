import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Public first-party identity surfaces only. Never remove Facebook domain IOCs
// from security detection engines, or private researcher/audit evidence.
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const PUBLIC_IDENTITIES = ['about.html','llms.txt','platform/frontend/src/app/layout.tsx'];
test('Threat Intel public first-party identity sources do not advertise unverified Facebook or ORCID profiles', () => {
  for (const name of PUBLIC_IDENTITIES) {
    const source = readFileSync(resolve(ROOT, name), 'utf8');
    assert.doesNotMatch(source, /https?:\/\/(?:www\.)?(?:facebook\.com|orcid\.org)(?:\/|["'\s]|$)/i, name);
  }
});
test('Retiring unverified profiles does not break approved first-party profiles', () => {
  for (const name of PUBLIC_IDENTITIES) {
    const source = readFileSync(resolve(ROOT, name), 'utf8');
    assert.match(source, /https:\/\/www\.linkedin\.com\/company\/cyberdudebivash\//, name);
    assert.match(source, /https:\/\/www\.instagram\.com\/cyberdudebivash_official\//, name);
  }
});
