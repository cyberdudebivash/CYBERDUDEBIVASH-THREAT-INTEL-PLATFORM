import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const html = readFileSync(new URL('../api-docs.html', import.meta.url), 'utf8');

function panel(document, id) {
  const start = document.indexOf('<pre id="' + id + '"');
  assert.ok(start >= 0, 'missing quick-start panel: ' + id);
  const bodyStart = document.indexOf('>', start) + 1;
  const end = document.indexOf('</pre>', bodyStart);
  assert.ok(bodyStart > start && end > bodyStart, 'malformed panel: ' + id);
  return document.slice(bodyStart, end);
}

function contractErrors(document) {
  const errors = [];
  const curl = panel(document, 'qs-curl');
  const python = panel(document, 'qs-python');
  const javascript = panel(document, 'qs-js');
  const go = panel(document, 'qs-go');
  const powershell = panel(document, 'qs-ps');

  if (curl.includes('X-API-Key: YOUR_API_KEY')) errors.push('public cURL asks for a fake key');
  if (!curl.includes('curl -fsS') ||
      !curl.includes('https://intel.cyberdudebivash.com/api/feed?limit=5&severity=CRITICAL')) {
    errors.push('public cURL must call the real keyless feed');
  }
  if (python.includes('headers=headers') || python.includes('headers = {"X-API-Key"')) {
    errors.push('public Python feed sends an API key');
  }
  const publicJs = javascript.split('// Register SIEM webhook')[0];
  if (publicJs.includes("headers: { 'X-API-Key'")) errors.push('public JavaScript feed sends an API key');
  if (go.includes('req.Header.Set("X-API-Key"')) errors.push('public Go feed sends an API key');
  const publicPs = powershell.split('# Pro+ Sigma export')[0];
  if (publicPs.includes('-Headers')) errors.push('public PowerShell feed sends an API key');
  if (!document.includes('Returns a JSON object containing an <code>items</code> array')) {
    errors.push('public response shape incorrectly described');
  }
  if (curl.includes('JSON array of critical advisories with CVSS, EPSS, IOCs, Sigma rules')) {
    errors.push('free response promises paid exports');
  }
  if (python.includes('/feed/sigma') || powershell.includes('/feed/sigma')) {
    errors.push('quick start uses legacy Sigma route');
  }
  if (!document.includes('GET /api/v1/export/sigma')) errors.push('paid Sigma route not documented');
  return errors;
}

test('all five public quick starts use the verified keyless feed contract', () => {
  assert.deepEqual(contractErrors(html), []);
});

test('a fake public API key or wrong JSON-array claim fails the documentation gate', () => {
  const fakeKey = html.replace('curl -fsS', 'curl -fsS -H "X-API-Key: YOUR_API_KEY"');
  assert.ok(contractErrors(fakeKey).length > 0, 'negative control: fake key');
  const badShape = html.replace('Returns a JSON object containing an <code>items</code> array',
    'Returns a JSON array of advisories');
  assert.ok(contractErrors(badShape).length > 0, 'negative control: wrong envelope');
});

test('authenticated endpoints remain documented separately from Community', () => {
  assert.ok(html.includes('All authenticated endpoints require an API key'));
  assert.ok(html.includes('Enterprise webhook operations'));
  assert.ok(html.includes('Pro+ Sigma export'));
});
