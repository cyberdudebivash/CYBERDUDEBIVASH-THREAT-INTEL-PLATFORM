import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const html = readFileSync(new URL('../api-docs.html', import.meta.url), 'utf8');

function panel(document, id) {
  const match = document.match(new RegExp('<pre id="' + id + '"[^>]*>([\\s\\S]*?)<\\/pre>'));
  assert.ok(match, 'missing quick-start panel: ' + id);
  return match[1];
}

function contractErrors(document) {
  const errors = [];
  const curl = panel(document, 'qs-curl');
  const python = panel(document, 'qs-python');
  const javascript = panel(document, 'qs-js');
  const go = panel(document, 'qs-go');
  const powershell = panel(document, 'qs-ps');

  if (/X-API-Key:\\s*YOUR_API_KEY/.test(curl)) errors.push('public cURL asks for a fake key');
  if (!/curl -fsS\\s*\\\\\\s*\\n\\s*"https:\/\/intel\\.cyberdudebivash\\.com\/api\/feed/.test(curl)) {
    errors.push('public cURL must call the real keyless feed');
  }
  if (/headers\\s*=\\s*\\{\\s*["']X-API-Key/.test(python) ||
      /requests\\.get\\(f["']\\{BASE\\}\/feed["'],\\s*headers=/.test(python)) {
    errors.push('public Python feed sends an API key');
  }
  const publicJs = javascript.split('// Register SIEM webhook')[0];
  if (/headers:\\s*\\{\\s*['"]X-API-Key/.test(publicJs)) errors.push('public JavaScript feed sends an API key');
  if (/req\\.Header\\.Set\\(["']X-API-Key/.test(go)) errors.push('public Go feed sends an API key');
  const publicPs = powershell.split('# Pro+ Sigma export')[0];
  if (/Invoke-RestMethod[^\\n]*-Headers/.test(publicPs)) errors.push('public PowerShell feed sends an API key');
  if (!document.includes('Returns a JSON object containing an <code>items</code> array')) {
    errors.push('public response shape incorrectly described');
  }
  if (/JSON array of critical advisories with CVSS, EPSS, IOCs, Sigma rules/.test(curl)) {
    errors.push('free response promises paid exports');
  }
  if (/\/feed\/sigma/.test(python + powershell)) errors.push('quick start uses unverified legacy Sigma route');
  if (!document.includes('GET /api/v1/export/sigma')) errors.push('paid Sigma route not documented');
  return errors;
}

test('all five public quick starts use the verified keyless feed contract', () => {
  assert.deepEqual(contractErrors(html), []);
});

test('a fake public API key or wrong JSON-array claim fails the documentation gate', () => {
  const fakeKey = html.replace('curl -fsS \\', 'curl -fsS -H "X-API-Key: YOUR_API_KEY" \\');
  assert.ok(contractErrors(fakeKey).length > 0, 'negative control: fake key');
  const badShape = html.replace('Returns a JSON object containing an <code>items</code> array',
    'Returns a JSON array of advisories');
  assert.ok(contractErrors(badShape).length > 0, 'negative control: wrong envelope');
});

test('authenticated endpoints remain documented separately from Community', () => {
  assert.match(html, /All authenticated endpoints require an API key/);
  assert.match(html, /Enterprise webhook operations/);
  assert.match(html, /Pro\\+ Sigma export/);
});
