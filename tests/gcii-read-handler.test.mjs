import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleGCIIRead } from '../worker/gcii-read-handler.mjs';

test('missing D1 binding returns 503 without incident claims', async () => {
  const response = await handleGCIIRead(new Request('https://example.org/diagnostic'), {});
  assert.equal(response.status,503);
  assert.match(await response.text(),/unavailable/);
});
test('write method rejected', async () => {
  const response = await handleGCIIRead(new Request('https://example.org/diagnostic',{method:'POST'}),{});
  assert.equal(response.status,405);
  assert.equal(response.headers.get('allow'),'GET, HEAD');
});
test('D1 errors fail closed', async () => {
  const db={prepare(){throw Error('database unavailable')}};
  const response=await handleGCIIRead(new Request('https://example.org/diagnostic'),{GCII_DB:db});
  assert.equal(response.status,503);
});
test('diagnostic schema cannot be mistaken for canonical feed', async () => {
  const db={prepare(){return {bind(){return {async all(){return {results:[]}}}}}}};
  const response=await handleGCIIRead(new Request('https://example.org/diagnostic'),{GCII_DB:db});
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.schema,'cdb.global-incidents.readonly.v1');
  assert.notEqual(body.schema,'cdb.global-incidents.v1');
  assert.equal(response.headers.get('cache-control'),'no-store, max-age=0');
});
