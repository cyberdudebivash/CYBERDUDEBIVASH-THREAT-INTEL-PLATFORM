'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const home = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');
const start = home.indexOf('(function _cdbAntiStaleGuard() {');
const end = home.indexOf('})();', start);
assert.ok(start >= 0 && end > start, 'anti-stale recovery guard must exist');
const guard = home.slice(start, end + 5);

async function runScenario({ rejectEnumeration = false } = {}) {
  const events = { updates: 0, handled: 0, reloads: 0, warnings: [], storedVersion: null };
  const registration = {
    update() {
      events.updates++;
      // This emulates a registration.update() that would otherwise reject
      // during the stale worker unregister/reload race. We count explicit
      // rejection handling without generating process-global rejections.
      return {
        catch(handler) {
          events.handled++;
          assert.equal(typeof handler, 'function');
          handler(new Error('Service Worker update: Not found'));
          return Promise.resolve();
        }
      };
    }
  };
  const sw = {
    ready: Promise.resolve(registration),
    getRegistrations() {
      return rejectEnumeration
        ? Promise.reject(new Error('registrations unavailable'))
        : Promise.resolve([registration]);
    }
  };
  const context = {
    Promise,
    Date,
    String,
    console: { log(){}, warn(...args){ events.warnings.push(args.join(' ')); } },
    navigator: { serviceWorker: sw },
    sessionStorage: {
      getItem(name) { assert.equal(name, 'cdb_ver_stamp'); return 'previous-release'; },
      setItem(name, value) { events.storedVersion = value; }
    },
    fetch(url) {
      assert.match(url, /^\/version\.json\?_t=/);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ version: 'new-release' }) });
    },
    caches: {
      keys: () => Promise.resolve(['sentinel-apex-old-cache']),
      delete: () => Promise.resolve(true)
    },
    window: { location: { reload() { events.reloads++; } } }
  };
  vm.runInNewContext(guard, context, { filename: 'anti-stale-recovery-inline.js' });
  // Drain promise continuations, including update + cache deletion + reload.
  for (let i = 0; i < 6; i++) await Promise.resolve();
  await new Promise(resolve => setImmediate(resolve));
  return events;
}

test('stale registration.update rejection is handled without interrupting reload recovery', async () => {
  const events = await runScenario();
  assert.equal(events.updates, 2, 'both initial and version-change updates were attempted');
  assert.equal(events.handled, 2, 'every update rejection must be observed');
  assert.equal(events.reloads, 1, 'bounded anti-stale recovery must still reload');
  assert.equal(events.storedVersion, 'new-release');
  assert.ok(events.warnings.some(msg => msg.includes('Service Worker update unavailable')));
});

test('getRegistrations rejection does not interrupt cache cleanup or reload', async () => {
  const events = await runScenario({ rejectEnumeration: true });
  assert.equal(events.updates, 1);
  assert.equal(events.handled, 1);
  assert.equal(events.reloads, 1);
  assert.ok(events.warnings.some(msg => msg.includes('registrations unavailable')));
});
