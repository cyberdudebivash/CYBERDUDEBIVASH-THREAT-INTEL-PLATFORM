// P0: stamp the reviewed exact Git SHA into the *ephemeral* production config.
// The checked-in TOML is never changed; this runs only after the manual
// workflow's main-ref + exact-head approval checks and before Wrangler deploy.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const VALID_SHA = /^[a-f0-9]{40}$/;

export function stampProductionSha(source, sha) {
  if (typeof source !== 'string' || typeof sha !== 'string' || !VALID_SHA.test(sha)) {
    throw new Error('invalid source or approved 40-character lowercase Git SHA');
  }
  const newline = source.includes('\r\n') ? '\r\n' : '\n';
  const lines = source.split(/\r?\n/);
  const headers = lines
    .map((line, i) => ({ line: line.trim(), i }))
    .filter(({ line }) => /^\[[^\]]+\]$/.test(line));
  const targets = headers.filter(({ line }) => line === '[env.production.vars]');
  if (targets.length !== 1) throw new Error('expected exactly one named production vars table');
  // Do not create a duplicate field or silently replace someone else's
  // source-identity binding, even if it is in the unrelated default env.
  if (lines.some((line) => /^\s*ENGINE_RELEASE_SHA\s*=/.test(line))) {
    throw new Error('release SHA already configured; refusing overwrite');
  }
  const start = targets[0].i + 1;
  const next = headers.find(({ i }) => i >= start);
  const end = next ? next.i : lines.length;
  const section = lines.slice(start, end);
  if (section.filter((line) => /^\s*ENGINE_VERSION\s*=\s*"[^"]+"\s*$/.test(line)).length !== 1) {
    throw new Error('missing or ambiguous named production engine version');
  }
  lines.splice(start, 0, `ENGINE_RELEASE_SHA = "${sha}"`);
  return lines.join(newline);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) throw new Error('usage: stamp-release-sha.mjs <approved_sha> <wrangler.toml>');
    const sha = process.argv[2];
    const filename = resolve(process.argv[3]);
    const original = readFileSync(filename, 'utf8');
    const stamped = stampProductionSha(original, sha);
    writeFileSync(filename, stamped, { encoding: 'utf8' });
    process.stdout.write('Named production release-SHA variable stamped into ephemeral Wrangler config.\n');
  } catch (error) {
    process.stderr.write(`Release SHA stamp refused: ${error.message}\n`);
    process.exitCode = 1;
  }
}
