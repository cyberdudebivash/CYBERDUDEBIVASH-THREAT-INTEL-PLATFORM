#!/usr/bin/env node
/**
 * Builds the Cyber Watchdog SAFE ROLLBACK TARGET deterministically:
 *   git archive <base_sha> workers/intel-gateway   (the exact pre-v3 gateway)
 *   + verify the four base files are the expected originals
 *   + overlay the four reviewed files from ./overlay
 *   + verify the digest of the resulting worker tree against manifest.json
 *
 *   node deploy/cyber-watchdog/safe-rollback/build.mjs --out /tmp/wd-safe-rollback
 *   node deploy/cyber-watchdog/safe-rollback/build.mjs --out DIR --record   (maintainers: rewrite digest)
 *
 * Then, from DIR/workers/intel-gateway:  npx wrangler deploy --env production
 * Exit 0 only when every hash matches. Prints JSON evidence.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const manifestPath = path.join(HERE, "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const args = process.argv.slice(2);
const outArg = args.indexOf("--out");
const out = path.resolve(outArg >= 0 ? args[outArg + 1] : path.join(REPO, ".safe-rollback-build"));
const record = args.includes("--record");

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const git = (...a) => execFileSync("git", a, { cwd: REPO, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 30 });

function fail(reason, extra = {}) {
  process.stdout.write(JSON.stringify({ result: "FAIL", reason, ...extra }, null, 2) + "\n");
  process.exit(1);
}

// 1. Base commit available (fetch it if this is a shallow clone).
try { git("cat-file", "-e", manifest.base_sha + "^{commit}"); } catch {
  try { git("fetch", "--no-tags", "--depth", "1", "origin", manifest.base_sha); } catch { fail("base_commit_unavailable", { base_sha: manifest.base_sha }); }
}

// 2. Exact pre-v3 gateway tree.
if (existsSync(out)) rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
const tar = git("archive", "--format=tar", manifest.base_sha, "workers/intel-gateway");
execFileSync("tar", ["-x", "-C", out], { input: tar });

// 3. The files being replaced are the expected originals.
for (const [rel, want] of Object.entries(manifest.base_files_sha256)) {
  const got = sha256(readFileSync(path.join(out, rel)));
  if (got !== want) fail("base_file_mismatch", { file: rel, got, want });
}

// 4. Overlay the reviewed files (and only those).
for (const [rel, want] of Object.entries(manifest.overlay_files_sha256)) {
  const src = path.join(HERE, "overlay", rel);
  const got = sha256(readFileSync(src));
  if (got !== want) fail("overlay_file_mismatch", { file: rel, got, want });
  cpSync(src, path.join(out, rel));
}

// 5. Digest of the whole deployable worker tree (sorted path + content hash).
function walk(dir, acc = []) {
  for (const name of readdirSync(dir).sort()) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, acc); else acc.push(p);
  }
  return acc;
}
const root = path.join(out, "workers/intel-gateway");
const lines = walk(root).map((p) => path.relative(out, p).split(path.sep).join("/") + " " + sha256(readFileSync(p)));
const digest = sha256(lines.join("\n") + "\n");
if (record) {
  manifest.artifact_digest = digest;
  manifest.artifact_file_count = lines.length;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
} else if (digest !== manifest.artifact_digest) {
  fail("artifact_digest_mismatch", { got: digest, want: manifest.artifact_digest });
}
process.stdout.write(JSON.stringify({
  result: "PASS",
  target: manifest.name,
  base_sha: manifest.base_sha,
  artifact_digest: digest,
  files: lines.length,
  worker_dir: root,
  deploy: "cd " + root + " && npx wrangler deploy --env production",
}, null, 2) + "\n");
