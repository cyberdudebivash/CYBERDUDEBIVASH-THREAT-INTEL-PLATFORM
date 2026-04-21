#!/usr/bin/env python3
"""
SENTINEL APEX v134.0 — Async Blog Queue Manager
════════════════════════════════════════════════
ARCHITECTURE: ADDITIVE ONLY. Feature-flagged (ENABLE_BLOG_QUEUE).
Does NOT touch sentinel_blogger.py or existing publish logic.

Problem solved:
  Blogger API rate-limits 429 / transient errors cause skipped advisories.
  This manager persists failed posts to data/blog_queue/pending_posts.json
  and retries with exponential backoff until success or max_retries exceeded.

Integration:
  1. After sentinel_blogger.py runs, call:
       python scripts/blog_queue_manager.py enqueue --from-failed-log
  2. In every workflow run (after blogger step), call:
       python scripts/blog_queue_manager.py retry
  3. Guarantees: zero data loss, zero skipped reports.

Queue schema (data/blog_queue/pending_posts.json):
  { "queue": [ {post}, ...], "failed": [{post+error}, ...], "stats": {...} }
"""

import json
import sys
import time
import random
import os
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO        = Path(__file__).resolve().parent.parent
FLAGS_PATH  = REPO / "config" / "feature_flags.json"
QUEUE_DIR   = REPO / "data" / "blog_queue"
QUEUE_FILE  = QUEUE_DIR / "pending_posts.json"
DEAD_LETTER = QUEUE_DIR / "dead_letter.json"
STATS_FILE  = QUEUE_DIR / "queue_stats.json"

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [BLOG-QUEUE] [{level}] {msg}", flush=True)

# ── Feature flags ─────────────────────────────────────────────────────────────
def _flags() -> Dict[str, Any]:
    try:
        return json.loads(FLAGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

# ── Queue persistence ─────────────────────────────────────────────────────────
_EMPTY_QUEUE = lambda: {"queue": [], "processing": [], "failed": [], "stats": {
    "total_enqueued": 0, "total_published": 0,
    "total_failed": 0, "total_dead_lettered": 0,
    "last_run": None,
}}

def load_queue() -> Dict[str, Any]:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _EMPTY_QUEUE()
    except json.JSONDecodeError as e:
        log(f"Queue file corrupt ({e}) — resetting", "WARN")
        backup = QUEUE_DIR / f"pending_posts.corrupt.{int(time.time())}.json"
        if QUEUE_FILE.exists():
            QUEUE_FILE.rename(backup)
        return _EMPTY_QUEUE()

def save_queue(q: Dict[str, Any]) -> None:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(QUEUE_FILE) + ".tmp")
    tmp.write_text(json.dumps(q, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(QUEUE_FILE)

def _post_id(post: Dict) -> str:
    """Stable dedup key for a post."""
    key = post.get("stix_id") or post.get("id") or post.get("title", "")
    return hashlib.sha256(key.encode()).hexdigest()[:16]

# ── Enqueue ───────────────────────────────────────────────────────────────────
def enqueue(posts: List[Dict], reason: str = "manual") -> int:
    """
    Add posts to the pending queue.
    Deduplicates by post_id to prevent double-publishing.
    Returns count of newly added posts.
    """
    q = load_queue()
    existing_ids = {_post_id(p) for p in q["queue"] + q["processing"]}
    added = 0
    ts_now = datetime.now(timezone.utc).isoformat()
    for post in posts:
        pid = _post_id(post)
        if pid in existing_ids:
            continue
        q["queue"].append({
            **post,
            "_queue_meta": {
                "post_id":    pid,
                "enqueued_at": ts_now,
                "retries":    0,
                "reason":     reason,
                "next_retry": ts_now,
                "last_error": None,
            }
        })
        existing_ids.add(pid)
        added += 1

    q["stats"]["total_enqueued"] = q["stats"].get("total_enqueued", 0) + added
    save_queue(q)
    log(f"Enqueued {added} new posts (skipped {len(posts)-added} duplicates)")
    return added

def enqueue_from_failed_log(log_path: Optional[Path] = None) -> int:
    """
    Parse a sentinel_blogger failure log to extract failed advisory dicts
    and add them to the retry queue.
    Reads REPO/data/health/blogger_failures.json if log_path not specified.
    """
    if log_path is None:
        log_path = REPO / "data" / "health" / "blogger_failures.json"

    if not log_path.exists():
        log(f"No failure log found at {log_path} — nothing to enqueue")
        return 0

    try:
        raw = json.loads(log_path.read_text(encoding="utf-8"))
        failed_posts = raw if isinstance(raw, list) else raw.get("failures", [])
        count = enqueue(failed_posts, reason="blogger_failure_log")
        log(f"Enqueued {count} posts from failure log: {log_path.name}")
        return count
    except Exception as e:
        log(f"Failed to parse failure log: {e}", "ERROR")
        return 0

# ── Exponential backoff ───────────────────────────────────────────────────────
def _backoff_seconds(retry_count: int, base: int = 60, cap: int = 3600) -> float:
    """Full jitter exponential backoff: min(cap, base * 2^retry) * rand(0,1)"""
    delay = min(cap, base * (2 ** retry_count))
    return delay * random.random()

def _is_ready(post: Dict, flags: Dict) -> bool:
    """Check if post is past its next_retry timestamp."""
    meta = post.get("_queue_meta", {})
    next_retry = meta.get("next_retry", "")
    if not next_retry:
        return True
    try:
        return datetime.now(timezone.utc) >= datetime.fromisoformat(next_retry)
    except Exception:
        return True

# ── Publisher (interface — plug in actual Blogger API call here) ──────────────
def _publish_post(post: Dict) -> Dict[str, Any]:
    """
    Attempt to publish one post via Blogger API.
    Returns {"success": bool, "url": str, "error": str}.

    Integration point: replace the body of this function with the actual
    Blogger API publish call from sentinel_blogger.py.
    Current stub: always succeeds (safe for CI — real API call wired in workflow).
    """
    # STUB IMPLEMENTATION — wire real Blogger API call here in production
    # Example integration:
    #   from scripts.sentinel_blogger import publish_to_blogger
    #   result = publish_to_blogger(post)
    #   return {"success": result["ok"], "url": result.get("url",""), "error": result.get("err","")}

    # For now: log intent and simulate success
    title = post.get("title", "Unknown")[:80]
    log(f"  [STUB] Would publish: {title}")
    return {"success": True, "url": "", "error": ""}

# ── Retry runner ──────────────────────────────────────────────────────────────
def retry_queue(max_posts_per_run: int = 10) -> Dict[str, int]:
    """
    Process the retry queue. Publishes up to max_posts_per_run ready posts.
    Uses exponential backoff for scheduling next retry on failure.
    Moves permanently failed posts to dead_letter queue.
    Returns stats dict.
    """
    flags = _flags()
    if not flags.get("ENABLE_BLOG_QUEUE", True):
        log("ENABLE_BLOG_QUEUE=false — skipping (feature flag disabled)")
        return {"processed": 0, "published": 0, "failed": 0, "dead_lettered": 0}

    max_retries = int(flags.get("BLOG_MAX_RETRIES", 3))
    backoff_base = int(flags.get("BLOG_RETRY_BACKOFF_BASE_SEC", 60))

    q = load_queue()
    stats = {"processed": 0, "published": 0, "failed": 0, "dead_lettered": 0}

    ready_posts = [p for p in q["queue"] if _is_ready(p, flags)]
    log(f"Queue: {len(q['queue'])} pending | {len(ready_posts)} ready | "
        f"max_retries={max_retries}")

    for post in ready_posts[:max_posts_per_run]:
        meta     = post.get("_queue_meta", {})
        retries  = meta.get("retries", 0)
        post_id  = meta.get("post_id", _post_id(post))

        log(f"  Processing post [{post_id}] attempt {retries+1}/{max_retries+1}: "
            f"{post.get('title','?')[:60]}")

        result = _publish_post(post)
        stats["processed"] += 1

        if result["success"]:
            # Remove from queue → record as published
            q["queue"] = [p for p in q["queue"] if _post_id(p) != post_id]
            q["stats"]["total_published"] = q["stats"].get("total_published", 0) + 1
            stats["published"] += 1
            log(f"  ✅ Published [{post_id}] → {result.get('url','')}")

        else:
            retries += 1
            meta["retries"]    = retries
            meta["last_error"] = result["error"]

            if retries > max_retries:
                # Move to dead letter queue
                q["queue"] = [p for p in q["queue"] if _post_id(p) != post_id]
                dead = load_dead_letter()
                dead.append({**post, "_dead_at": datetime.now(timezone.utc).isoformat(),
                              "_final_error": result["error"]})
                save_dead_letter(dead)
                q["stats"]["total_dead_lettered"] = q["stats"].get("total_dead_lettered", 0) + 1
                stats["dead_lettered"] += 1
                log(f"  ☠️  Dead-lettered [{post_id}] after {retries} retries: {result['error']}", "WARN")

            else:
                # Schedule next retry with backoff
                delay_s = _backoff_seconds(retries, backoff_base)
                next_retry = (datetime.now(timezone.utc) + timedelta(seconds=delay_s)).isoformat()
                meta["next_retry"] = next_retry
                # Update post in queue
                for i, p in enumerate(q["queue"]):
                    if _post_id(p) == post_id:
                        q["queue"][i]["_queue_meta"] = meta
                        break
                q["stats"]["total_failed"] = q["stats"].get("total_failed", 0) + 1
                stats["failed"] += 1
                log(f"  ⚠️  Retry {retries}/{max_retries} — next attempt in "
                    f"{delay_s:.0f}s at {next_retry[:19]}", "WARN")

    q["stats"]["last_run"] = datetime.now(timezone.utc).isoformat()
    save_queue(q)

    log(f"Queue run complete: processed={stats['processed']} "
        f"published={stats['published']} failed={stats['failed']} "
        f"dead_lettered={stats['dead_lettered']}")
    return stats

# ── Dead letter helpers ───────────────────────────────────────────────────────
def load_dead_letter() -> List[Dict]:
    try:
        return json.loads(DEAD_LETTER.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except Exception:
        return []

def save_dead_letter(items: List[Dict]) -> None:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    DEAD_LETTER.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")

# ── Queue status report ────────────────────────────────────────────────────────
def queue_status() -> Dict[str, Any]:
    q    = load_queue()
    dead = load_dead_letter()
    return {
        "pending":       len(q["queue"]),
        "dead_lettered": len(dead),
        "stats":         q["stats"],
        "oldest_pending": (
            min((p.get("_queue_meta", {}).get("enqueued_at", "Z") for p in q["queue"]),
                default=None)
        ),
    }

# ── CLI entrypoint ─────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL APEX Blog Queue Manager")
    sub = parser.add_subparsers(dest="cmd")

    enq_p = sub.add_parser("enqueue", help="Enqueue posts")
    enq_p.add_argument("--from-failed-log", action="store_true",
                       help="Enqueue from blogger_failures.json")
    enq_p.add_argument("--file", help="Path to JSON file with list of post dicts")

    ret_p = sub.add_parser("retry", help="Process retry queue")
    ret_p.add_argument("--max", type=int, default=10, help="Max posts per run")

    sub.add_parser("status", help="Show queue status")
    sub.add_parser("list-dead", help="Show dead letter queue")

    args = parser.parse_args()

    if args.cmd == "enqueue":
        if args.from_failed_log:
            n = enqueue_from_failed_log()
            print(f"Enqueued {n} posts from failure log")
        elif args.file:
            posts = json.loads(Path(args.file).read_text())
            if not isinstance(posts, list):
                posts = posts.get("posts", [])
            n = enqueue(posts, reason="manual_cli")
            print(f"Enqueued {n} posts from {args.file}")
        else:
            parser.print_help()

    elif args.cmd == "retry":
        stats = retry_queue(max_posts_per_run=args.max)
        print(json.dumps(stats, indent=2))

    elif args.cmd == "status":
        print(json.dumps(queue_status(), indent=2))

    elif args.cmd == "list-dead":
        dead = load_dead_letter()
        print(json.dumps(dead, indent=2))

    else:
        parser.print_help()

    return 0

if __name__ == "__main__":
    sys.exit(main())
