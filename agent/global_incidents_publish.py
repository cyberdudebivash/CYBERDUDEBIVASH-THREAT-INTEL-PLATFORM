"""GCII offline publisher: reviewed input -> validated, atomic JSON artifact.

Usage: python -m agent.global_incidents_publish reviewed.json output/feed.json
No remote fetching, no production writes, no background scheduling.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import tempfile
from agent.global_incidents import build_feed, IncidentValidationError

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024

def publish(input_path: str, output_path: str) -> dict:
    source = Path(input_path)
    target = Path(output_path)
    if not source.is_file() or source.stat().st_size > MAX_INPUT_BYTES:
        raise IncidentValidationError("missing or oversized input")
    if source.resolve() == target.resolve():
        raise IncidentValidationError("input and output must differ")
    with source.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise IncidentValidationError("input too large")
    try:
        events = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IncidentValidationError("invalid JSON input") from exc
    if not isinstance(events, list):
        raise IncidentValidationError("expected JSON array of reviewed incidents")
    feed = build_feed(events)
    data = (json.dumps(feed, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_OUTPUT_BYTES:
        raise IncidentValidationError("feed exceeds output budget")
    if not target.parent.is_dir():
        raise IncidentValidationError("output directory must already exist")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".gcii-", suffix=".tmp", delete=False) as tmp:
            temp_name = tmp.name
            os.chmod(temp_name, 0o600)
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temp_name, target)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return {"count": len(events), "sha256": feed["sha256"], "output": str(target)}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    print(json.dumps(publish(args.input, args.output)))

if __name__ == "__main__":
    main()
