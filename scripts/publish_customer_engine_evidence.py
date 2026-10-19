#!/usr/bin/env python3
"""Normalize canonical customer summaries from the downloaded manifest.

Run inside the existing sovereign workflow before validation/R2 upload.
No network operations; missing/invalid/empty inputs fail without overwriting
previous valid output. Coverage generation time is not feed publication time.
"""
import argparse
import json
from pathlib import Path
try:
    from scripts import regenerate_engine_data as regen
except ModuleNotFoundError:
    import regenerate_engine_data as regen

def publish(manifest: Path, root: Path) -> dict:
    raw = json.loads(manifest.read_text(encoding='utf-8'))
    # The canonical R2 feed (intel/feed_manifest.json) is produced as either
    # a bare record list or the 'advisories'/'items' envelope consumed by the
    # weekly source loader. Older fixtures use 'entries'; retain that path.
    # Use first-present semantics: an explicitly empty authoritative list
    # cannot silently fall back to another, potentially stale envelope.
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        records = next((raw[key] for key in ('advisories', 'items', 'entries') if key in raw), None)
    else:
        records = None
    if not isinstance(records, list) or not records or any(not isinstance(row, dict) for row in records):
        raise ValueError('Expected a nonempty manifest record list; publication blocked')
    outputs = {
        'data/cortex/cortex_output.json': regen.generate_cortex(records),
        'data/quantum/quantum_output.json': regen.generate_quantum(records),
        'data/sovereign/sovereign_output.json': regen.generate_sovereign(records),
    }
    # Serialize every result before any writes; never partially publish a
    # successful aggregate if another generator yields invalid JSON.
    for data in outputs.values():
        json.dumps(data, allow_nan=False)
        data['input_evidence'] = {'source': 'authoritative_feed_manifest', 'record_count':len(records)}
    for name,data in outputs.items():
        if not regen._safe_write(str(root/name),data):
            raise RuntimeError('Customer evidence write failed; upload must not proceed')
    return outputs

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',default='data/stix/feed_manifest.json')
    parser.add_argument('--root',default='.')
    args=parser.parse_args()
    result=publish(Path(args.manifest),Path(args.root))
    print('Customer evidence summaries validated:', ', '.join(result))
