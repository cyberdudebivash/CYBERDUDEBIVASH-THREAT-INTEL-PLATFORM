#!/usr/bin/env python3
"""
scripts/backup_kv_to_r2.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Cloudflare KV Namespace Backup to R2

Exports all 4 KV namespaces to R2 as daily snapshot JSON files.
Key schema: kv-snapshots/{YYYY-MM-DD}/{namespace_name}.json

Env vars required:
  CF_API_TOKEN            - CF token with KV:Read permission
  CF_ACCOUNT_ID           - Cloudflare account ID
  CF_R2_ACCESS_KEY_ID     - R2 S3-compatible access key
  CF_R2_SECRET_ACCESS_KEY - R2 S3-compatible secret key
  CF_R2_ENDPOINT          - https://<account_id>.r2.cloudflarestorage.com
  CF_R2_BUCKET            - target bucket (default: sentinel-apex-data)
"""
import os
import sys
import json
import time
import hashlib
import datetime
import urllib.request
import urllib.error
import urllib.parse

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("FATAL: boto3 is required. Run: pip install boto3")
    sys.exit(1)

CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_R2_ACCESS_KEY = os.environ.get("CF_R2_ACCESS_KEY_ID", "")
CF_R2_SECRET_KEY = os.environ.get("CF_R2_SECRET_ACCESS_KEY", "")
CF_R2_ENDPOINT = os.environ.get("CF_R2_ENDPOINT", "")
CF_R2_BUCKET = os.environ.get("CF_R2_BUCKET", "sentinel-apex-data")

KV_NAMESPACES = {
    "API_KEYS_KV":      "ca786702c6df47b7a95d9777536c7cfb",
    "RATE_LIMIT_KV":    "647efdda28dc4a2db91378931cfa02dc",
    "ANALYTICS_KV":     "baa66e510f7247d4b268af943bfb7213",
    "SECURITY_HUB_KV":  "95faae90943f43afa26d552b8385d339",
}

SKIP_TRANSIENT_IN = {"RATE_LIMIT_KV"}


def cf_get(path, params=None):
    url = f"{CF_API_BASE}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"CF API {path} -> HTTP {e.code}: {body[:200]}")


def list_kv_keys(ns_id, prefix=None):
    keys = []
    cursor = None
    _MAX_PAGES = 500  # hard ceiling: 500 pages × 1000 keys = 500K keys max
    _page = 0
    while True:
        _page += 1
        if _page > _MAX_PAGES:
            raise RuntimeError(
                f"KV list exceeded {_MAX_PAGES} pages for namespace {ns_id} — "
                "possible infinite cursor loop; aborting to prevent stall"
            )
        params = {"limit": "1000"}
        if cursor:
            params["cursor"] = cursor
        if prefix:
            params["prefix"] = prefix
        resp = cf_get(f"/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{ns_id}/keys", params)
        if not resp.get("success"):
            raise RuntimeError(f"KV list failed: {resp}")
        keys.extend(k["name"] for k in resp.get("result", []))
        cursor = resp.get("result_info", {}).get("cursor")
        if not cursor:
            break
        time.sleep(0.05)
    return keys


def get_kv_value(ns_id, key):
    url = f"{CF_API_BASE}/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{ns_id}/values/{urllib.parse.quote(key, safe='')}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {CF_API_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def backup_namespace(ns_name, ns_id, skip_transient):
    print(f"  Listing keys for {ns_name} ({ns_id})...")
    try:
        keys = list_kv_keys(ns_id)
    except Exception as e:
        print(f"  ERROR listing {ns_name}: {e}")
        return None

    print(f"  Found {len(keys)} keys in {ns_name}")

    if skip_transient:
        # Skip rate limit entries (rl: prefix) — transient state not worth backing up
        keys = [k for k in keys if not k.startswith("rl:")]
        print(f"  After transient filter: {len(keys)} keys")

    entries = {}
    errors = 0
    for i, key in enumerate(keys):
        try:
            val = get_kv_value(ns_id, key)
            entries[key] = val
        except Exception as e:
            print(f"    WARN: Could not fetch key {key!r}: {e}")
            errors += 1
        if i > 0 and i % 100 == 0:
            print(f"    Progress: {i}/{len(keys)} keys fetched...")
            time.sleep(0.05)

    checksum = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    return {
        "namespace": ns_name,
        "namespace_id": ns_id,
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "count": len(entries),
        "errors": errors,
        "checksum_sha256": checksum,
        "entries": entries,
    }


def upload_to_r2(key, data):
    if not all([CF_R2_ACCESS_KEY, CF_R2_SECRET_KEY, CF_R2_ENDPOINT]):
        print(f"  SKIP R2 upload (credentials not configured): {key}")
        return False

    s3 = boto3.client(
        "s3",
        endpoint_url=CF_R2_ENDPOINT,
        aws_access_key_id=CF_R2_ACCESS_KEY,
        aws_secret_access_key=CF_R2_SECRET_KEY,
        region_name="auto",
    )
    body = json.dumps(data, indent=2).encode("utf-8")
    try:
        s3.put_object(
            Bucket=CF_R2_BUCKET,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        size_kb = len(body) / 1024
        print(f"  Uploaded to R2: {key} ({size_kb:.1f} KB)")
        return True
    except ClientError as e:
        print(f"  ERROR uploading to R2: {e}")
        return False


def main():
    if not CF_API_TOKEN:
        print("FATAL: CF_API_TOKEN not set")
        sys.exit(1)
    if not CF_ACCOUNT_ID:
        print("FATAL: CF_ACCOUNT_ID not set")
        sys.exit(1)

    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    print(f"=== SENTINEL APEX KV Backup -> R2 | Date: {today} ===")

    failed = []
    for ns_name, ns_id in KV_NAMESPACES.items():
        print(f"\n[{ns_name}]")
        skip = ns_name in SKIP_TRANSIENT_IN
        snapshot = backup_namespace(ns_name, ns_id, skip_transient=skip)
        if snapshot is None:
            failed.append(ns_name)
            continue
        r2_key = f"kv-snapshots/{today}/{ns_name}.json"
        ok = upload_to_r2(r2_key, snapshot)
        if not ok:
            # Save locally as fallback
            local_path = f"/tmp/kv_backup_{ns_name}_{today}.json"
            with open(local_path, "w") as f:
                json.dump(snapshot, f, indent=2)
            print(f"  Saved locally: {local_path}")

    if failed:
        print(f"\nFATAL: Failed namespaces: {failed}")
        sys.exit(1)

    print(f"\n=== KV Backup complete. All {len(KV_NAMESPACES)} namespaces exported. ===")


if __name__ == "__main__":
    main()
