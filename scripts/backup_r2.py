#!/usr/bin/env python3
# P0 release-assurance review: independently rescan this changed Cloudflare
# metered-backup surface after the bypassed PR #814 required SAST failure.
"""
scripts/backup_r2.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Cloudflare R2 Bucket Backup

Syncs R2 bucket content to a daily backup manifest with SHA-256 checksums.

P0 R2 COST INCIDENT FIX (2026-09): this was a SECOND, independent full-bucket
amplifier alongside scripts/r2_upload.py's whole-corpus sync (see
docs/P0_R2_COST_CONTAINMENT.md). Confirmed live: this script ran DAILY
(automated-backup.yml, cron 0 1 * * *, its own concurrency group -- not
serialized against sentinel-blogger.yml) and unconditionally GET+SHA256'd
EVERY object in BOTH sentinel-apex-data and sentinel-apex-reports, no
sampling, no bound (~278,790 GETs/day at incident-time object counts).
Two fixes, both evidence-based, not just "reduce the number":
  1. sentinel-apex-reports removed from SOURCE_BUCKETS entirely. Its content
     is now bounded to a 24h rolling window and fully regenerable from the
     core intelligence manifest (scripts/generate_intel_reports.py) --
     backing it up is not needed, and daily-verifying the (formerly ~193K,
     now historical) object corpus is exactly the "historical verification
     scan against sentinel-apex-reports" the cost-containment hardening
     explicitly prohibits in normal operation, independent of retention
     window. sentinel-apex-data (genuine irreplaceable state: dedup
     history, manifests, KV snapshots) remains backed up.
  2. Per-object GET+SHA256 verification is bounded to a rotating sample
     (MAX_BACKUP_VERIFY_OBJECTS_PER_RUN per run) rather than 100% of the
     bucket every day -- see verify_sample_indices()'s docstring for the
     coverage-over-time guarantee this still provides. Objects outside
     this run's sample are still catalogued in the manifest (key/size/etag
     from the LIST response, which is already paid for) with sha256 left
     unset, not silently dropped.

Env vars required:
  CF_R2_ACCESS_KEY_ID     - R2 S3-compatible access key
  CF_R2_SECRET_ACCESS_KEY - R2 S3-compatible secret key
  CF_R2_ENDPOINT          - https://<account_id>.r2.cloudflarestorage.com

Optional:
  CF_R2_BACKUP_BUCKET             - secondary backup bucket (if set, copies verified objects there)
  BACKUP_MANIFEST_PREFIX          - R2 key prefix for manifests (default: r2-backups/)
  MAX_BACKUP_VERIFY_OBJECTS_PER_RUN - per-run GET+SHA256 verification cap (default: 2000)
"""
import os
import sys
import json
import hashlib
import datetime

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from r2_cost_guard import (R2OperationPlan, emit_summary, R2Budgets,
                           enforce_budget, R2BudgetExceeded)  # noqa: E402
from cloudflare_metered_backup_guard import require_metered_backup_permit, MeteredBackupDenied  # noqa: E402

try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.config import Config
except ImportError:
    print("FATAL: boto3 is required. Run: pip install boto3")
    sys.exit(1)

CF_R2_ACCESS_KEY = os.environ.get("CF_R2_ACCESS_KEY_ID", "")
CF_R2_SECRET_KEY = os.environ.get("CF_R2_SECRET_ACCESS_KEY", "")
CF_R2_ENDPOINT   = os.environ.get("CF_R2_ENDPOINT", "")
BACKUP_BUCKET    = os.environ.get("CF_R2_BACKUP_BUCKET", "")
MANIFEST_PREFIX  = os.environ.get("BACKUP_MANIFEST_PREFIX", "r2-backups/")
# Hard ceilings; to raise them requires source review, not environment overrides.
MAX_VERIFY_PER_RUN = min(500, max(1, int(os.environ.get("MAX_BACKUP_VERIFY_OBJECTS_PER_RUN", "500"))))
MAX_LIST_PAGES = 99  # at most 100 network LISTs incl. the overflow check
MAX_MANIFEST_BYTES = 16 * 1024 * 1024  # independent R2 storage/PUT bound

# sentinel-apex-reports intentionally excluded -- see module docstring's
# P0 R2 COST INCIDENT FIX note (fix #1). Never touch cyberdudebivash-scan-results
# either (out of scope for this backup job, always has been -- not listed here).
SOURCE_BUCKETS = [
    "sentinel-apex-data",
]


def r2_credentials_configured() -> bool:
    return all([CF_R2_ACCESS_KEY, CF_R2_SECRET_KEY, CF_R2_ENDPOINT])


def get_s3():
    # Callers must check r2_credentials_configured() first (see main()) -- this function assumes
    # it, so this remains a hard FATAL only for the case that should never happen (checked once,
    # then called immediately after).
    if not r2_credentials_configured():
        print("FATAL: CF_R2_ACCESS_KEY_ID, CF_R2_SECRET_ACCESS_KEY, and CF_R2_ENDPOINT required")
        sys.exit(1)
    return boto3.client(
        "s3",
        endpoint_url=CF_R2_ENDPOINT,
        aws_access_key_id=CF_R2_ACCESS_KEY,
        aws_secret_access_key=CF_R2_SECRET_KEY,
        region_name="auto",
        config=Config(retries={"total_max_attempts": 1}),
    )


def list_objects(s3, bucket, prefix="", plan=None):
    objects = []
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page_number, page in enumerate(paginator.paginate(Bucket=bucket, Prefix=prefix), 1):
            if plan is not None:
                plan.record_list()
            if page_number > MAX_LIST_PAGES:
                raise RuntimeError("R2 inventory exceeded 99 pages; BLOCK before manifest upload")
            for obj in page.get("Contents", []):
                objects.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "etag": obj.get("ETag", "").strip('"'),
                })
    except (ClientError, RuntimeError) as e:
        print(f"  ERROR listing {bucket}: {e}")
        return None
    return objects


def verify_object(s3, bucket, key):
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        data = resp["Body"].read()
        sha256 = hashlib.sha256(data).hexdigest()
        return sha256, len(data)
    except ClientError as e:
        return None, 0


def copy_to_backup(s3, src_bucket, key, dst_bucket):
    if not dst_bucket:
        return False
    try:
        s3.copy_object(
            CopySource={"Bucket": src_bucket, "Key": key},
            Bucket=dst_bucket,
            Key=f"{src_bucket}/{key}",
        )
        return True
    except ClientError as e:
        print(f"  WARN: Could not copy {key} to backup bucket: {e}")
        return False


def verify_sample_indices(total: int, sample_size: int, day_of_year: int) -> set:
    """Deterministic rotating window into a sorted object list -- gives
    eventual full coverage (every object gets GET+SHA256-verified at least
    once every ceil(total/sample_size) days) without ever exceeding
    sample_size verifications in a single run. Contiguous (not random)
    purely so a human reading two consecutive days' manifests can see the
    window visibly advance -- the coverage guarantee doesn't depend on that,
    only on the offset advancing by sample_size (mod total) every day.
    """
    if total <= 0 or sample_size <= 0:
        return set()
    if sample_size >= total:
        return set(range(total))
    offset = (day_of_year * sample_size) % total
    if offset + sample_size <= total:
        return set(range(offset, offset + sample_size))
    return set(range(offset, total)) | set(range(0, (offset + sample_size) - total))


def backup_bucket(s3, bucket_name, today, plan: R2OperationPlan):
    print(f"\n[{bucket_name}]")
    objects = list_objects(s3, bucket_name, plan=plan)
    if objects is None:
        return None
    objects.sort(key=lambda o: o["key"])  # stable order so the rotating sample is well-defined
    # LIST calls were counted for each network page in list_objects(), including abort.

    print(f"  Found {len(objects)} objects")

    day_of_year = datetime.date.today().timetuple().tm_yday
    sample_idx = verify_sample_indices(len(objects), MAX_VERIFY_PER_RUN, day_of_year)
    if len(objects) > MAX_VERIFY_PER_RUN:
        cycle_days = -(-len(objects) // MAX_VERIFY_PER_RUN)
        print(f"  P0 cost fix: verifying a rotating sample of {len(sample_idx)}/{len(objects)} "
              f"objects this run (full coverage cycle: ~{cycle_days} day(s)). "
              f"Un-sampled objects are still catalogued (key/size/etag) with sha256 unset.")

    verified = []
    errors = 0
    verified_this_run = 0
    for i, obj in enumerate(objects):
        key = obj["key"]
        if i not in sample_idx:
            verified.append({**obj, "sha256": None, "verified_size": None})
            continue
        plan.record_get()
        sha256, size = verify_object(s3, bucket_name, key)
        verified_this_run += 1
        if sha256:
            verified.append({**obj, "sha256": sha256, "verified_size": size})
            if BACKUP_BUCKET:
                copy_to_backup(s3, bucket_name, key, BACKUP_BUCKET)
                plan.record_copy()
        else:
            print(f"  WARN: Could not verify {key}")
            verified.append({**obj, "sha256": "ERROR", "verified_size": 0})
            errors += 1
        if verified_this_run > 0 and verified_this_run % 200 == 0:
            print(f"  Progress: {verified_this_run}/{len(sample_idx)} sampled objects verified...")

    manifest = {
        "bucket": bucket_name,
        "backup_date": today,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_objects": len(objects),
        "verified_this_run": verified_this_run,
        "errors": errors,
        "total_size_bytes": sum(o.get("size", 0) for o in objects),
        "objects": verified,
    }
    print(f"  Verified this run: {verified_this_run - errors}/{len(objects)} total objects | Errors: {errors}")
    return manifest


def upload_manifest(s3, manifest, bucket, today, plan: R2OperationPlan):
    key = f"{MANIFEST_PREFIX}{today}/{manifest['bucket']}-manifest.json"
    body = json.dumps(manifest, indent=2).encode("utf-8")
    if len(body) > MAX_MANIFEST_BYTES:
        print("  BLOCK: R2 inventory manifest exceeds 16 MiB storage budget")
        return False
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        plan.record_put(nbytes=len(body))
        print(f"  Manifest saved: {bucket}/{key}")
        return True
    except ClientError as e:
        print(f"  ERROR saving manifest: {e}")
        local_path = f"/tmp/r2_manifest_{manifest['bucket']}_{today}.json"
        with open(local_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"  Saved locally: {local_path}")
        return False


def main():
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    print(f"=== SENTINEL APEX R2 Backup | Date: {today} ===")

    # Matches backup_kv_to_r2.py's upload_to_r2() precedent (same job, sibling script): missing
    # R2 credentials is an expected, environment-dependent condition, not a code defect, and that
    # script already treats it as a SKIP rather than a hard failure. Unlike that script, this
    # one's entire job is R2-based (there's no KV-via-API fallback to still attempt), so there is
    # nothing partial to do here -- the whole run is the thing being skipped. Exiting 0 (not 1)
    # for this specific, named, already-precedented condition keeps this job from going red for
    # an unconfigured-environment state its own sibling step doesn't fail on either.
    if not r2_credentials_configured():
        print("SKIP: CF_R2_ACCESS_KEY_ID, CF_R2_SECRET_ACCESS_KEY, and CF_R2_ENDPOINT not configured "
              "-- R2 bucket backup requires them and has nothing else it can do. Not a code error; "
              "matches backup_kv_to_r2.py's own treatment of this identical condition.")
        sys.exit(0)

    # The next operation is a billed R2 call. Deny first if 10-platform
    # Cloudflare headroom/approval has not been established.
    try:
        require_metered_backup_permit()
        if SOURCE_BUCKETS != ["sentinel-apex-data"] or BACKUP_BUCKET:
            raise MeteredBackupDenied("unapproved bucket expansion or secondary COPY")
        approved = R2Budgets(max_list_calls_per_run=100,
                             max_class_b_calls_per_run=MAX_VERIFY_PER_RUN,
                             max_data_writes_per_run=1)
        worst_case = R2OperationPlan(label="backup_r2_preflight", bucket=SOURCE_BUCKETS[0])
        worst_case.record_list(100)  # 99 pages plus one overflow detection
        worst_case.record_get(MAX_VERIFY_PER_RUN)
        worst_case.record_put()
        enforce_budget(worst_case, approved, is_report_plan=False)
    except (MeteredBackupDenied, R2BudgetExceeded) as exc:
        print(f"BLOCK: R2 optional backup rejected before network calls: {exc}")
        sys.exit(2)

    s3 = get_s3()
    failed = []
    plan = R2OperationPlan(label="backup_r2", bucket=",".join(SOURCE_BUCKETS))

    for bucket in SOURCE_BUCKETS:
        manifest = backup_bucket(s3, bucket, today, plan)
        if manifest is None:
            failed.append(bucket)
            continue
        # Write manifest back to the same bucket (under r2-backups/ prefix)
        if not upload_manifest(s3, manifest, bucket, today, plan):
            failed.append(bucket)

    # P0 R2 cost fix: observability parity with r2_upload.py/r2_report_publisher.py --
    # this job is not budget-ENFORCED (it's a bounded-by-construction daily inventory,
    # continue-on-error in automated-backup.yml), but it must still be counted so the
    # platform's total R2 footprint is visible in one place (data/quality/r2_cost_guard_report.json).
    emit_summary(plan, approved, status="BLOCKED" if failed else "PASS", is_report_plan=False)

    if failed:
        print(f"\nFATAL: Failed buckets: {failed}")
        sys.exit(1)

    print(f"\n=== R2 Backup complete. {len(SOURCE_BUCKETS)} bucket(s) catalogued "
          f"(sentinel-apex-reports excluded -- see module docstring). ===")


if __name__ == "__main__":
    main()
