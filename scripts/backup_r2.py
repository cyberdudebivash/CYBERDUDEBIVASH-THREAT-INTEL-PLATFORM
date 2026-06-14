#!/usr/bin/env python3
"""
scripts/backup_r2.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Cloudflare R2 Bucket Backup

Syncs R2 bucket content to a daily backup manifest with SHA-256 checksums.
Objects modified since last backup are re-verified and catalogued.

Env vars required:
  CF_R2_ACCESS_KEY_ID     - R2 S3-compatible access key
  CF_R2_SECRET_ACCESS_KEY - R2 S3-compatible secret key
  CF_R2_ENDPOINT          - https://<account_id>.r2.cloudflarestorage.com

Optional:
  CF_R2_BACKUP_BUCKET     - secondary backup bucket (if set, copies objects there)
  BACKUP_MANIFEST_PREFIX  - R2 key prefix for manifests (default: r2-backups/)
"""
import os
import sys
import json
import hashlib
import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("FATAL: boto3 is required. Run: pip install boto3")
    sys.exit(1)

CF_R2_ACCESS_KEY = os.environ.get("CF_R2_ACCESS_KEY_ID", "")
CF_R2_SECRET_KEY = os.environ.get("CF_R2_SECRET_ACCESS_KEY", "")
CF_R2_ENDPOINT   = os.environ.get("CF_R2_ENDPOINT", "")
BACKUP_BUCKET    = os.environ.get("CF_R2_BACKUP_BUCKET", "")
MANIFEST_PREFIX  = os.environ.get("BACKUP_MANIFEST_PREFIX", "r2-backups/")

SOURCE_BUCKETS = [
    "sentinel-apex-data",
    "sentinel-apex-reports",
]


def get_s3():
    if not all([CF_R2_ACCESS_KEY, CF_R2_SECRET_KEY, CF_R2_ENDPOINT]):
        print("FATAL: CF_R2_ACCESS_KEY_ID, CF_R2_SECRET_ACCESS_KEY, and CF_R2_ENDPOINT required")
        sys.exit(1)
    return boto3.client(
        "s3",
        endpoint_url=CF_R2_ENDPOINT,
        aws_access_key_id=CF_R2_ACCESS_KEY,
        aws_secret_access_key=CF_R2_SECRET_KEY,
        region_name="auto",
    )


def list_objects(s3, bucket, prefix=""):
    objects = []
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                objects.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "etag": obj.get("ETag", "").strip('"'),
                })
    except ClientError as e:
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


def backup_bucket(s3, bucket_name, today):
    print(f"\n[{bucket_name}]")
    objects = list_objects(s3, bucket_name)
    if objects is None:
        return None

    print(f"  Found {len(objects)} objects")

    verified = []
    errors = 0
    for i, obj in enumerate(objects):
        key = obj["key"]
        sha256, size = verify_object(s3, bucket_name, key)
        if sha256:
            verified.append({**obj, "sha256": sha256, "verified_size": size})
            if BACKUP_BUCKET:
                copy_to_backup(s3, bucket_name, key, BACKUP_BUCKET)
        else:
            print(f"  WARN: Could not verify {key}")
            verified.append({**obj, "sha256": "ERROR", "verified_size": 0})
            errors += 1
        if i > 0 and i % 50 == 0:
            print(f"  Progress: {i}/{len(objects)} objects verified...")

    manifest = {
        "bucket": bucket_name,
        "backup_date": today,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_objects": len(objects),
        "verified_objects": len(verified) - errors,
        "errors": errors,
        "total_size_bytes": sum(o.get("size", 0) for o in verified),
        "objects": verified,
    }
    print(f"  Verified: {len(verified) - errors}/{len(objects)} objects | Errors: {errors}")
    return manifest


def upload_manifest(s3, manifest, bucket, today):
    key = f"{MANIFEST_PREFIX}{today}/{manifest['bucket']}-manifest.json"
    body = json.dumps(manifest, indent=2).encode("utf-8")
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
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

    s3 = get_s3()
    failed = []

    for bucket in SOURCE_BUCKETS:
        manifest = backup_bucket(s3, bucket, today)
        if manifest is None:
            failed.append(bucket)
            continue
        # Write manifest back to the same bucket (under r2-backups/ prefix)
        upload_manifest(s3, manifest, bucket, today)

    if failed:
        print(f"\nFATAL: Failed buckets: {failed}")
        sys.exit(1)

    print(f"\n=== R2 Backup complete. {len(SOURCE_BUCKETS)} buckets catalogued. ===")


if __name__ == "__main__":
    main()
