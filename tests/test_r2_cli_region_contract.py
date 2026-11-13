"""R2 AWS CLI signing-region regression (offline, zero cloud operations).

A real publisher failed with InvalidRegionName on us-west-2, returning 400
for multiple HeadObject state reads. This suite uses the actual shared R2
transport helper methods and records each generated command without running
the AWS CLI, fetching keys, or contacting R2.
"""
from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from scripts import r2_upload


ENDPOINT = "https://account-placeholder.r2.cloudflarestorage.com"


def _fake_cli(monkeypatch, returncode=0, error=""):
    issued = []

    def run(command, **kwargs):
        assert isinstance(command, list), "never run concatenated shell strings"
        issued.append(list(command))
        return CompletedProcess(command, returncode, stdout="", stderr=error)

    monkeypatch.setattr(r2_upload.subprocess, "run", run)
    return issued


def test_every_r2_s3_operation_pins_auto_even_if_runner_region_is_us_west_2(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    commands = _fake_cli(monkeypatch)
    assert r2_upload.s3_cp("local.json", "bucket", "state/item.json", ENDPOINT)
    assert r2_upload.s3_get("local.json", "bucket", "state/item.json", ENDPOINT) == "OK"
    assert r2_upload.s3_delete("bucket", "state/item.json", ENDPOINT)
    assert r2_upload.s3_sync("local-folder", "bucket", "state", ENDPOINT)
    assert r2_upload.s3_sync_download("local-folder", "bucket", "state", ENDPOINT)
    assert len(commands) == 5
    for command in commands:
        assert command[:2] == ["aws", "s3"]
        assert command.count("--region") == 1
        assert command[command.index("--region") + 1] == "auto"
        assert command.count("--endpoint-url") == 1
        assert command[command.index("--endpoint-url") + 1] == ENDPOINT
        assert "us-west-2" not in command, "never inherit incompatible AWS signing region"
    assert r2_upload.R2_S3_REGION == "auto"


@pytest.mark.parametrize("error", [
    "An error occurred (400) when calling the HeadObject operation: Bad Request",
    "InvalidRegionName: The region name 'us-west-2' is not valid",
    "AccessDenied: invalid credentials",
])
def test_r2_read_transport_errors_stay_fail_closed(monkeypatch, error):
    commands = _fake_cli(monkeypatch, 1, error)
    assert r2_upload.s3_get("local.json", "bucket", "state/item.json", ENDPOINT) == "ERROR"
    assert r2_upload.s3_sync_download("local-folder", "bucket", "state", ENDPOINT) is False
    assert len(commands) == 2
    assert all(c[c.index("--region") + 1] == "auto" for c in commands)


def test_no_global_aws_config_or_environment_mutation(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    commands = _fake_cli(monkeypatch)
    r2_upload.s3_get("state.json", "bucket", "item", ENDPOINT)
    import os
    assert os.environ["AWS_DEFAULT_REGION"] == "us-west-2"
    assert os.environ["AWS_REGION"] == "us-west-2"
    assert len(commands) == 1
    assert commands[0][:2] == ["aws", "s3"]
    assert "configure" not in commands[0]


def test_final_paid_manifest_resync_pins_cloudflare_region(monkeypatch):
    """Last-mile PRO uploader must obey the same signing contract as state sync."""
    from scripts import r2_resync_manifests as resync
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    commands = _fake_cli(monkeypatch)
    assert resync.s3_cp("latest_pro.json", "bucket", "api/v1/intel/latest_pro.json",
                        ENDPOINT, cache_control="private, no-store")
    assert len(commands) == 1
    command = commands[0]
    assert command[:2] == ["aws", "s3"]
    assert command.count("--region") == 1
    assert command[command.index("--region") + 1] == "auto"
    assert command[command.index("--endpoint-url") + 1] == ENDPOINT
    assert command[command.index("--cache-control") + 1] == "private, no-store"
    assert "us-west-2" not in command
    assert resync.R2_S3_REGION == r2_upload.R2_S3_REGION


def test_final_paid_manifest_resync_upload_failure_stays_nonzero(monkeypatch):
    from scripts import r2_resync_manifests as resync
    commands = _fake_cli(monkeypatch, returncode=1, error="InvalidRegionName")
    assert not resync.s3_cp("latest_pro.json", "bucket", "api/v1/intel/latest_pro.json",
                            ENDPOINT, cache_control="private, no-store")
    assert len(commands) == 1
    assert commands[0][commands[0].index("--region") + 1] == "auto"
