from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

OPS_SCRIPTS = [
    "scripts/pipeline_alert.py",
    "scripts/check_pipeline_staleness.py",
    "scripts/enterprise_alert_manager.py",
    "scripts/print_anomaly_alert.py",
    "api/enterprise.py",
]

OPS_WORKFLOWS = [
    ".github/workflows/automated-backup.yml",
    ".github/workflows/deploy-swarm-live.yml",
    ".github/workflows/deploy-worker.yml",
    ".github/workflows/enterprise-alerts.yml",
    ".github/workflows/enterprise-governance.yml",
    ".github/workflows/enterprise-rollback-governance.yml",
    ".github/workflows/master-deployment-orchestrator.yml",
    ".github/workflows/pipeline-staleness-monitor.yml",
    ".github/workflows/post-deploy-validation.yml",
    ".github/workflows/r2-finops-regression-gate.yml",
    ".github/workflows/self-healing.yml",
    ".github/workflows/storage-governance.yml",
]

PUBLIC_INTEL_SURFACES = [
    "agent/telegram_alerts.py",
    "scripts/weekly_threat_brief.py",
    "scripts/v74_manifest_enricher.py",
    "scripts/growth/telegram_content_generator.py",
]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_internal_alert_scripts_never_consume_public_chat_secret():
    forbidden = (
        'os.environ.get("TELEGRAM_CHAT_ID"',
        'os.getenv("TELEGRAM_CHAT_ID"',
        'os.environ["TELEGRAM_CHAT_ID"]',
    )
    for rel in OPS_SCRIPTS:
        text = _read(rel)
        assert "TELEGRAM_OPS_CHAT_ID" in text, f"{rel} must use a private ops destination"
        for token in forbidden:
            assert token not in text, (
                f"{rel} consumes the public subscriber TELEGRAM_CHAT_ID; "
                "internal diagnostics must never be routed to customers"
            )


def test_internal_workflows_never_bind_public_telegram_destination():
    for rel in OPS_WORKFLOWS:
        text = _read(rel)
        assert "secrets.TELEGRAM_OPS_CHAT_ID" in text, f"{rel} must bind TELEGRAM_OPS_CHAT_ID"
        assert "secrets.TELEGRAM_CHAT_ID" not in text, (
            f"{rel} binds the public subscriber destination; this can expose "
            "workflow failures, repository/run IDs, backup state, or platform internals"
        )


def test_mixed_pipeline_has_explicit_channel_separation():
    text = _read(".github/workflows/sentinel-apex.yml")
    assert "secrets.TELEGRAM_CHAT_ID" in text, "public intel delivery must remain configured"
    assert "secrets.TELEGRAM_OPS_CHAT_ID" in text, "internal pipeline alerts need a separate private destination"


def test_public_intelligence_delivery_stays_on_public_channel():
    for rel in PUBLIC_INTEL_SURFACES:
        text = _read(rel)
        assert "TELEGRAM_CHAT_ID" in text, f"{rel} should remain a public intelligence-delivery surface"
