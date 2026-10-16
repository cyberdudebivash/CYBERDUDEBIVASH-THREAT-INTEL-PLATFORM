from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

ISOLATED_WRITERS = {
    ".github/workflows/arsenal.yml": "sentinel-data-writer-arsenal",
    ".github/workflows/convergence.yml": "sentinel-data-writer-convergence",
    ".github/workflows/bughunter-recon.yml": "sentinel-data-writer-bughunter",
    ".github/workflows/bughunter-resilient.yml": "sentinel-data-writer-bughunter",
    ".github/workflows/omnishield.yml": "sentinel-data-writer-omnishield",
    ".github/workflows/precognition-engine.yml": "sentinel-data-writer-precognition",
    ".github/workflows/weekly-analyst-briefing.yml": "sentinel-data-writer-weekly-analyst",
    ".github/workflows/syndicate.yml": "sentinel-data-writer-syndicate",
}

CORE_SERIALIZED_WRITERS = (
    ".github/workflows/sentinel-apex.yml",
    ".github/workflows/multi-source-intel.yml",
    ".github/workflows/dashboard-feeds-sync.yml",
    ".github/workflows/enterprise-intel-quality.yml",
)


def _concurrency_group(path: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^concurrency:\s*\n(?:^[ \t]*#.*\n)*^[ \t]+group:\s*([^\s#]+)",
        text,
    )
    assert match, f"{path}: missing top-level concurrency.group"
    return match.group(1)


def test_derived_writers_do_not_share_global_pending_slot():
    """Independent derived writers must not starve the publication pipeline.

    GitHub Actions concurrency permits one running and one pending run per
    group. A third run replaces the pending run, even when
    cancel-in-progress=false. These workflows read shared intelligence but
    write only their own derived namespaces, so putting them in the global
    sentinel-data-writer group can cancel them before their first job starts
    and can also displace sentinel-blogger while another writer is running.
    """
    for path, expected in ISOLATED_WRITERS.items():
        group = _concurrency_group(path)
        assert group == expected, f"{path}: expected {expected}, got {group}"
        assert group != "sentinel-data-writer"


def test_core_state_writers_remain_serialized():
    """R2/core-feed writers still require the global serialization lock."""
    for path in CORE_SERIALIZED_WRITERS:
        assert _concurrency_group(path) == "sentinel-data-writer"
