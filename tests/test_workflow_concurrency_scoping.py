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
    ".github/workflows/detection-engine.yml",
    ".github/workflows/report-engine.yml",
    ".github/workflows/r2-data-sync.yml",
    ".github/workflows/weekly-threat-brief.yml",
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


def _writer_queue_config(path: str) -> dict[str, str]:
    """Only top-level workflow concurrency can serialize all jobs of a writer."""
    source = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^concurrency:\s*\n((?:^[ \t]+[^\n]*\n)+)",
        source,
    )
    assert match, f"{path}: missing workflow-level concurrency settings"
    result = dict(re.findall(
        r"(?m)^  (group|queue|cancel-in-progress):\s*([^\s#]+)",
        match.group(1),
    ))
    return result


def test_shared_core_writers_preserve_pending_queue_without_parallel_writes():
    """The shared serialized writers must keep their backlog across collisions.

    GitHub Actions' default single pending slot cancels older pending runs even
    when cancel-in-progress is false. queue: max retains pending writers, while
    the unchanged group still permits only one writer to run at a time.
    """
    expected = {
        "group": "sentinel-data-writer",
        "queue": "max",
        "cancel-in-progress": "false",
    }
    for path in CORE_SERIALIZED_WRITERS:
        assert _writer_queue_config(path) == expected, path


def test_all_shared_writer_group_members_have_the_same_queue_policy():
    """A newly introduced shared writer must not silently reset queue policy."""
    found = set()
    workflow_root = ROOT / ".github" / "workflows"
    for workflow in workflow_root.glob("*.yml"):
        path = str(workflow.relative_to(ROOT)).replace("\\", "/")
        config = _writer_queue_config(path) if re.search(
            r"(?m)^concurrency:\s*\n",
            workflow.read_text(encoding="utf-8"),
        ) else {}
        if config.get("group") == "sentinel-data-writer":
            found.add(path)
            assert config["queue"] == "max", path
            assert config["cancel-in-progress"] == "false", path
    assert found == set(CORE_SERIALIZED_WRITERS), (found, set(CORE_SERIALIZED_WRITERS))
