"""Report archive floor (F13, docs/CUSTOMER_RELEASE_LEDGER.md).

scripts/report_archive_manager.py refuses to untrack reports when the HOT
tier would fall below ARCHIVE_MIN_REPORTS. From the first publisher run of
October (sentinel-blogger run 36815948964, 2026-10-01T05:18:57Z) that refusal
fired on every run: classification is by (year, month), so the whole of
August turned ARCHIVE at the month boundary (HOT 22, ARCHIVE 22,433), and
the R2-first publisher now commits only a handful of reports a month. The
refusal returned 1, STAGE 5.4.5b failed the job, and every later step left
on the default success() condition was skipped: post-deploy smoke tests,
deployment canary, report URL canary, production release gates. The deploy
steps carry `!cancelled()` and still ran, unvalidated.

Contract: at the floor nothing is untracked, a ::warning:: annotation says
so, and the exit code is 0. Archiving above the floor and the hard stop on
a git error are unchanged. Temporary git repositories only; no network.
"""
import importlib.util
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "report_archive_manager.py"


def _clock(at):
    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(*at, tzinfo=timezone.utc)
    return Fixed


def _load(monkeypatch, repo, now, min_reports=500):
    spec = importlib.util.spec_from_file_location("report_archive_manager_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    archive_dir = repo / "data" / "archive"
    monkeypatch.setattr(mod, "REPO_ROOT", repo)
    monkeypatch.setattr(mod, "REPORTS_DIR", repo / "reports")
    monkeypatch.setattr(mod, "ARCHIVE_DIR", archive_dir)
    monkeypatch.setattr(mod, "AUDIT_LOG_PATH", archive_dir / "report_archive_audit.jsonl")
    monkeypatch.setattr(mod, "ARCHIVE_MANIFEST", archive_dir / "report_archive_manifest.json")
    monkeypatch.setattr(mod, "WORKFLOW_PATH", repo / ".github" / "workflows" / "sentinel-apex.yml")
    monkeypatch.setattr(mod, "MIN_REPORT_THRESHOLD", min_reports)
    monkeypatch.setattr(mod, "datetime", _clock(now))
    return mod


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def _repo(tmp_path, months):
    repo = tmp_path / "repo"
    for ym, count in months.items():
        folder = repo / "reports" / ym
        folder.mkdir(parents=True)
        for i in range(count):
            (folder / f"intel--{i:04d}.html").write_text("<html></html>", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=ci@example.com", "-c", "user.name=ci", "-c", "commit.gpgsign=false",
         "commit", "-qm", "seed")
    return repo


def _tracked(repo):
    return [p for p in _git(repo, "ls-files", "reports/").splitlines() if p.endswith(".html")]


# The incident: 2026-10-01, 30-day window (the repository variable), floor 500.
INCIDENT_NOW = (2026, 10, 1, 5, 18, 57)


def test_reproduction_month_boundary_floor_is_not_a_job_failure(tmp_path, monkeypatch, capsys):
    repo = _repo(tmp_path, {"2026/08": 600, "2026/09": 22})
    mod = _load(monkeypatch, repo, INCIDENT_NOW)
    rc = mod.run_archive(retention_days=30, dry_run=False)
    out = capsys.readouterr().out
    assert rc == 0, "the floor refused to archive and the step failed the publisher job"
    assert len(_tracked(repo)) == 622, "nothing may be untracked at the floor"
    assert "::warning" in out and "nothing untracked" in out, "the skip must stay visible in the run summary"


def test_dry_run_at_the_floor_is_not_a_failure_either(tmp_path, monkeypatch, capsys):
    repo = _repo(tmp_path, {"2026/08": 600, "2026/09": 22})
    mod = _load(monkeypatch, repo, INCIDENT_NOW)
    assert mod.run_archive(retention_days=30, dry_run=True) == 0
    assert len(_tracked(repo)) == 622
    assert "::warning" in capsys.readouterr().out


def test_control_the_day_before_archives_above_the_floor_as_before(tmp_path, monkeypatch):
    # 2026-09-30: cutoff 2026-08-31, so August and September are HOT and
    # July is archived, exactly as the green run 36774798831 did.
    repo = _repo(tmp_path, {"2026/07": 50, "2026/08": 600, "2026/09": 22})
    mod = _load(monkeypatch, repo, (2026, 9, 30, 21, 49, 8))
    assert mod.run_archive(retention_days=30, dry_run=False) == 0
    tracked = _tracked(repo)
    assert len(tracked) == 622 and not any(p.startswith("reports/2026/07/") for p in tracked)
    assert (repo / "reports" / "2026" / "07" / "intel--0000.html").exists(), "files stay on disk"


def test_control_a_git_error_is_still_a_hard_stop(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"2026/07": 50, "2026/08": 600, "2026/09": 22})
    mod = _load(monkeypatch, repo, (2026, 9, 30, 21, 49, 8))
    monkeypatch.setattr(mod, "_git_rm_cached", lambda paths, batch_size=500: False)
    assert mod.run_archive(retention_days=30, dry_run=False) == 1
