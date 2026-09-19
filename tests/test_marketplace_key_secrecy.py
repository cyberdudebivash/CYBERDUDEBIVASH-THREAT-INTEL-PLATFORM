"""
test_marketplace_key_secrecy.py — CYBERDUDEBIVASH SENTINEL APEX

SEC-2026-07-25 regression suite.

THE DEFECT THIS PINS
--------------------
agent/marketplace/marketplace_engine.py persisted every issued API key in
plaintext to data/marketplace/marketplace_state.json — as the keys of the
``api_keys`` map and again as ``subscriptions[tenant]["api_key"]`` — and that
file was committed to a PUBLIC repository holding 57 live-format credentials.

The .gitignore entry added for it at the time did not fix this: gitignore only
suppresses UNTRACKED files. The file was already tracked, so `git add -A` kept
staging it. That gap is the single most important thing here, because it is
invisible — the ignore rule *looks* like protection. TestSecretStateFilesAreNotTracked
asserts the property that actually matters (not tracked), not the one that
looks reassuring (listed in .gitignore).

The keys were never live: the production Worker authenticates only against
env.API_KEYS_KV and nothing ever synced this file there. These tests exist so
the next key written by this engine — which may not be test data — cannot reach
a public commit or a readable file.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from agent.marketplace.marketplace_engine import (  # noqa: E402
    ThreatIntelMarketplace,
    key_digest,
    mask_api_key,
)

# Files that hold credential-shaped material and must never be tracked. Both
# are named in .gitignore's SEC-2026-07-25 block; being listed there is not
# sufficient, which is the whole point of this suite.
# The marketplace engine mints live-format credentials on every
# create_subscription() and persists them here. It carries a .gitignore rule,
# so the only thing standing between it and a public commit is NOT being
# tracked.
UNTRACKABLE_STATE_FILES = ("data/marketplace/marketplace_state.json",)

# A live-format issued key: cdb_<tier>_<token_urlsafe(32)>, which is >=43 chars.
LIVE_KEY_PATTERN = r"cdb_(free|pro|ent|mssp)_[A-Za-z0-9_-]{32,}"

PLAINTEXT_PREFIX = "cdb_"


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(REPO), capture_output=True, text=True, timeout=120,
    )


class TestSecretStateFilesAreNotTracked:
    """gitignore is not protection for a file git is already tracking.

    This is the subtle half of the incident. `data/marketplace/marketplace_state.json`
    was listed in .gitignore AND still committed on every `git add -A`, because
    gitignore only suppresses untracked paths. Asserting "it is in .gitignore"
    would have passed throughout the entire exposure — so these assert the
    property that actually protects the file.
    """

    @pytest.mark.parametrize("path", UNTRACKABLE_STATE_FILES)
    def test_secret_state_file_is_not_tracked_by_git(self, path):
        assert _git("ls-files", "--error-unmatch", path).returncode != 0, (
            f"{path} is TRACKED by git. It holds credential-shaped material and is "
            f"listed in .gitignore, but gitignore only suppresses UNTRACKED files — "
            f"every `git add -A` will keep committing it. Fix: git rm --cached {path}"
        )

    @pytest.mark.parametrize("path", UNTRACKABLE_STATE_FILES)
    def test_secret_state_file_has_an_ignore_rule(self, path):
        # --no-index is required: `git check-ignore` stays SILENT on tracked
        # paths, so without it this reports "no rule" for exactly the files in
        # the broken state, which is backwards.
        result = _git("check-ignore", "--no-index", path)
        assert result.returncode == 0, (
            f"{path} is matched by no .gitignore rule; once untracked, a routine "
            f"`git add -A` could commit it again."
        )

    def test_no_tracked_file_contains_a_plaintext_api_key(self):
        """The durable invariant, independent of any one file's name.

        Catches a leak through a path nobody thought to list — which is how
        marketplace_state.json survived a gitignore entry written specifically
        for it.
        """
        result = _git("grep", "-I", "-n", "-E", LIVE_KEY_PATTERN, "--", ".")
        # `git grep` exits 1 with no output when there are no matches.
        hits = [ln for ln in result.stdout.splitlines() if ln.strip()]
        assert not hits, (
            "plaintext live-format API key(s) found in tracked files:\n  "
            + "\n  ".join(hits[:10])
        )

    def test_marketplace_state_on_disk_holds_no_plaintext_key(self):
        """The working copy itself must not carry a usable credential."""
        state_file = REPO / "data" / "marketplace" / "marketplace_state.json"
        if not state_file.exists():
            pytest.skip("no local marketplace state (expected on a fresh clone)")
        state = json.loads(state_file.read_text(encoding="utf-8"))

        plaintext = [k for k in state.get("api_keys", {}) if k.startswith(PLAINTEXT_PREFIX)]
        assert not plaintext, (
            f"{len(plaintext)} plaintext API key(s) in the api_keys map; "
            f"only sha256: digests may be persisted"
        )
        leaked_subs = [
            t for t, sub in state.get("subscriptions", {}).items()
            if isinstance(sub, dict) and isinstance(sub.get("api_key"), str)
            and sub["api_key"].startswith(PLAINTEXT_PREFIX)
        ]
        assert not leaked_subs, (
            f"subscriptions still hold a plaintext api_key: {leaked_subs[:3]} — "
            f"this was the second, easily-missed location of the leak"
        )


class TestEngineNeverPersistsPlaintext:
    @pytest.fixture
    def engine(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CDB_DATA_DIR", str(tmp_path))
        import agent.marketplace.marketplace_engine as mod
        monkeypatch.setattr(mod, "DATA_DIR", str(tmp_path))
        return ThreatIntelMarketplace(), tmp_path / "marketplace_state.json"

    def test_issued_key_is_returned_to_the_caller(self, engine):
        market, _ = engine
        result = market.create_subscription("acme-001", "pro", "ops@acme.example")
        assert result["api_key"].startswith("cdb_pro_")
        # Preserved for callers that read the key off the subscription dict.
        assert result["subscription"]["api_key"] == result["api_key"]

    def test_issued_key_never_reaches_disk(self, engine):
        market, state_file = engine
        api_key = market.create_subscription("acme-001", "pro")["api_key"]
        raw = state_file.read_text(encoding="utf-8")
        assert api_key not in raw, "plaintext API key was written to the state file"
        assert key_digest(api_key) in json.loads(raw)["api_keys"]

    def test_issued_key_still_authenticates(self, engine):
        market, _ = engine
        api_key = market.create_subscription("acme-001", "enterprise")["api_key"]
        result = market.validate_api_key(api_key)
        assert result["valid"] is True
        assert result["tenant_id"] == "acme-001"
        assert result["tier"] == "enterprise"

    def test_unknown_key_is_rejected(self, engine):
        market, _ = engine
        market.create_subscription("acme-001", "pro")
        assert market.validate_api_key("cdb_pro_not-a-real-key")["valid"] is False

    def test_digest_alone_cannot_authenticate(self, engine):
        """A leaked state file must not be replayable as a credential."""
        market, _ = engine
        api_key = market.create_subscription("acme-001", "pro")["api_key"]
        assert market.validate_api_key(key_digest(api_key))["valid"] is False

    def test_state_survives_reload(self, engine, tmp_path, monkeypatch):
        market, _ = engine
        api_key = market.create_subscription("acme-001", "pro")["api_key"]
        import agent.marketplace.marketplace_engine as mod
        monkeypatch.setattr(mod, "DATA_DIR", str(tmp_path))
        assert ThreatIntelMarketplace().validate_api_key(api_key)["valid"] is True

    def test_state_file_is_owner_only(self, engine):
        market, state_file = engine
        market.create_subscription("acme-001", "pro")
        assert oct(state_file.stat().st_mode & 0o777) == "0o600"

    def test_save_refuses_to_write_reintroduced_plaintext(self, engine):
        """Last line of defence if a future change re-adds a plaintext key."""
        market, state_file = engine
        market.create_subscription("acme-001", "pro")
        good = state_file.read_text(encoding="utf-8")

        market.api_keys["cdb_ent_reintroduced_plaintext_key"] = {
            "tenant_id": "bad", "tier": "enterprise",
            "access_level": 5, "usage_today": 0, "total_calls": 0,
        }
        market._save_state()
        assert state_file.read_text(encoding="utf-8") == good, (
            "state file was overwritten despite containing a plaintext key"
        )


class TestLegacyPlaintextMigration:
    """A pre-existing state file must be migrated without breaking its keys."""

    @pytest.fixture
    def legacy_state(self, tmp_path, monkeypatch):
        # Synthetic on purpose: a fixture must never re-commit a real key,
        # even an inert one, into the repository this incident was about.
        legacy_key = "cdb_ent_SYNTHETIC0FIXTURE0NOT0A0REAL0KEY0000000"
        (tmp_path / "marketplace_state.json").write_text(json.dumps({
            "api_keys": {
                legacy_key: {"tenant_id": "ent-test-001", "tier": "enterprise",
                             "access_level": 5, "usage_today": 0, "total_calls": 0},
            },
            "subscriptions": {
                "ent-test-001": {"tenant_id": "ent-test-001", "tier": "enterprise",
                                 "email": "ent@test.com", "api_key": legacy_key,
                                 "access_level": 5, "rate_limit": 50000,
                                 "features": [], "usage_today": 0,
                                 "total_calls": 0, "status": "ACTIVE"},
            },
        }), encoding="utf-8")
        import agent.marketplace.marketplace_engine as mod
        monkeypatch.setattr(mod, "DATA_DIR", str(tmp_path))
        return legacy_key, tmp_path / "marketplace_state.json"

    def test_migration_removes_all_plaintext(self, legacy_state):
        legacy_key, state_file = legacy_state
        ThreatIntelMarketplace()
        raw = state_file.read_text(encoding="utf-8")
        assert legacy_key not in raw
        assert key_digest(legacy_key) in json.loads(raw)["api_keys"]

    def test_migration_clears_the_subscription_copy_too(self, legacy_state):
        _, state_file = legacy_state
        ThreatIntelMarketplace()
        sub = json.loads(state_file.read_text(encoding="utf-8"))["subscriptions"]["ent-test-001"]
        assert "api_key" not in sub
        assert sub["api_key_digest"].startswith("sha256:")
        assert sub["api_key_hint"].startswith("cdb_ent_...")

    def test_already_issued_key_keeps_working_after_migration(self, legacy_state):
        """Migration must not silently revoke keys already handed to tenants."""
        legacy_key, _ = legacy_state
        result = ThreatIntelMarketplace().validate_api_key(legacy_key)
        assert result["valid"] is True
        assert result["tenant_id"] == "ent-test-001"

    def test_migration_is_idempotent(self, legacy_state):
        legacy_key, state_file = legacy_state
        ThreatIntelMarketplace()
        first = state_file.read_text(encoding="utf-8")
        ThreatIntelMarketplace()
        assert state_file.read_text(encoding="utf-8") == first
        assert ThreatIntelMarketplace().validate_api_key(legacy_key)["valid"] is True


class TestMaskingHelpers:
    @pytest.mark.parametrize("key,expected", [
        ("cdb_pro_abcdefghijklmnop", "cdb_pro_...mnop"),
        ("cdb_ent_ZZZZ1234", "cdb_ent_...1234"),
        ("", ""),
    ])
    def test_mask_keeps_prefix_and_last_four(self, key, expected):
        assert mask_api_key(key) == expected

    def test_mask_output_is_not_a_usable_key(self):
        key = "cdb_pro_" + "x" * 43
        assert key_digest(mask_api_key(key)) != key_digest(key)

    def test_digest_is_stable_and_distinct(self):
        assert key_digest("cdb_pro_a") == key_digest("cdb_pro_a")
        assert key_digest("cdb_pro_a") != key_digest("cdb_pro_b")
        assert key_digest("cdb_pro_a").startswith("sha256:")
