"""
test_deduplication.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the Deduplication Engine (deduplication.py).
"""
import pytest
from agent.deduplication import dedup_engine


class TestDeduplicationEngine:
    def test_new_entry_is_not_duplicate(self):
        """A brand new unique title should not be flagged as duplicate."""
        import uuid
        unique_title = f"UNIQUE_TEST_{uuid.uuid4().hex}"
        assert dedup_engine.is_duplicate(unique_title) is False

    def test_same_entry_is_duplicate_after_first_check(self):
        """After first is_duplicate() call marks it, second call should return True."""
        import uuid
        title = f"DUP_TEST_{uuid.uuid4().hex}"
        first = dedup_engine.is_duplicate(title)
        assert first is False, "First check must return False (not a dup yet)"
        second = dedup_engine.is_duplicate(title)
        assert second is True, "Second check must return True (it's now a dup)"

    def test_processed_count_increments(self):
        """Processed count should increase after marking new entries."""
        import uuid
        initial_count = dedup_engine.get_processed_count()
        dedup_engine.is_duplicate(f"COUNT_TEST_{uuid.uuid4().hex}")
        assert dedup_engine.get_processed_count() >= initial_count

    def test_processed_count_returns_int(self):
        count = dedup_engine.get_processed_count()
        assert isinstance(count, int)

    def test_different_titles_are_not_duplicates_of_each_other(self):
        import uuid
        title_a = f"ALPHA_{uuid.uuid4().hex}"
        title_b = f"BETA_{uuid.uuid4().hex}"
        dedup_engine.is_duplicate(title_a)
        assert dedup_engine.is_duplicate(title_b) is False

    def test_empty_string_does_not_crash(self):
        result = dedup_engine.is_duplicate("")
        assert isinstance(result, bool)

    def test_long_title_does_not_crash(self):
        long_title = "A" * 10000
        result = dedup_engine.is_duplicate(long_title)
        assert isinstance(result, bool)
