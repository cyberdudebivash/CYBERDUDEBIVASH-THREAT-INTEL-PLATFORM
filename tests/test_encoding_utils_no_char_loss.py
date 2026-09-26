"""
Ingest sanitising must never delete characters from clean text.

Production /api/v1/intel/latest.json (2026-09-26T08:55Z): "U.S. CISA adds
WordPressflaw to its Known Exploited Vulnerabilities catalog" -- Security
Affairs' RSS title has a no-break space (U+00A0) before "flaw". Without ftfy
(not installed in the pipeline), fix_encoding()'s fallback round trip used
errors='ignore' in both directions and deleted every non-ASCII character that
was not mojibake, whenever the result kept 80% of the length.
"""
import builtins
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from core.utils import encoding_utils as eu  # noqa: E402


@pytest.fixture
def no_ftfy(monkeypatch):
    """The pipeline's condition: ftfy is not installed."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "ftfy":
            raise ImportError("ftfy not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


@pytest.mark.parametrize("clean", [
    "U.S. CISA adds WordPress flaw to its Known Exploited Vulnerabilities catalog",
    "OpenAI’s AI Agents Tried Hacking 4 Websites Without Being Prompted",
    "Ransomware gang hits Zürich hospital, patient records stolen",
    "Café résumé naïve",
    "Thin space and narrow no-break space in a long advisory title",
    "plain ascii title",
])
def test_clean_text_is_unchanged(no_ftfy, clean):
    assert eu.sanitize_field(clean) == clean


@pytest.mark.parametrize("broken,fixed", [
    ("CafÃ© rÃ©sumÃ©", "Café résumé"),
    ("Microsoftâ€™s patch", "Microsoft’s patch"),
    ("ZÃ¼rich hospital hit by ransomware gang, data leaked", "Zürich hospital hit by ransomware gang, data leaked"),
])
def test_double_encoded_text_is_still_repaired(no_ftfy, broken, fixed):
    assert eu.sanitize_field(broken) == fixed


def test_non_strings_pass_through(no_ftfy):
    for value in (None, 7, True, ["x"]):
        assert eu.sanitize_field(value) == value
