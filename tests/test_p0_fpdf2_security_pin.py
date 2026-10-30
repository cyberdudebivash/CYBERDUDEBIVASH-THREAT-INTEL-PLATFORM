"""P0: reject vulnerable fpdf2 pins in both runtime and lightweight CI manifests.

Offline contract for GHSA-wqw6-wpr3-45rh and GHSA-rw7v-4hrq-x6r9.
The upstream fixed release is 2.8.8; this test does not replace pip-audit.
"""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ("requirements.txt", "requirements-ci-light.txt")
MIN_SAFE = (2, 8, 8)
PIN = re.compile(r"^\s*fpdf2\s*==\s*(\d+)\.(\d+)\.(\d+)\s*(?:#.*)?$", re.I)


def parse_fpdf2_pin(text: str) -> tuple[int, int, int]:
    declarations = [line for line in text.splitlines()
                    if re.match(r"^\s*fpdf2\b", line, re.I)]
    if len(declarations) != 1:
        raise ValueError("fpdf2 must have exactly one explicit pin")
    match = PIN.fullmatch(declarations[0])
    if not match:
        raise ValueError("fpdf2 must use an exact three-component version pin")
    version = tuple(int(part) for part in match.groups())
    if version < MIN_SAFE:
        raise ValueError("fpdf2 pin precedes security fix 2.8.8")
    return version


def test_both_production_manifests_pin_the_same_fixed_fpdf2():
    versions = [parse_fpdf2_pin((ROOT / name).read_text(encoding="utf-8"))
                for name in MANIFESTS]
    assert versions == [MIN_SAFE, MIN_SAFE]


@pytest.mark.parametrize("bad", [
    "fpdf2==2.7.7", "fpdf2==2.8.7", "fpdf2>=2.8.8", "fpdf2",
    "fpdf2==2.8.8\nfpdf2==2.8.8", "", "fpdf2==2.8.8rc1",
])
def test_vulnerable_ambiguous_or_duplicate_pins_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_fpdf2_pin(bad)


def test_fixed_release_with_comment_is_accepted():
    assert parse_fpdf2_pin("fpdf2==2.8.8 # patched SVG/HTML resource handling") == MIN_SAFE
