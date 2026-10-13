"""Focused regression for internal advisory identity in immutable manifest dedup.

Run: python -m unittest discover -s tests -p 'test_manifest_advisory_identity.py'
This test isolates the function AST so no publisher side effects execute.
"""
import ast
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "generate_api_manifests.py"


def load_dedup():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {"_title_hash", "_content_hash", "deduplicate"}
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    if {f.name for f in functions} != names:
        raise AssertionError("Required manifest dedup functions are missing")
    namespace = {
        "BRAND_NOISE": set(),
        "warn": lambda message: None,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace["deduplicate"]


class AdvisoryIdentityRegression(unittest.TestCase):
    def setUp(self):
        self.dedup = load_dedup()

    def test_distinct_internal_ids_do_not_collapse_on_shared_legacy_stix_alias(self):
        records = [
            {"id": "intel--alpha", "stix_id": "intel--shared", "title": "Alpha advisory"},
            {"id": "intel--beta", "stix_id": "intel--shared", "title": "Beta advisory"},
        ]
        self.assertEqual([x["id"] for x in self.dedup(records)], ["intel--alpha", "intel--beta"])

    def test_duplicate_internal_id_is_dropped(self):
        records = [
            {"id": "intel--alpha", "title": "Alpha advisory"},
            {"id": "intel--alpha", "title": "Different headline"},
        ]
        self.assertEqual(len(self.dedup(records)), 1)

    def test_legacy_idless_records_still_deduplicate_by_stix_id(self):
        records = [
            {"stix_id": "indicator--legacy", "title": "Legacy advisory"},
            {"stix_id": "indicator--legacy", "title": "Another headline"},
        ]
        self.assertEqual(len(self.dedup(records)), 1)


if __name__ == "__main__":
    unittest.main()
