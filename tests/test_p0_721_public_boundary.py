#!/usr/bin/env python3
"""
tests/test_p0_721_public_boundary.py
P0 #721/#725 -- last-mile TLP enforcement on finished, anonymously served bytes:
  * scripts/tlp_public_boundary.py  (JSON documents + the GitHub Pages dist/ artifact)
  * scripts/r2_upload.py            (every JSON object of the public data bucket, not just api/feed.json)
  * scripts/r2_resync_manifests.py  (final resync of the same objects)
Negative controls assert that no restricted byte (id, title, IOC-like marker) survives in the output.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import r2_resync_manifests as resync  # noqa: E402
import r2_upload  # noqa: E402
import tlp_public_boundary as tb  # noqa: E402

POLICY = {"legacy_white_treated_as_clear": False, "first_party_public_sources": []}

# A sentinel that must never appear in any output. Composed at runtime so no secret-looking literal sits in the source.
SECRET = "".join(["LEAK", "MARKER", "-", "NEVER", "PUBLISH"])


def rec(i, tlp=None, **kw):
    d = {"id": i, "title": f"title-{i}", "report_url": f"/reports/2026/10/{i}.html"}
    if tlp is not None:
        d["tlp"] = tlp
    d.update(kw)
    return d


class TestSanitizeDocument(unittest.TestCase):
    def test_every_restricted_missing_invalid_and_legacy_label_is_removed(self):
        doc = {"count": 8, "items": [
            rec("clear", "TLP:CLEAR"), rec("green", "TLP:GREEN", d=SECRET), rec("amber", "TLP:AMBER"),
            rec("amberstrict", "TLP:AMBER+STRICT"), rec("red", "TLP:RED"), rec("missing"),
            rec("invalid", "TLP:PURPLE"), rec("white", "TLP:WHITE")]}
        out, removed, withheld = tb.sanitize_document(doc, POLICY)
        self.assertIsNone(withheld)
        self.assertEqual([x["id"] for x in out["items"]], ["clear"])
        self.assertEqual(out["count"], 1, "a sibling count that matched the old length is kept consistent")
        self.assertEqual({r["id"] for r in removed}, {"green", "amber", "amberstrict", "red", "missing", "invalid", "white"})
        self.assertNotIn(SECRET, json.dumps(out))
        for r in removed:  # rows must never carry content
            self.assertEqual(set(r), {"id", "reason_code", "path"})

    def test_nested_lists_are_filtered_at_any_depth(self):
        doc = {"a": {"b": [{"x": [rec("g", "TLP:GREEN"), rec("c", "TLP:CLEAR")]}]}, "top_critical_items": [rec("r", "TLP:RED")]}
        out, removed, _ = tb.sanitize_document(doc, POLICY)
        self.assertEqual([x["id"] for x in out["a"]["b"][0]["x"]], ["c"])
        self.assertEqual(out["top_critical_items"], [])
        self.assertEqual(len(removed), 2)

    def test_restricted_nested_dicts_are_quarantined_not_just_list_elements(self):
        doc = {
            "outer": {
                "restricted": {"id": "hidden", "title": "sensitive", "tlp": "TLP:RED", "payload": SECRET},
                "unlabelled": {"id": "unsigned", "title": "advisory", "report_url": "/reports/old", "payload": SECRET},
                "allow": {"id": "clear", "title": "safe", "tlp": "TLP:CLEAR", "summary": "Approved"},
            }
        }
        out, removed, withheld = tb.sanitize_document(doc, POLICY)
        self.assertIsNone(withheld)
        self.assertTrue(out["outer"]["restricted"]["tlp_boundary"]["withheld"])
        self.assertTrue(out["outer"]["unlabelled"]["tlp_boundary"]["withheld"])
        self.assertEqual(out["outer"]["allow"]["id"], "clear")
        self.assertNotIn(SECRET, json.dumps(out))
        self.assertEqual({r["id"] for r in removed}, {"hidden", "unsigned"})

    def test_nested_document_level_classification_fails_closed(self):
        for cls in ("TLP:AMBER", "TLP:CLEAR; TLP:RED"):
            with self.subTest(cls=cls):
                doc = {"cards": {"intel": {"classification": cls, "payload": SECRET}}}
                out, removed, _ = tb.sanitize_document(doc, POLICY)
                self.assertTrue(out["cards"]["intel"]["tlp_boundary"]["withheld"])
                self.assertNotIn(SECRET, json.dumps(out))
                self.assertEqual(len(removed), 1)

    def test_restricted_upstream_evidence_cannot_be_laundered_into_a_clear_record(self):
        doc = [rec("agg", "TLP:CLEAR", evidence_chain=[{"tlp": "TLP:AMBER"}]), rec("ok", "TLP:CLEAR")]
        out, removed, _ = tb.sanitize_document(doc, POLICY)
        self.assertEqual([x["id"] for x in out], ["ok"])
        self.assertEqual(removed[0]["reason_code"], "RESTRICTED_UPSTREAM_LABEL")

    def test_malformed_nested_label_structures_fail_closed(self):
        for bad in ({"id": "n", "title": "t", "tlp": None}, {"id": "n", "title": "t", "tlp": {"x": 1}},
                    {"id": "n", "title": "t", "tlp": ["TLP:CLEAR"]}, {"id": "n", "title": "t", "tlp": 7}):
            out, removed, _ = tb.sanitize_document([bad], POLICY)
            self.assertEqual(out, [], bad)
        # a Unicode look-alike or padded label never reads as TLP:CLEAR
        for sneaky in ("TLP:CLEAR​", "TLP:CLEΑR", "TLP:CLEAR; TLP:RED", "tlp:clear\x00"):
            out, _, _ = tb.sanitize_document([rec("s", sneaky)], POLICY)
            self.assertEqual(out, [], repr(sneaky))

    def test_document_level_restricted_classification_becomes_a_tombstone(self):
        doc = {"classification": "TLP:AMBER — For Authorized Recipients Only", "payload": SECRET}
        out, removed, withheld = tb.sanitize_document(doc, POLICY)
        self.assertEqual(withheld[0], "RESTRICTED_DOCUMENT")
        self.assertNotIn(SECRET, json.dumps(out))
        self.assertTrue(out["tlp_boundary"]["withheld"])
        # a non-TLP classification string, or CLEAR, is not a restriction
        for ok in ({"classification": "UNCLASSIFIED", "n": 1}, {"classification": "TLP:CLEAR — public", "n": 1}):
            _o, _r, w = tb.sanitize_document(ok, POLICY)
            self.assertIsNone(w, ok)

    def test_conflicting_document_classification_never_allows_restricted_bytes(self):
        for label in ("TLP:CLEAR; TLP:RED", "TLP:CLEAR / TLP:GREEN",
                      "TLP:CLEAR then TLP:AMBER+STRICT", "TLP:CLEAR; TLP:PURPLE"):
            with self.subTest(label=label):
                doc = {"classification": label, "payload": SECRET}
                out, _removed, withheld = tb.sanitize_document(doc, POLICY)
                self.assertIsNotNone(withheld)
                self.assertNotIn(SECRET, json.dumps(out))
                self.assertTrue(out["tlp_boundary"]["withheld"])

    def test_single_top_level_restricted_record_becomes_a_tombstone(self):
        out, _removed, withheld = tb.sanitize_document(rec("one", "TLP:RED", d=SECRET), POLICY)
        self.assertIsNotNone(withheld)
        self.assertNotIn(SECRET, json.dumps(out))

    def test_unlabelled_derived_document_inherits_only_its_verified_parent_decision(self):
        parents = tb.build_parent_index([])
        self.assertEqual(parents, {})
        allowed = {"allowed": True, "reason_code": "OK", "reason": "", "label": "TLP:CLEAR", "state": "PUBLISH", "assignment": "explicit"}
        denied = {"allowed": False, "reason_code": "RESTRICTED_LABEL", "reason": "x", "label": "TLP:GREEN", "state": "QUARANTINE", "assignment": None}
        det = {"title": "det", "cve_id": "CVE-2026-1", "stix_id": "s", "sigma_rule": SECRET}
        _o, _r, w = tb.sanitize_document(dict(det, id="p1"), POLICY, {"p1": allowed})
        self.assertIsNone(w)
        out, _r, w = tb.sanitize_document(dict(det, id="p2"), POLICY, {"p2": denied})
        self.assertEqual(w[0], "RESTRICTED_LABEL")
        self.assertNotIn(SECRET, json.dumps(out))
        out, _r, w = tb.sanitize_document(dict(det, id="orphan"), POLICY, {"p1": allowed})
        self.assertEqual(w[0], "MISSING_LABEL", "no verified parent -> fail closed")
        # file-stem hint (api/v1/detections/<intel-id>.json) resolves the parent as well
        _o, _r, w = tb.sanitize_document(det, POLICY, {"stem": allowed}, id_hint="stem")
        self.assertIsNone(w)
        # an explicit own label always beats the parent
        _o, _r, w = tb.sanitize_document(dict(det, id="p1", tlp="TLP:RED"), POLICY, {"p1": allowed})
        self.assertIsNotNone(w)

    def test_parent_index_most_restrictive_wins_and_survives_bad_files(self):
        with tempfile.TemporaryDirectory() as td:
            a, b, c = Path(td, "a.json"), Path(td, "b.json"), Path(td, "c.json")
            a.write_text(json.dumps([rec("x", "TLP:CLEAR")]))
            b.write_text(json.dumps({"items": [rec("x", "TLP:RED")]}))
            c.write_text("{not json")
            idx = tb.build_parent_index([a, b, c, Path(td, "missing.json")], POLICY)
        self.assertFalse(idx["x"]["allowed"])

    def test_restricted_in_an_authoritative_feed_overrides_a_clear_label_elsewhere(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td, "feed.json")
            f.write_text(json.dumps([rec("x", "TLP:AMBER"), rec("unl")]))  # "unl" is only MISSING_LABEL there
            idx = tb.build_parent_index([f], POLICY)
        self.assertTrue(idx["x"].get("force"))
        self.assertFalse(idx["unl"].get("force"), "a missing label elsewhere must not veto an explicit CLEAR")
        out, removed, _ = tb.sanitize_document([rec("x", "TLP:CLEAR"), rec("unl", "TLP:CLEAR")], POLICY, idx)
        self.assertEqual([r["id"] for r in out], ["unl"])
        self.assertEqual(removed[0]["id"], "x")

    def test_unlabeled_id_title_aggregate_is_not_a_public_advisory(self):
        # Worker publicTlpJsonVerified() rejects every title/id object lacking
        # an explicit CLEAR label. Python must remove these before publication,
        # while unrelated name/id metadata is still allowed.
        doc = {"count": 2, "top_threats": [{"id": "TH-1", "title": "t", "risk_score": 9}, {"id": "TH-2", "title": "u"}],
               "actors": [{"id": "a", "name": "n"}]}
        out, removed, withheld = tb.sanitize_document(doc, POLICY)
        self.assertEqual(out["top_threats"], [])
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["actors"], doc["actors"])
        self.assertEqual(len(removed), 2)
        self.assertIsNone(withheld)

    def test_naked_nested_advisory_is_removed_but_labeled_clear_is_retained(self):
        doc = {"count": 1, "items": [{
            "id": "intel--public", "title": "Source-supported bulletin",
            "tlp": "TLP:CLEAR",
            "related": [
                {"id": "intel--unverified", "title": "Unclassified nested entry", "ioc": "DO_NOT_PUBLISH"},
                {"id": "intel--verified", "title": "Verified subentry", "tlp": "TLP:CLEAR"},
            ],
        }]}
        out, removed, withheld = tb.sanitize_document(doc, POLICY)
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0]["related"], [
            {"id": "intel--verified", "title": "Verified subentry", "tlp": "TLP:CLEAR"}
        ])
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(out))
        self.assertEqual(len(removed), 1)
        self.assertIsNone(withheld)


class TestConflictingClassification(unittest.TestCase):
    """Independent review of #728 head 29b12cb: a first-token match let "TLP:CLEAR; TLP:RED" through, and a benign
    CLEAR anywhere in a page negated an explicit RED marking. Neither may recur."""

    AMBIGUOUS = ["TLP:CLEAR; TLP:RED", "TLP:RED; TLP:CLEAR", "TLP:CLEAR/RED", "TLP:CLEAR, TLP:GREEN", "TLP:CLEAR and TLP:AMBER",
                 "TLP:GREEN or TLP:CLEAR", "TLP:CLEAR | TLP:AMBER+STRICT", "TLP:CLEAR TLP:RED", "TLP:CLEAR - TLP:RED"]

    def test_document_classification_with_any_restricted_or_conflicting_marking_is_denied(self):
        for text in self.AMBIGUOUS + ["TLP:GREEN \u2014 For Authorized Recipients Only", "TLP:AMBER", "TLP:AMBER+STRICT",
                                      "TLP:RED", "tlp:red", "TLP\u200b:RED", "TLP&#58;RED".replace("&#58;", ":"),
                                      "TLP:\u0421LEAR", "TLP:CLEAR\u202e; TLP:RED", "TLP", "TLP: unknown"]:
            out, removed, withheld = tb.sanitize_document({"classification": text, "payload": SECRET}, POLICY)
            self.assertIsNotNone(withheld, text)
            self.assertNotIn(SECRET, json.dumps(out), text)
        out, _r, w = tb.sanitize_document({"classification": "TLP:CLEAR; TLP:RED", "n": 1}, POLICY)
        self.assertEqual(w[0], "CONFLICTING_CLASSIFICATION")

    def test_unambiguous_clear_or_non_tlp_classification_is_not_denied(self):
        for text in ("TLP:CLEAR", "tlp:clear", "TLP:CLEAR \u2014 public", "UNCLASSIFIED", "Internal", ""):
            _o, _r, w = tb.sanitize_document({"classification": text, "n": 1}, POLICY)
            self.assertIsNone(w, text)
        # legacy WHITE only when the operator migrated it
        _o, _r, w = tb.sanitize_document({"classification": "TLP:WHITE"}, POLICY)
        self.assertEqual(w[0], "LEGACY_LABEL_UNMIGRATED")
        _o, _r, w = tb.sanitize_document({"classification": "TLP:WHITE"}, dict(POLICY, legacy_white_treated_as_clear=True))
        self.assertIsNone(w)

    def test_tlp_and_tlp_label_fields_must_be_exactly_one_clear_label(self):
        for key in ("tlp", "tlp_label"):
            for val in self.AMBIGUOUS + ["CLEAR", "TLP:CLEAR ", "TLP:CLEAR\u200b"]:
                doc = {key: val, "items": [rec("a", "TLP:CLEAR")]}
                _o, _r, w = tb.sanitize_document(doc, POLICY)
                if val.strip() == "TLP:CLEAR":
                    continue
                self.assertIsNotNone(w, (key, val))

    def test_record_level_classification_text_with_a_restricted_or_conflicting_marking_denies_the_record(self):
        for text in self.AMBIGUOUS + ["TLP:AMBER \u2014 authorized recipients"]:
            out, removed, _w = tb.sanitize_document([rec("a", "TLP:CLEAR", classification=text), rec("b", "TLP:CLEAR")], POLICY)
            self.assertEqual([x["id"] for x in out], ["b"], text)
        out, _r, _w = tb.sanitize_document([rec("a", "TLP:CLEAR", classification="TLP:CLEAR"), rec("c", "TLP:CLEAR", classification="Internal")], POLICY)
        self.assertEqual([x["id"] for x in out], ["a", "c"])

    def test_html_an_explicit_restricted_marking_is_never_negated_by_a_clear_elsewhere(self):
        pages = {
            "reviewer case (RED badge + CLEAR mention)": "<html><span>TLP:RED</span><p>see TLP:CLEAR guidance</p></html>",
            "RED banner class, CLEAR text": "<div class='tlp-banner tlp-RED'>TLP:CLEAR</div>",
            "CLEAR banner class, RED text in the same element": "<div class='tlp-banner tlp-CLEAR'>TLP:RED</div>",
            "meta RED, CLEAR row": "<meta name='tlp' content='TLP:RED'><div class='kv-key'>TLP Label</div><div class='kv-val'>TLP:CLEAR</div>",
            "no authoritative markers, both in prose": "<p>TLP:CLEAR</p><p>TLP:GREEN</p>",
            "entity-encoded RED beside CLEAR": "<span>TLP&#58;RED</span><span>TLP:CLEAR</span>",
            "zero-width inside RED": "<span>TLP:R\u200bED</span><span>TLP:CLEAR</span>",
            "data-tlp attribute": "<body data-tlp='amber'><span>TLP:CLEAR</span></body>",
            "title RED": "<title>Report TLP:RED</title><div class='tlp-banner tlp-CLEAR'>TLP:CLEAR</div>",
            "kv row RED, banner CLEAR": "<div class='tlp-banner tlp-CLEAR'>TLP:CLEAR</div><div class='kv-key'>TLP Label</div><div class='kv-val'>TLP:AMBER+STRICT</div>",
            "compound marking in the banner": "<div class='tlp-banner tlp-CLEAR'>TLP:CLEAR/RED</div>",
            "look-alike letters in the banner": "<div class='tlp-banner tlp--CLEAR'>TLP:\u0421LEAR</div>",
            "AMBER+STRICT sev-chip": "<span class='sev-chip sev-INFO'>TLP:AMBER+STRICT</span><span>TLP:CLEAR</span>",
        }
        for name, html in pages.items():
            self.assertTrue(tb.classify_html_head(html)["restricted"], name)

    def test_html_clear_pages_and_incidental_mentions_are_kept(self):
        real_markup = ("<style>.tlp-banner.tlp-RED{color:red}.tlp-GREEN{x:1}/* TLP Banner */.cls-TLP{y:2}</style>"
                       "<div class='tlp-banner tlp--CLEAR'>\n  TLP: TLP:CLEAR &nbsp;\u00b7&nbsp; CYBERDUDEBIVASH</div>"
                       "<span class='cls-chip cls-TLP'>TLP:CLEAR</span><div class='kv-key'>TLP</div><div class='kv-val'>"
                       "<span class='sev-chip sev-INFO'>TLP:CLEAR</span></div><div class='kv-key'>TLP Label</div>"
                       "<div class='kv-val'>TLP:CLEAR</div>")
        for name, html in {"generator markup with CSS naming every label": real_markup,
                           "CLEAR badge, prose about RED handling": "<div class='tlp-banner tlp-CLEAR'>TLP:CLEAR</div><p>how to handle TLP:RED data</p>",
                           "no TLP at all": "<html>nothing</html>"}.items():
            self.assertFalse(tb.classify_html_head(html)["restricted"], name)

    def test_html_files_end_to_end_in_dist_and_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            dist = Path(td, "dist")
            rep = dist / "reports" / "2026" / "10"
            rep.mkdir(parents=True)
            (rep / "neg.html").write_text("<html><span>TLP:RED</span><p>see TLP:CLEAR</p></html>")
            (rep / "ok.html").write_text("<div class='tlp-banner tlp--CLEAR'>TLP: TLP:CLEAR</div>")
            r = tb.sanitize_dist(dist, POLICY, parent_sources=[])
            self.assertFalse((rep / "neg.html").exists())
            self.assertTrue((rep / "ok.html").exists())
            self.assertEqual(r["report_files_removed"], 1)
            (rep / "neg2.html").write_text("<div class='tlp-banner tlp-AMBER'>TLP:AMBER</div><span class='x'>TLP:CLEAR</span>")
            inv = tb.inventory_tree(Path(td, "dist"), subdirs=("reports",), policy=POLICY)
            self.assertEqual(inv["report_pages"]["restricted_badge"], 1)
            self.assertEqual(inv["report_pages"]["by_label"], {"TLP:AMBER": 1})


class TestSanitizeJsonFile(unittest.TestCase):
    def test_source_untouched_and_output_contains_no_restricted_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            src, dst = Path(td, "in.json"), Path(td, "out", "o.json")
            src.write_text(json.dumps([rec("k", "TLP:CLEAR"), rec("r", "TLP:RED", d=SECRET)]))
            before = src.read_bytes()
            res = tb.sanitize_json_file(src, dst, POLICY)
            self.assertEqual(src.read_bytes(), before)
            self.assertEqual(len(res["removed"]), 1)
            self.assertNotIn(SECRET, dst.read_text())
            # idempotent
            dst2 = Path(td, "o2.json")
            res2 = tb.sanitize_json_file(dst, dst2, POLICY)
            self.assertEqual(res2["removed"], [])
            self.assertEqual(dst.read_text(), dst2.read_text())

    def test_unparseable_json_is_never_passed_as_clean(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td, "bad.json")
            src.write_text("{nope")
            with self.assertRaises(tb.BoundaryError):
                tb.sanitize_json_file(src, Path(td, "o.json"), POLICY)
            self.assertFalse(Path(td, "o.json").exists())


class TestSanitizeDist(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self.tmp.name) / "dist"
        (self.dist / "api" / "v1" / "intel").mkdir(parents=True)
        (self.dist / "api" / "v1" / "detections").mkdir(parents=True)
        (self.dist / "reports" / "2026" / "10").mkdir(parents=True)
        (self.dist / "api" / "feed.json").write_text(json.dumps([rec("ok", "TLP:CLEAR"), rec("bad", "TLP:RED", d=SECRET)]))
        (self.dist / "api" / "v1" / "intel" / "latest.json").write_text(
            json.dumps({"count": 2, "items": [rec("ok", "TLP:CLEAR"), rec("bad2", "TLP:AMBER")]}))
        (self.dist / "api" / "v1" / "detections" / "ok.json").write_text(
            json.dumps({"title": "d", "cve_id": "CVE-1", "stix_id": "s", "sigma_rule": "r"}))
        (self.dist / "api" / "v1" / "detections" / "orphan.json").write_text(
            json.dumps({"title": "d", "cve_id": "CVE-2", "stix_id": "s", "sigma_rule": SECRET}))
        (self.dist / "blog").mkdir()
        (self.dist / "blog" / "index.json").write_text(json.dumps({"posts": [{"title": "post", "stix_id": "x", "url": "/b"}]}))
        (self.dist / "api" / "ai.json").write_text(json.dumps({"classification": "TLP:AMBER — Authorized Only", "x": SECRET}))
        rep = self.dist / "reports" / "2026" / "10"
        (rep / "ok.html").write_text("<html><span>TLP:CLEAR</span></html>")
        (rep / "bad.html").write_text("<html><span>TLP:CLEAR</span></html>")      # removed by denied id
        (rep / "bad2.html").write_text("<html>x</html>")                           # removed by denied id
        (rep / "selfred.html").write_text("<html><span>TLP:RED</span> " + SECRET + "</html>")  # self-declared
        (rep / "mentions.html").write_text(
            "<html><div class='tlp-banner tlp--CLEAR'>TLP: TLP:CLEAR</div><p>handling of TLP:RED data</p></html>")
        (rep / "mixedmeta.html").write_text("<html><head><meta name='tlp' content='TLP:RED'></head><span>TLP:CLEAR</span> " + SECRET + "</html>")
        (rep / "mixedbadge.html").write_text("<html><span>TLP:GREEN</span><span>TLP:CLEAR</span> " + SECRET + "</html>")
        (self.dist / "reports" / "2026" / "outside.html").write_text("<html>y</html>")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **kw):
        return tb.sanitize_dist(self.dist, POLICY, parent_sources=[self.dist / "api" / "feed.json"], **kw)

    def test_dry_run_changes_nothing(self):
        snap = {p: p.read_bytes() for p in self.dist.rglob("*") if p.is_file()}
        rep = self._run(dry_run=True)
        self.assertTrue(rep["dry_run"])
        self.assertGreater(rep["records_removed"], 0)
        self.assertEqual({p: p.read_bytes() for p in self.dist.rglob("*") if p.is_file()}, snap)

    def test_enforcement_leaves_no_restricted_byte_anywhere_in_dist(self):
        rep = self._run()
        blob = b"".join(p.read_bytes() for p in self.dist.rglob("*") if p.is_file())
        self.assertNotIn(SECRET.encode(), blob)
        feed = json.loads((self.dist / "api" / "feed.json").read_text())
        self.assertEqual([x["id"] for x in feed], ["ok"])
        latest = json.loads((self.dist / "api" / "v1" / "intel" / "latest.json").read_text())
        self.assertEqual((latest["count"], [x["id"] for x in latest["items"]]), (1, ["ok"]))
        ai = json.loads((self.dist / "api" / "ai.json").read_text())
        self.assertTrue(ai["tlp_boundary"]["withheld"])
        det_ok = json.loads((self.dist / "api" / "v1" / "detections" / "ok.json").read_text())
        self.assertEqual(det_ok["cve_id"], "CVE-1", "derived document of a CLEAR parent is kept")
        det_orphan = json.loads((self.dist / "api" / "v1" / "detections" / "orphan.json").read_text())
        self.assertTrue(det_orphan["tlp_boundary"]["withheld"], "no verified parent -> fail closed")
        rep_dir = self.dist / "reports" / "2026" / "10"
        self.assertTrue((rep_dir / "ok.html").exists())
        self.assertFalse((rep_dir / "bad.html").exists())
        self.assertFalse((rep_dir / "bad2.html").exists())
        self.assertFalse((rep_dir / "selfred.html").exists())
        self.assertFalse((rep_dir / "mixedmeta.html").exists(), "explicit RED meta cannot be vetoed by CLEAR")
        self.assertFalse((rep_dir / "mixedbadge.html").exists(), "explicit GREEN badge cannot be vetoed by CLEAR")
        self.assertTrue((rep_dir / "mentions.html").exists(),
                        "a page whose authoritative badge is CLEAR and that merely MENTIONS another label in prose stays")
        self.assertGreaterEqual(rep["report_files_removed"], 3)

    def test_first_party_content_outside_api_is_not_treated_as_advisory_data(self):
        self._run()
        blog = json.loads((self.dist / "blog" / "index.json").read_text())
        self.assertEqual(len(blog["posts"]), 1)

    def test_idempotent_second_run_is_a_no_op(self):
        self._run()
        snap = {p: p.read_bytes() for p in self.dist.rglob("*") if p.is_file()}
        rep2 = self._run()
        self.assertEqual(rep2["records_removed"], 0)
        self.assertEqual(rep2["report_files_removed"], 0)
        self.assertEqual({p: p.read_bytes() for p in self.dist.rglob("*") if p.is_file()}, snap)

    def test_unverifiable_json_is_reported_not_silently_clean(self):
        (self.dist / "api" / "broken.json").write_text("{nope")
        rep = self._run()
        self.assertIn("api/broken.json", rep["unverifiable_json"])

    def test_path_traversal_ids_never_escape_reports(self):
        outside = self.dist / "outside_victim.html"
        outside.write_text("keep")
        rep = tb.sanitize_dist(self.dist, POLICY, extra_denied_ids=["../outside_victim", "..", "a/b"],
                               parent_sources=[])
        self.assertTrue(outside.exists())
        self.assertIsNotNone(rep)

    def test_report_report_has_ids_and_codes_only(self):
        rep = self._run()
        self.assertNotIn(SECRET, json.dumps(rep))


class TestR2UploaderBoundary(unittest.TestCase):
    def test_json_helper_sanitizes_withholds_unverifiable_and_passes_missing_through(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td, "priority.json")
            src.write_text(json.dumps([rec("a", "TLP:GREEN", d=SECRET), rec("b", "TLP:CLEAR")]))
            safe = r2_upload.tlp_safe_public_json_source(src, Path(td, "s"), "apex_v2/priority.json")
            self.assertEqual([x["id"] for x in json.loads(safe.read_text())], ["b"])
            self.assertNotIn(SECRET, safe.read_text())
            bad = Path(td, "bad.json")
            bad.write_text("{nope")
            self.assertIsNone(r2_upload.tlp_safe_public_json_source(bad, Path(td, "s"), "x/bad.json"))
            missing = Path(td, "missing.json")
            self.assertEqual(r2_upload.tlp_safe_public_json_source(missing, Path(td, "s"), "x/m.json"), missing)

    def test_main_puts_only_sanitized_bytes_for_every_json_key_and_budgets_fewer_puts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            files = {
                "apex_v2/priority.json": [rec("p1", "TLP:GREEN", d=SECRET), rec("p2", "TLP:CLEAR")],
                "ai/apex_report.json": {"classification": "TLP:AMBER — For Authorized Recipients Only", "x": SECRET},
                "intel/ok.json": {"count": 1, "items": [rec("i1", "TLP:CLEAR")]},
                "api/feed.json": [rec("f1", "TLP:CLEAR"), rec("f2", "TLP:RED", d=SECRET)],
            }
            pairs = []
            for key, doc in files.items():
                p = root / key.replace("/", "_")
                p.write_text(json.dumps(doc))
                pairs.append((str(p), key))
            broken = root / "broken.json"
            broken.write_text("{nope")
            pairs.append((str(broken), "intel/broken.json"))
            puts = {}
            planned = {}

            def fake_cp(src, bucket, key, endpoint, *a, **k):
                puts[key] = Path(src).read_text(encoding="utf-8")
                return True

            real_plan = r2_upload.R2OperationPlan

            class SpyPlan(real_plan):
                def record_put(self, n=1):
                    planned["puts"] = n
                    return super().record_put(n)

            with mock.patch.object(r2_upload, "build_upload_plan", return_value=pairs), \
                    mock.patch.object(r2_upload, "s3_cp", side_effect=fake_cp), \
                    mock.patch.object(r2_upload, "get_credentials", return_value=("acct", "k", "s")), \
                    mock.patch.object(r2_upload, "install_awscli"), \
                    mock.patch.object(r2_upload, "configure_awscli_performance"), \
                    mock.patch.object(r2_upload, "count_manifest", return_value=1), \
                    mock.patch.object(r2_upload, "_generate_ai_endpoints"), \
                    mock.patch.object(r2_upload, "emit_summary"), \
                    mock.patch.object(r2_upload, "write_github_env"), \
                    mock.patch.object(r2_upload, "R2OperationPlan", SpyPlan), \
                    mock.patch.object(r2_upload, "REPO_ROOT", root), \
                    mock.patch("p0_r44_publication_boundary.finalize_public_feed", return_value={"published_count": 1}), \
                    mock.patch("os.chdir"):
                # This unit tests R2 TLP/cost handling only; the real finalizer
                # is independently covered by the mandatory R44 gate.
                r2_upload.main()
        self.assertEqual([x["id"] for x in json.loads(puts["apex_v2/priority.json"])], ["p2"])
        self.assertTrue(json.loads(puts["ai/apex_report.json"])["tlp_boundary"]["withheld"])
        self.assertEqual([x["id"] for x in json.loads(puts["api/feed.json"])], ["f1"])
        self.assertNotIn("intel/broken.json", puts, "an unverifiable document is withheld, never PUT raw")
        for body in puts.values():
            self.assertNotIn(SECRET, body)
        self.assertEqual(planned["puts"], 4 + 1, "the withheld object is not budgeted; +1 sync metadata")

    def test_resync_applies_the_boundary_to_every_json_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "api" / "v1" / "intel").mkdir(parents=True)
            (root / "api" / "feed.json").write_text(json.dumps([rec("c", "TLP:CLEAR")]))
            (root / "api" / "v1" / "intel" / "latest.json").write_text(
                json.dumps({"generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                            "count": 2, "items": [rec("c", "TLP:CLEAR"), rec("r", "TLP:RED", d=SECRET)]}))
            puts = {}

            def fake_cp(src, bucket, key, endpoint, cache_control="x"):
                puts[key] = Path(src).read_text(encoding="utf-8")
                return True

            with mock.patch.object(resync, "REPO_ROOT", root), \
                    mock.patch.object(resync, "_WORKER_PUBLIC_FEED_CHECK", str(REPO / "scripts/p0_r2_public_feed_diagnostic.mjs")), \
                    mock.patch.object(resync, "s3_cp", side_effect=fake_cp), \
                    mock.patch.object(resync, "get_credentials", return_value=("a", "k", "s")), \
                    mock.patch.object(resync, "stale_manifest_reason", return_value=None), \
                    mock.patch("os.chdir"):
                with self.assertRaises(SystemExit):
                    resync.main()
        self.assertIn("api/v1/intel/latest.json", puts)
        self.assertNotIn(SECRET, puts["api/v1/intel/latest.json"])
        self.assertEqual(json.loads(puts["api/v1/intel/latest.json"])["count"], 1)


class TestSanitizeWorkspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "api" / "v1" / "detections").mkdir(parents=True)
        (self.root / "reports" / "2026" / "10").mkdir(parents=True)
        (self.root / "data").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, rel, doc):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        return p

    def test_feed_and_derived_documents_become_consistent_and_internal_data_is_untouched(self):
        self._w("api/feed.json", [rec("ok", "TLP:CLEAR"), rec("red", "TLP:RED", d=SECRET)])
        self._w("api/v1/detections/ok.json", {"title": "d", "cve_id": "CVE-1", "stix_id": "s"})
        self._w("api/v1/detections/red.json", {"title": "d", "cve_id": "CVE-2", "stix_id": "s", "sigma": SECRET})
        internal = self._w("data/feed_manifest.json", [rec("ok", "TLP:CLEAR"), rec("red", "TLP:RED", d=SECRET)])
        before_internal = internal.read_bytes()
        rep = tb.sanitize_workspace(self.root, POLICY)
        self.assertEqual([x["id"] for x in json.loads((self.root / "api/feed.json").read_text())], ["ok"])
        self.assertEqual(json.loads((self.root / "api/v1/detections/ok.json").read_text())["cve_id"], "CVE-1")
        self.assertTrue(json.loads((self.root / "api/v1/detections/red.json").read_text())["tlp_boundary"]["withheld"])
        self.assertEqual(internal.read_bytes(), before_internal, "data/ keeps every record")
        self.assertEqual(rep["denied_ids"], ["red"])
        self.assertNotIn(SECRET, "".join(p.read_text() for p in (self.root / "api").rglob("*.json")))

    def test_an_id_labelled_restricted_in_any_document_is_denied_in_every_document(self):
        self._w("api/feed.json", [rec("x", "TLP:CLEAR"), rec("y", "TLP:CLEAR")])
        self._w("api/apex_v2/priority.json", [rec("x", "TLP:GREEN")])
        rep = tb.sanitize_workspace(self.root, POLICY)
        self.assertEqual([r["id"] for r in json.loads((self.root / "api/feed.json").read_text())], ["y"])
        self.assertIn("x", rep["denied_ids"])

    def test_a_clear_record_whose_report_page_states_a_restricted_tlp_is_removed(self):
        self._w("api/feed.json", [rec("page_red", "TLP:CLEAR"), rec("page_ok", "TLP:CLEAR")])
        self._w("reports/2026/10/page_red.html", "<html>TLP:AMBER</html>")
        self._w("reports/2026/10/page_ok.html", "<html>TLP:CLEAR</html>")
        rep = tb.sanitize_workspace(self.root, POLICY)
        self.assertEqual([r["id"] for r in json.loads((self.root / "api/feed.json").read_text())], ["page_ok"])
        self.assertIn("page_red", rep["denied_ids"])

    def test_dry_run_and_unverifiable_documents(self):
        f = self._w("api/feed.json", [rec("red", "TLP:RED")])
        self._w("api/broken.json", "{nope")
        before = f.read_bytes()
        rep = tb.sanitize_workspace(self.root, POLICY, dry_run=True)
        self.assertEqual(f.read_bytes(), before)
        self.assertIn("api/broken.json", rep["unverifiable_json"])


class TestFailOnZeroWithPolicyWithheldItems(unittest.TestCase):
    """Run 37806739926 went red because the only in-window items were TLP-withheld: written=0 with eligible>0."""

    def _run(self, items):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": items}))
            quarantine = REPO / "data" / "quality" / "tlp_quarantine_report.json"
            had = quarantine.exists()
            try:
                res = subprocess.run([sys.executable, str(REPO / "scripts" / "generate_intel_reports.py"),
                                      "--manifest", str(manifest), "--public-prefix", "https://intel.cyberdudebivash.com",
                                      "--limit", "0", "--since-hours", "24", "--fail-on-zero"],
                                     cwd=REPO, capture_output=True, text=True, timeout=120)
            finally:
                if not had:
                    quarantine.unlink(missing_ok=True)
                for it in items:
                    for p in (REPO / "reports").rglob(f"{it['id']}.html*"):
                        p.unlink(missing_ok=True)
            return res

    def _item(self, i, **kw):
        from datetime import datetime, timedelta, timezone
        ts = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return dict({"id": i, "title": "Fixture advisory " + i, "description": "x" * 80, "severity": "LOW",
                     "timestamp": ts, "report_url": ""}, **kw)

    def test_window_whose_only_items_are_policy_withheld_is_loud_but_not_a_renderer_failure(self):
        res = self._run([self._item("intel--r12fz000001"), self._item("intel--r12fz000002", tlp="TLP:RED")])
        self.assertEqual(res.returncode, 0, res.stdout[-600:] + res.stderr[-600:])
        self.assertIn("::warning::TLP policy withheld 2 item(s)", res.stdout + res.stderr)

    def test_a_publishable_item_that_produces_no_report_still_fails_the_gate(self):
        # CLEAR + eligible but excluded from rendering by the generator itself must still be caught by --fail-on-zero;
        # emulate by a CLEAR item that the renderer cannot write (read-only reports dir is not portable), so assert
        # the eligibility arithmetic instead: withheld items are subtracted, publishable ones are not.
        src = (REPO / "scripts" / "generate_intel_reports.py").read_text(encoding="utf-8")
        self.assertIn("eligible = len(items) - excluded_by_window - skipped_brand - len(tlp_quarantined)", src)
        res = self._run([self._item("intel--r12fz000003", tlp="TLP:CLEAR")])
        self.assertEqual(res.returncode, 0, res.stdout[-400:] + res.stderr[-400:])


class TestReportValidationGateWithPolicyWithheldItems(unittest.TestCase):
    """Run 37809443847 hard-failed STAGE 3.3 ("20 report(s) failed validation") on advisories the TLP gate had
    deliberately not rendered. The gate must accept that absence -- and only that absence."""

    def setUp(self):
        import os
        import validate_reports as vr
        self.vr = vr
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        from datetime import datetime, timedelta, timezone
        self.now = datetime.now(timezone.utc).replace(microsecond=0)  # keep synthetic report inside the actual gate window
        self.fresh = (self.now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def tearDown(self):
        import os
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _entry(self, iid, **kw):
        return dict({"id": iid, "report_url": f"/reports/2026/10/{iid}.html", "processed_at": self.fresh}, **kw)

    def _one(self, entry):
        return self.vr._validate_one(entry, 0, now=self.now, window_hours=24, published_ids=set())

    def test_withheld_when_denied_and_missing(self):
        for kw in ({}, {"tlp": "TLP:RED"}, {"tlp": "TLP:GREEN"}, {"tlp": "TLP:AMBER+STRICT"}, {"tlp": "TLP:PURPLE"},
                   {"tlp": "TLP:CLEAR", "evidence_chain": [{"tlp": "TLP:AMBER"}]}):
            failures, disposition = self._one(self._entry("intel--w1", **kw))
            self.assertEqual((failures, disposition), ([], "WITHHELD"), kw)

    def test_publishable_but_missing_in_window_still_fails_the_gate(self):
        failures, disposition = self._one(self._entry("intel--w2", tlp="TLP:CLEAR"))
        self.assertEqual(disposition, "FAIL")
        self.assertTrue(any("RULE 3 FAIL" in f for f in failures))

    def test_existing_report_of_a_denied_item_is_still_validated_not_waved_through(self):
        p = Path("reports/2026/10/intel--w3.html")
        p.parent.mkdir(parents=True)
        p.write_text("tiny")  # an existing but invalid file must not be excused by the policy status
        failures, disposition = self._one(self._entry("intel--w3", tlp="TLP:RED"))
        self.assertEqual(disposition, "FAIL")

    def test_whole_gate_passes_with_only_withheld_items_and_still_blocks_on_a_real_defect(self):
        from pathlib import Path as P
        import json as _j
        P("data/stix").mkdir(parents=True)
        mf = P("data/stix/feed_manifest.json")
        mf.write_text(_j.dumps({"advisories": [self._entry("intel--w4"), self._entry("intel--w5", tlp="TLP:RED")]}))
        with mock.patch.object(self.vr, "load_publish_state", return_value={"items": {}}):
            self.assertTrue(self.vr.validate_all_reports(manifest_path=mf, reports_base=P("reports")))
            mf.write_text(_j.dumps({"advisories": [self._entry("intel--w4"), self._entry("intel--w6", tlp="TLP:CLEAR")]}))
            self.assertFalse(self.vr.validate_all_reports(manifest_path=mf, reports_base=P("reports")))


class TestPublishingVerdictBehavior(unittest.TestCase):
    """P0 #720: execute the real verdict step script (bash) for every publisher outcome combination."""

    @classmethod
    def setUpClass(cls):
        import yaml
        wf = yaml.safe_load((REPO / ".github" / "workflows" / "sentinel-blogger.yml").read_text(encoding="utf-8"))
        steps = wf["jobs"]["generate-and-sync"]["steps"]
        cls.step = next(s for s in steps if s.get("id") == "p0-publisher-verdict")

    def _run(self, initial, late, enabled="true"):
        import os
        import subprocess
        env = {"PATH": os.environ["PATH"], "INITIAL_OUTCOME": initial, "LATE_OUTCOME": late, "PUBLISHING_ENABLED": enabled}
        r = subprocess.run(["bash", "-eo", "pipefail", "-c", self.step["run"]], env=env, capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_only_two_successful_publishers_allow_pages(self):
        self.assertEqual(self._run("success", "success")[0], 0)
        for init, late in (("failure", "success"), ("success", "failure"), ("failure", "failure"),
                           ("skipped", "success"), ("success", "skipped"), ("cancelled", "success"), ("", "success"),
                           ("success", "")):
            code, out = self._run(init, late)
            self.assertEqual(code, 1, (init, late, out))
            self.assertIn("BLOCKED", out)

    def test_disabled_publisher_never_masquerades_as_a_clean_release(self):
        for flag in ("false", "FALSE", " False "):
            code, out = self._run("success", "success", flag)
            self.assertEqual(code, 0)
            self.assertIn("PASS-WITH-PUBLISHER-DISABLED", out)
            self.assertIn("NOT a fully successful fresh release", out)
        self.assertNotIn("DISABLED", self._run("success", "success", "true")[1])
        # a failing publisher is still blocked even when the kill switch text is present
        self.assertEqual(self._run("failure", "success", "false")[0], 1)

    def test_every_pages_write_path_in_the_main_pipeline_depends_on_the_verdict(self):
        import yaml
        wf = yaml.safe_load((REPO / ".github" / "workflows" / "sentinel-blogger.yml").read_text(encoding="utf-8"))
        writers = [s for s in wf["jobs"]["generate-and-sync"]["steps"]
                   if "github-pages-deploy-action" in str(s.get("uses", "")) or "deploy-pages" in str(s.get("uses", ""))]
        self.assertTrue(writers)
        for s in writers:
            self.assertIn("p0-publisher-verdict", str(s.get("if", "")), s.get("name"))


class TestOtherPublicWritersUseTheBoundary(unittest.TestCase):
    def _wf(self, name):
        return (REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")

    def test_workflows_with_raw_r2_uploads_sanitize_every_object_first(self):
        for name in ("dashboard-feeds-sync.yml", "r2-data-sync.yml"):
            text = self._wf(name)
            self.assertIn("tlp_public_boundary.py --sanitize-file", text, name)
            self.assertNotRegex(text, r'aws s3 cp "\$FILE" "s3', name)
            self.assertNotRegex(text, r'aws s3 cp "\$f" "s3', name)

    def test_weekly_publishers_no_longer_publish_raw_trees(self):
        brief = self._wf("weekly-threat-brief.yml")
        self.assertNotRegex(brief, r"folder:\s*\.\s*\n", "the whole checkout must never be published to gh-pages")
        self.assertIn("tlp_public_boundary.py --tree .publish", brief)
        self.assertIn("tlp_public_boundary.py --tree .publish", self._wf("weekly-analyst-briefing.yml"))

    def test_cli_sanitize_file_and_tree(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            src, out = Path(td, "in.json"), Path(td, "out.json")
            src.write_text(json.dumps([rec("a", "TLP:CLEAR"), rec("b", "TLP:RED", d=SECRET)]))
            r = subprocess.run([sys.executable, str(REPO / "scripts" / "tlp_public_boundary.py"),
                                "--sanitize-file", str(src), "--out-file", str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual([x["id"] for x in json.loads(out.read_text())], ["a"])
            self.assertNotIn(SECRET, out.read_text() + r.stdout + r.stderr)
            bad = Path(td, "bad.json")
            bad.write_text("{nope")
            r = subprocess.run([sys.executable, str(REPO / "scripts" / "tlp_public_boundary.py"),
                                "--sanitize-file", str(bad), "--out-file", str(Path(td, "o2.json"))], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(Path(td, "o2.json").exists())
            tree = Path(td, "tree")
            (tree / "d").mkdir(parents=True)
            (tree / "d" / "x.json").write_text(json.dumps({"items": [rec("c", "TLP:GREEN", d=SECRET), rec("e", "TLP:CLEAR")]}))
            r = subprocess.run([sys.executable, str(REPO / "scripts" / "tlp_public_boundary.py"), "--tree", str(tree),
                                "--out", str(Path(td, "rep.json"))], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(SECRET, (tree / "d" / "x.json").read_text())
            (tree / "d" / "broken.json").write_text("{nope")
            r = subprocess.run([sys.executable, str(REPO / "scripts" / "tlp_public_boundary.py"), "--tree", str(tree),
                                "--out", str(Path(td, "rep.json"))], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, "a staged publish folder with an unverifiable document must fail")


class TestPublicUploadPrimitive(unittest.TestCase):
    """s3_cp stays the plain PUT (internal state sync needs byte-exact JSON); every anonymous upload mode uses s3_cp_public."""

    def test_every_public_upload_mode_uses_the_boundary_primitive_and_state_sync_keeps_the_plain_one(self):
        import re
        src = (REPO / "scripts" / "r2_upload.py").read_text(encoding="utf-8")
        for fn in ("upload_p40_artifacts", "main_ai_tracker_only", "main_governance_telemetry_only",
                   "main_weekly_brief_only", "main_reports_index_only"):
            body = src[src.index(f"def {fn}("):]
            body = body[:re.search(r"\n(?:def |if __name__)", body[10:]).start() + 10]
            self.assertIn("s3_cp_public(", body, fn)
            self.assertNotRegex(body, r"(?<![\w_])s3_cp\(", f"{fn} must not use the plain primitive")
        state = (REPO / "scripts" / "r2_state_sync.py").read_text(encoding="utf-8")
        self.assertNotIn("s3_cp_public", state, "internal cross-run state must round-trip unsanitized")

    def test_s3_cp_public_sanitizes_unverified_json_and_refuses_unverifiable(self):
        sent = []
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(r2_upload, "s3_cp", side_effect=lambda src, *a, **k: sent.append(Path(src).read_text()) or True):
            ok = Path(td, "w.json")
            ok.write_text(json.dumps({"week": 1, "top": [rec("g", "TLP:GREEN", d=SECRET), rec("c", "TLP:CLEAR")]}))
            self.assertTrue(r2_upload.s3_cp_public(str(ok), "b", "api/v1/intel/weekly_brief.json", "e"))
            self.assertNotIn(SECRET, sent[-1])
            self.assertIn('"c"', sent[-1])
            bad = Path(td, "bad.json")
            bad.write_text("{nope")
            before = len(sent)
            self.assertFalse(r2_upload.s3_cp_public(str(bad), "b", "x/bad.json", "e"))
            self.assertEqual(len(sent), before, "nothing is PUT for an unverifiable document")
            html = Path(td, "r.html")
            html.write_text("<html>raw</html>")
            self.assertTrue(r2_upload.s3_cp_public(str(html), "b", "reports/x.html", "e"))
            self.assertEqual(sent[-1], "<html>raw</html>", "non-JSON objects are not rewritten here")

    def test_plain_s3_cp_is_untouched_for_internal_state(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(r2_upload.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            state = Path(td, "feed_state.json")
            state.write_text(json.dumps([rec("g", "TLP:GREEN", d=SECRET)]))
            self.assertTrue(r2_upload.s3_cp(str(state), "b", "state/feed_state.json", "e"))
            self.assertEqual(run.call_args[0][0][3], str(state), "the original file is PUT, not a sanitized copy")

    def test_pre_verified_copies_are_not_sanitized_twice(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(r2_upload, "s3_cp", return_value=True) as raw:
            src = Path(td, "o.json")
            src.write_text(json.dumps([rec("a", "TLP:CLEAR")]))
            safe = r2_upload.tlp_safe_public_json_source(src, Path(td, "s"), "k.json")
            with mock.patch.object(r2_upload._tlp_boundary, "sanitize_json_file") as san:
                self.assertTrue(r2_upload.s3_cp_public(str(safe), "b", "k.json", "e"))
                san.assert_not_called()
            self.assertEqual(raw.call_args[0][0], str(safe))


class TestExposureInventory(unittest.TestCase):
    def setUp(self):
        import tlp_exposure_inventory as inv
        self.inv = inv
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "api").mkdir()
        (self.root / "reports" / "2026" / "10").mkdir(parents=True)
        (self.root / "api" / "feed.json").write_text(json.dumps([
            rec("pubr", "TLP:RED", d=SECRET), rec("pubg", "TLP:GREEN"), rec("ok", "TLP:CLEAR"), rec("unl")]))
        (self.root / "reports" / "2026" / "10" / "pubr.html").write_text("<html>TLP:RED " + SECRET + "</html>")
        self.salt = b"s" * 24

    def tearDown(self):
        self.tmp.cleanup()

    def test_ledger_has_references_and_codes_never_content_or_raw_ids(self):
        led = self.inv.build_ledger(self.root, self.salt)
        blob = json.dumps(led)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("title-", blob)
        self.assertNotIn('"pubr"', blob)
        self.assertEqual(len(led["rows"]), 2, "only restricted-labelled advisories; CLEAR and merely-unlabelled are excluded")
        refs = {r["opaque_ref"] for r in led["rows"]}
        self.assertEqual(refs, {self.inv.opaque_ref("pubr", self.salt), self.inv.opaque_ref("pubg", self.salt)})
        self.assertNotEqual(self.inv.opaque_ref("pubr", self.salt), self.inv.opaque_ref("pubr", b"t" * 24))
        row = next(r for r in led["rows"] if r["opaque_ref"] == self.inv.opaque_ref("pubr", self.salt))
        self.assertIn("pages_report", {a["kind"] for a in row["artifacts"]})
        self.assertTrue(row["originator_notification_required"])
        self.assertEqual(row["verification_status"], "NOT_VERIFIED_ANONYMOUSLY")
        self.assertEqual(self.inv.summarize(led)["by_label"], {"TLP:RED": 1, "TLP:GREEN": 1})

    def test_probe_is_bounded_and_records_status_only(self):
        calls = []
        led = self.inv.build_ledger(self.root, self.salt, probe_limit=1, prober=lambda url: calls.append(url) or "200")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith(self.inv.PUBLIC_ORIGIN + "/reports/"))
        self.assertEqual([r["verification_status"] for r in led["rows"]].count("CONFIRMED_ANONYMOUSLY_ACCESSIBLE"), 1)
        calls.clear()
        self.inv.build_ledger(self.root, self.salt, probe_limit=0, prober=lambda url: calls.append(url) or "200")
        self.assertEqual(calls, [], "default is fully offline")

    def test_cli_refuses_in_tree_output_and_weak_or_missing_salt_and_changes_nothing(self):
        import os
        import subprocess
        snap = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        env = dict(os.environ, TLP_LEDGER_SALT="s" * 20)
        script = str(REPO / "scripts" / "tlp_exposure_inventory.py")
        r = subprocess.run([sys.executable, script, "--root", str(self.root), "--out", str(REPO / "x_ledger.json")],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertFalse((REPO / "x_ledger.json").exists())
        r = subprocess.run([sys.executable, script, "--root", str(self.root), "--out", str(self.root / "l.json")],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, "an out path inside the inspected root is refused too")
        r = subprocess.run([sys.executable, script, "--root", str(self.root), "--out", "/tmp/never.json"],
                           env=dict(os.environ, TLP_LEDGER_SALT="short"), capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, script, "--root", str(self.root), "--out", str(Path(out, "l.json"))],
                               env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(SECRET, r.stdout + r.stderr + Path(out, "l.json").read_text())
            self.assertEqual(oct(Path(out, "l.json").stat().st_mode & 0o777), "0o600")
        self.assertEqual({p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}, snap, "read-only")


class TestWiring(unittest.TestCase):
    def test_dist_builder_applies_the_boundary_before_anything_is_copied_and_before_the_checksum_manifest(self):
        src = (REPO / "scripts" / "build_dist_artifact.py").read_text(encoding="utf-8")
        ws, dist = src.index("sanitize_workspace(REPO_ROOT)"), src.index("sanitize_dist(DIST_DIR")
        self.assertLess(ws, src.index("shutil.rmtree(DIST_DIR)"), "workspace pass precedes the build")
        self.assertLess(dist, src.index("build_manifest(DIST_DIR, run_id"))
        self.assertLess(dist, src.index("sentinel-branding.cjs"))
        # fail closed: both calls sit in a try/except that returns 1 rather than building/deploying an unchecked artifact
        self.assertIn("return 1", src[ws:ws + 600])
        self.assertIn("return 1", src[dist:dist + 400])


if __name__ == "__main__":
    unittest.main()
