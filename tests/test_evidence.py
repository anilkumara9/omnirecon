"""Tests for omnirecon.evidence — Finding validation, ledger CRUD, dedup, persistence."""
import os
import tempfile
import unittest

from omnirecon.evidence import EvidenceLedger, Finding
from omnirecon.security import ReconError


def _f(**kw):
    d = {"type": "endpoint", "title": "GET /api/users",
         "detail": "observed in traffic", "classification": "OBSERVED",
         "confidence": 0.9, "confidence_why": "captured live",
         "sources": ["https://x.test/api/users"], "route": "/users",
         "endpoint": "/api/users"}
    d.update(kw)
    return d


class TestAdd(unittest.TestCase):
    def test_assigns_ids_and_timestamps(self):
        led = EvidenceLedger()
        a = led.add(_f())
        b = led.add(_f(title="other"))
        self.assertEqual(a, "F-0001")
        self.assertEqual(b, "F-0002")
        got = led.get(a)
        self.assertTrue(got["timestamp"])
        self.assertEqual(got["verification"], "unverified")

    def test_rejects_bad_classification(self):
        led = EvidenceLedger()
        with self.assertRaises(ReconError) as ctx:
            led.add(_f(classification="MAYBE"))
        self.assertEqual(ctx.exception.code, "invalid_classification")

    def test_rejects_bad_type(self):
        led = EvidenceLedger()
        with self.assertRaises(ReconError) as ctx:
            led.add(_f(type="spaceship"))
        self.assertEqual(ctx.exception.code, "invalid_finding_type")

    def test_rejects_bad_confidence(self):
        led = EvidenceLedger()
        for bad in (-0.1, 1.5, "high"):
            with self.assertRaises(ReconError):
                led.add(_f(confidence=bad))

    def test_rejects_non_dict(self):
        led = EvidenceLedger()
        with self.assertRaises(ReconError):
            led.add("nope")

    def test_defaults(self):
        led = EvidenceLedger()
        fid = led.add({"title": "minimal"})
        got = led.get(fid)
        self.assertEqual(got["classification"], "UNVERIFIED")
        self.assertEqual(got["type"], "note")
        self.assertEqual(got["confidence"], 0.5)


class TestReads(unittest.TestCase):
    def setUp(self):
        self.led = EvidenceLedger()
        self.led.add(_f(type="endpoint", classification="OBSERVED", confidence=0.9))
        self.led.add(_f(type="route", title="R /", classification="INFERRED",
                        confidence=0.4, route="/"))
        self.led.add(_f(type="endpoint", title="POST /api/login",
                        classification="OBSERVED", confidence=0.7, route="/login"))

    def test_get_missing(self):
        self.assertIsNone(self.led.get("F-9999"))

    def test_list_filters(self):
        self.assertEqual(len(self.led.list(type="endpoint")), 2)
        self.assertEqual(len(self.led.list(classification="INFERRED")), 1)
        self.assertEqual(len(self.led.list(min_confidence=0.8)), 1)
        self.assertEqual(len(self.led.list(type="endpoint", min_confidence=0.8)), 1)

    def test_search_case_insensitive(self):
        self.assertEqual(len(self.led.search("login")), 1)
        self.assertEqual(len(self.led.search("OBSERVED IN TRAFFIC")), 3)
        self.assertEqual(self.led.search(""), [])


class TestDedup(unittest.TestCase):
    def test_merges_same_type_and_route(self):
        led = EvidenceLedger()
        led.add(_f(confidence=0.6, sources=["a"], limitations="L1"))
        led.add(_f(confidence=0.9, sources=["b"], limitations="L2"))
        merged = led.dedup()
        self.assertEqual(merged, 1)
        self.assertEqual(len(led), 1)
        survivor = led.list()[0]
        self.assertEqual(survivor["confidence"], 0.9)  # highest wins
        self.assertEqual(sorted(survivor["sources"]), ["a", "b"])
        self.assertIn("L1", survivor["limitations"])
        self.assertIn("L2", survivor["limitations"])

    def test_no_merge_across_routes(self):
        led = EvidenceLedger()
        led.add(_f(route="/a"))
        led.add(_f(route="/b"))
        self.assertEqual(led.dedup(), 0)
        self.assertEqual(len(led), 2)

    def test_no_merge_across_types(self):
        led = EvidenceLedger()
        led.add(_f(type="endpoint", route="/x"))
        led.add(_f(type="component", route="/x"))
        self.assertEqual(led.dedup(), 0)

    def test_anchor_falls_back_to_endpoint_then_title(self):
        led = EvidenceLedger()
        led.add(_f(type="endpoint", route=None, endpoint="/api/a", title="t1"))
        led.add(_f(type="endpoint", route=None, endpoint="/api/a", title="t2"))
        self.assertEqual(led.dedup(), 1)


class TestPersistence(unittest.TestCase):
    def test_save_load_round_trip(self):
        led = EvidenceLedger()
        led.add(_f(title="one"))
        led.add(_f(title="two", type="route", route="/"))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evidence.jsonl")
            led.save(path)
            self.assertTrue(os.path.exists(path))
            led2 = EvidenceLedger.load(path)
            self.assertEqual(len(led2), 2)
            self.assertEqual(led2.get("F-0001")["title"], "one")
            # counter continues past loaded ids
            fid = led2.add(_f(title="three"))
            self.assertEqual(fid, "F-0003")

    def test_stats(self):
        led = EvidenceLedger()
        led.add(_f(type="endpoint", classification="OBSERVED"))
        led.add(_f(type="endpoint", classification="INFERRED"))
        led.add(_f(type="route", classification="OBSERVED", route="/"))
        s = led.stats()
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_type"], {"endpoint": 2, "route": 1})
        self.assertEqual(s["by_classification"], {"OBSERVED": 2, "INFERRED": 1})


class TestFindingDataclass(unittest.TestCase):
    def test_round_trip(self):
        f = Finding(id="F-0001", type="tech", title="t",
                    classification="OBSERVED", confidence=0.8)
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        self.assertEqual(f2.id, "F-0001")
        self.assertEqual(f2.confidence, 0.8)
        # unknown keys ignored
        f3 = Finding.from_dict({"id": "F-9", "bogus": 1})
        self.assertEqual(f3.id, "F-9")


if __name__ == "__main__":
    unittest.main()
