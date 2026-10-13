"""Tests for omnirecon.graph — node/edge construction and linkage rules."""
import json
import unittest

from omnirecon.evidence import EvidenceLedger
from omnirecon.graph import build_graph


def _ledger():
    led = EvidenceLedger()
    led.add({"type": "tech", "title": "Platform uses Next.js",
             "detail": "__NEXT_DATA__", "classification": "OBSERVED",
             "confidence": 0.85, "confidence_why": "marker",
             "sources": ["https://demo.test/"]})
    led.add({"type": "route", "title": "Route /users",
             "detail": "nav link", "classification": "OBSERVED",
             "confidence": 0.9, "confidence_why": "crawled",
             "sources": ["https://demo.test/"], "route": "/users"})
    led.add({"type": "endpoint", "title": "GET /api/users",
             "detail": "user list", "classification": "OBSERVED",
             "confidence": 0.9, "confidence_why": "captured",
             "sources": ["https://demo.test/users"], "route": "/users",
             "endpoint": "/api/users"})
    led.add({"type": "entity", "title": "Entity User",
             "detail": "fields id,name", "classification": "INFERRED",
             "confidence": 0.6, "confidence_why": "repeated shape",
             "sources": ["https://demo.test/api/users"], "route": "/users",
             "endpoint": "/api/users"})
    led.add({"type": "component", "title": "UserTable",
             "detail": "renders rows; calls /api/users for data",
             "classification": "OBSERVED", "confidence": 0.8,
             "confidence_why": "dom snapshot",
             "sources": ["https://demo.test/users"], "route": "/users"})
    led.add({"type": "workflow", "title": "Login flow",
             "detail": "fill form then POST", "classification": "OBSERVED",
             "confidence": 0.9, "confidence_why": "traced",
             "sources": ["https://demo.test/login"], "route": "/login",
             "endpoint": "/api/login"})
    return led


def _edge_set(g):
    return {(e["from"], e["to"], e["rel"]) for e in g["edges"]}


class TestBuildGraph(unittest.TestCase):
    def test_nodes_and_route_hubs(self):
        g = build_graph(_ledger(), target="https://demo.test")
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertIn("platform", kinds)
        self.assertIn("route", kinds)
        route_hubs = [n for n in g["nodes"] if n["id"].startswith("route:")]
        self.assertEqual({n["label"] for n in route_hubs}, {"/users", "/login"})
        self.assertEqual(g["counts"]["findings"], 6)
        self.assertEqual(g["counts"]["nodes"], 6 + 2 + 1)

    def test_linkage_rules(self):
        led = _ledger()
        g = build_graph(led, target="https://demo.test")
        by_title = {n["label"]: n["id"] for n in g["nodes"]}
        edges = _edge_set(g)
        # tech -> platform
        self.assertIn((by_title["Platform uses Next.js"], "platform", "built_with"), edges)
        # endpoint -> route hub
        self.assertIn((by_title["GET /api/users"], "route:/users", "exposed_at"), edges)
        # entity -> endpoint
        self.assertIn((by_title["Entity User"], by_title["GET /api/users"], "returned_by"), edges)
        # component -> endpoint via detail mention
        self.assertIn((by_title["UserTable"], by_title["GET /api/users"], "calls"), edges)
        # workflow -> its route hub
        self.assertIn((by_title["Login flow"], "route:/login", "visits"), edges)

    def test_no_target_no_platform_hub(self):
        g = build_graph(_ledger())
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertNotIn("platform", kinds)

    def test_empty_ledger(self):
        g = build_graph(EvidenceLedger())
        self.assertEqual(g["nodes"], [])
        self.assertEqual(g["edges"], [])
        self.assertEqual(g["counts"], {"nodes": 0, "edges": 0, "routes": 0, "findings": 0})

    def test_deterministic(self):
        a = build_graph(_ledger(), target="https://demo.test")
        b = build_graph(_ledger(), target="https://demo.test")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_no_duplicate_edges(self):
        led = _ledger()
        # add a second component mentioning the same endpoint
        led.add({"type": "component", "title": "UserTable copy",
                 "detail": "also calls /api/users", "classification": "OBSERVED",
                 "confidence": 0.5, "confidence_why": "x",
                 "sources": ["https://demo.test/users"], "route": "/users"})
        g = build_graph(led, target="https://demo.test")
        self.assertEqual(len(g["edges"]), len(_edge_set(g)))

    def test_node_schema(self):
        g = build_graph(_ledger())
        for n in g["nodes"]:
            for key in ("id", "kind", "label", "route"):
                self.assertIn(key, n, f"node missing {key}: {n}")
        for e in g["edges"]:
            for key in ("from", "to", "rel"):
                self.assertIn(key, e)


if __name__ == "__main__":
    unittest.main()
