"""Tests for omnirecon.spec.generate_spec."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omnirecon import spec as SPEC


def _mk(fid, ftype, title, cls="OBSERVED", conf=0.9, **kw):
    d = {"id": fid, "type": ftype, "title": title,
         "detail": kw.get("detail", f"detail of {title}"),
         "classification": cls, "confidence": conf,
         "confidence_why": "test fixture",
         "sources": kw.get("sources", ["https://example.com"]),
         "route": kw.get("route"), "component": kw.get("component"),
         "endpoint": kw.get("endpoint"), "artifact": kw.get("artifact"),
         "timestamp": "2026-10-12T00:00:00+00:00",
         "verification": "unverified",
         "limitations": kw.get("limitations", "")}
    return d


def _rich_ledger():
    return [
        _mk("F-0001", "tech", "Tech: Static HTML", "INFERRED", 0.7,
            detail="no framework markers"),
        _mk("F-0002", "route", "Route https://example.com/",
            route="https://example.com/"),
        _mk("F-0003", "route", "Route https://example.com/about",
            route="https://example.com/about"),
        _mk("F-0004", "endpoint", "Endpoint /api/widgets",
            endpoint="/api/widgets"),
        _mk("F-0005", "component", "Form -> /search", component="form:/search",
            route="https://example.com/"),
        _mk("F-0006", "workflow", "Search flow",
            detail="fill q, submit, results listed"),
        _mk("F-0007", "entity", "Entity: Widget",
            detail="inferred from /api/widgets responses", cls="INFERRED",
            conf=0.55),
        _mk("F-0008", "asset", "Asset: logo.svg",
            detail="header logo", artifact="artifacts/logo.svg"),
        _mk("F-0009", "auth", "No login form found", cls="UNVERIFIED",
            conf=0.4, limitations="only the homepage was inspected"),
        _mk("F-0010", "state", "Empty state on /api/widgets",
            detail="zero widgets shows 'nothing here'"),
        _mk("F-0011", "note", "Admin area unreachable", cls="BLOCKED",
            conf=1.0, limitations="/admin returned 403; not investigated"),
    ]


def test_all_sections_present():
    s = SPEC.generate_spec(_rich_ledger(), {"nodes": [], "edges": []})
    assert set(s["sections"].keys()) == set(SPEC.SECTION_NAMES), \
        f"sections mismatch: {sorted(s['sections'].keys())}"
    assert s["meta"]["finding_count"] == 11
    assert s["meta"]["by_classification"]["OBSERVED"] >= 1


def test_every_bullet_carries_finding_ids():
    s = SPEC.generate_spec(_rich_ledger(), {"nodes": [], "edges": []})
    for name, sec in s["sections"].items():
        assert isinstance(sec["bullets"], list), name
        for b in sec["bullets"]:
            assert "finding_ids" in b, f"{name}: bullet missing finding_ids"
            assert isinstance(b["finding_ids"], list)
            assert b["classification"] in SPEC.VALID_CLASS, \
                f"{name}: bad classification {b['classification']}"


def test_empty_ledger_marks_blocked_unverified():
    s = SPEC.generate_spec([], {"nodes": [], "edges": []})
    for name, sec in s["sections"].items():
        assert sec["status"] == "missing", f"{name} should be missing"
        assert all(b["classification"] in ("UNVERIFIED", "BLOCKED")
                   for b in sec["bullets"]), name
    # priorities must say the ledger is empty, not invent work
    prio_text = " ".join(b["text"] for b in s["sections"]["priorities"]["bullets"])
    assert "empty" in prio_text.lower()


def test_blocked_findings_surface_in_open_questions():
    s = SPEC.generate_spec(_rich_ledger(), {"nodes": [], "edges": []})
    oq = " ".join(b["text"] for b in
                  s["sections"]["open_questions"]["bullets"])
    assert "403" in oq or "Admin" in oq
    prio = " ".join(b["text"] for b in s["sections"]["priorities"]["bullets"])
    assert "P0" in prio  # blocked items are the critical path


def test_ledger_object_with_list_method():
    class FakeLedger:
        def list(self):
            return _rich_ledger()
    s = SPEC.generate_spec(FakeLedger(), None)
    assert s["meta"]["finding_count"] == 11


def test_graph_routes_merge():
    graph = {"nodes": [{"id": "route:/extra", "kind": "route",
                        "label": "/extra", "finding_id": None}],
             "edges": []}
    s = SPEC.generate_spec([], graph)
    texts = " ".join(b["text"] for b in s["sections"]["routes"]["bullets"])
    assert "/extra" in texts


def test_json_serializable():
    import json
    s = SPEC.generate_spec(_rich_ledger(), {"nodes": [], "edges": []})
    json.dumps(s)  # must not raise
