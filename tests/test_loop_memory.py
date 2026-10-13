"""Tests for the rebuild-loop memory upgrades (v1.33.0):
comparison persistence + trend, deviation evidence refs, build manifest.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnirecon import spec as SPEC  # noqa: E402
from omnirecon import verify as VERIFY  # noqa: E402
from omnirecon import server as SRV  # noqa: E402

SID = "test-loop-memory"


def _sdir():
    return os.path.join(os.path.dirname(__file__), "..", "sessions", SID)


def _write_ledger(findings):
    os.makedirs(_sdir(), exist_ok=True)
    with open(os.path.join(_sdir(), "evidence.jsonl"), "w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")


def _clean_comparisons():
    import shutil
    d = os.path.join(_sdir(), "comparisons")
    if os.path.exists(d):
        shutil.rmtree(d)


def _run(matched_routes, missing_routes, matched_eps, missing_eps,
         build_url="https://build.test"):
    return {
        "session_id": SID, "build_url": build_url,
        "checked_utc": "2026-10-13T00:00:00+00:00",
        "route_coverage": {"total": matched_routes + missing_routes,
                           "matched": matched_routes,
                           "missing": [f"/r{i}" for i in range(missing_routes)]},
        "endpoint_overlap": {
            "recorded": matched_eps + missing_eps,
            "matched": [f"/api/e{i}" for i in range(matched_eps)],
            "missing": [f"/api/m{i}" for i in range(missing_eps)]},
        "deviations": [],
    }


def test_persist_reload_round_trip():
    _clean_comparisons()
    res = _run(3, 2, 1, 1)
    path = VERIFY.save_comparison(SID, res)
    assert os.path.exists(path)
    assert path.endswith(".json")
    runs = VERIFY.list_comparisons(SID)
    assert len(runs) == 1
    assert runs[0]["route_coverage"]["matched"] == 3
    assert runs[0]["build_url"] == "https://build.test"


def test_trend_delta_computation():
    prev = _run(2, 3, 0, 2)   # missing /r0,/r1,/r2 and /api/m0,/api/m1
    cur = _run(4, 1, 2, 0)    # missing /r0 only; everything else fixed
    trend = VERIFY.compute_trend(cur, prev)
    assert trend["runs_compared"] == 2
    assert trend["routes_delta_matched"] == 2
    assert trend["endpoints_delta_matched"] == 2
    assert "/r1" in trend["fixed_since_last"]
    assert "/r2" in trend["fixed_since_last"]
    assert "/api/m0" in trend["fixed_since_last"]
    assert "/r0" in trend["still_missing"]
    assert trend["new_missing"] == []


def test_trend_new_missing_detected():
    prev = _run(3, 1, 1, 0)   # missing /r0
    cur = _run(2, 2, 1, 0)    # missing /r0,/r1 -> /r1 is new
    trend = VERIFY.compute_trend(cur, prev)
    assert trend["routes_delta_matched"] == -1
    assert trend["new_missing"] == ["/r1"]
    assert trend["fixed_since_last"] == []


def test_trend_no_previous_run_honest():
    trend = VERIFY.compute_trend(_run(1, 0, 0, 0), None)
    assert trend["previous_run"] is None
    assert trend["runs_compared"] == 1
    assert "baseline" in trend["note"].lower()


def test_deviation_evidence_refs_attached():
    _write_ledger([
        {"id": "F-0001", "type": "route", "title": "Route /about",
         "route": "https://ref.test/about", "classification": "OBSERVED",
         "sources": ["https://ref.test/about"]},
        {"id": "F-0002", "type": "endpoint", "title": "Endpoint /api/users",
         "endpoint": "/api/users", "classification": "OBSERVED",
         "sources": ["https://ref.test/openapi.json"]},
    ])
    result = {
        "route_coverage": {"total": 1, "matched": 0, "missing": ["/about"]},
        "endpoint_overlap": {"recorded": 1, "matched": [],
                             "missing": ["/api/users"]},
        "deviations": [
            {"kind": "missing_route", "severity": "high",
             "detail": "Recorded route /about not found in the build."},
            {"kind": "missing_endpoint", "severity": "high",
             "detail": "Recorded endpoint /api/users not observed in "
                       "the build's client surface."},
            {"kind": "extra_route", "severity": "info",
             "detail": "Build serves /extra, which was not recorded."},
        ],
    }
    out = SRV._attach_deviation_evidence(SID, result)
    by_kind = {d["kind"]: d for d in out["deviations"]}
    assert by_kind["missing_route"]["evidence_refs"]["finding_ids"] == ["F-0001"]
    assert by_kind["missing_endpoint"]["evidence_refs"]["finding_ids"] == ["F-0002"]
    assert by_kind["missing_endpoint"]["evidence_refs"]["sources"] == \
        ["https://ref.test/openapi.json"]
    # extra_route has no recorded finding -> no refs attached, no crash
    assert "evidence_refs" not in by_kind["extra_route"]


def _spec_fixture():
    findings = [
        {"id": "F-1", "type": "route", "title": "Route /a",
         "route": "https://x.test/a", "classification": "OBSERVED",
         "confidence": 0.9, "confidence_why": "crawled"},
        {"id": "F-2", "type": "route", "title": "Route /b",
         "route": "https://x.test/b", "classification": "UNVERIFIED",
         "confidence": 0.4, "confidence_why": "sitemap only"},
        {"id": "F-3", "type": "workflow", "title": "Signup flow",
         "detail": "visits https://x.test/a then submits",
         "route": "https://x.test/a", "classification": "OBSERVED",
         "confidence": 0.85, "confidence_why": "traced"},
        {"id": "F-4", "type": "note", "title": "Login wall hit",
         "classification": "BLOCKED", "confidence": 1.0,
         "confidence_why": "auth required",
         "limitations": "needs test credentials"},
    ]
    spec = SPEC.generate_spec(findings, None)
    graph = {
        "nodes": [
            {"id": "route:https://x.test/a", "kind": "route",
             "label": "https://x.test/a", "route": "https://x.test/a"},
            {"id": "route:https://x.test/b", "kind": "route",
             "label": "https://x.test/b", "route": "https://x.test/b"},
            {"id": "F-3", "kind": "workflow", "label": "Signup flow"},
        ],
        "edges": [{"from": "F-3", "to": "route:https://x.test/a",
                   "rel": "visits"}],
    }
    return spec, graph


def test_manifest_ordering_p0_first():
    spec, graph = _spec_fixture()
    manifest = SPEC.generate_manifest(spec, graph)
    assert manifest, "manifest must not be empty"
    prios = [t["priority"] for t in manifest]
    # P0 < P1 < P2 < P3 ordering holds across the whole list
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    assert prios == sorted(prios, key=lambda p: order[p])
    assert prios[0] == "P0"
    p0 = [t for t in manifest if t["priority"] == "P0"]
    assert any("F-4" in t["finding_ids"] for t in p0)
    # task shape is complete
    for t in manifest:
        assert set(t) >= {"id", "title", "section", "finding_ids",
                          "priority", "depends_on", "acceptance", "status"}
        assert t["status"] == "pending"
    # ids are dense and deterministic
    assert [t["id"] for t in manifest] == \
        [f"T-{i:03d}" for i in range(1, len(manifest) + 1)]
    # deterministic: same input -> same output
    assert SPEC.generate_manifest(spec, graph) == manifest


def test_manifest_depends_on_wiring():
    spec, graph = _spec_fixture()
    manifest = SPEC.generate_manifest(spec, graph)
    wf = [t for t in manifest
          if t["section"] == "user_journeys" and t["priority"] == "P3"]
    assert len(wf) == 1
    route_a = [t for t in manifest
               if t["section"] == "routes" and "https://x.test/a" in t["title"]]
    assert len(route_a) == 1
    assert route_a[0]["id"] in wf[0]["depends_on"], \
        "workflow must depend on the route it visits (graph edge)"
    route_b = [t for t in manifest
               if t["section"] == "routes" and "https://x.test/b" in t["title"]]
    assert route_b[0]["id"] not in wf[0]["depends_on"]


def test_manifest_empty_spec_honest():
    spec = SPEC.generate_spec([], None)
    manifest = SPEC.generate_manifest(spec, None)
    assert len(manifest) >= 1
    assert manifest[0]["priority"] == "P0"
    # empty ledger -> P0 task about the missing evidence (BLOCKED bullet or
    # the honest fallback), never an invented build plan
    assert ("Target unknown" in manifest[0]["title"]
            or "analysis pipeline" in manifest[0]["title"])


def test_manifest_p1_p2_present():
    spec, graph = _spec_fixture()
    manifest = SPEC.generate_manifest(spec, graph)
    p1 = [t for t in manifest if t["priority"] == "P1"]
    assert any("F-2" in t["finding_ids"] for t in p1), \
        "UNVERIFIED route finding needs a P1 verify task"
