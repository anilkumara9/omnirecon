"""Tests for the deep-dive differentiators: consistency verification,
source-map recovery honesty, replay script generation, endpoint probing."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnirecon import deep_dive as DD  # noqa: E402
from omnirecon import server as SRV  # noqa: E402


def _mk_session(sid: str, findings: list[dict]) -> None:
    sdir = os.path.join(os.path.dirname(__file__), "..", "sessions", sid)
    os.makedirs(sdir, exist_ok=True)
    with open(os.path.join(sdir, "evidence.jsonl"), "w") as fh:
        for i, f in enumerate(findings):
            f = dict(f)
            f.setdefault("id", f"F-{i:04d}")
            fh.write(json.dumps(f) + "\n")


def test_consistency_flags_unrendered_routes():
    sid = "test-consistency"
    _mk_session(sid, [
        {"type": "route", "title": "Route /a", "route": "https://x.test/a",
         "classification": "OBSERVED"},
        {"type": "route", "title": "Route /b", "route": "https://x.test/b",
         "classification": "OBSERVED"},
        {"type": "page", "title": "Page /a", "route": "https://x.test/a",
         "classification": "OBSERVED"},
    ])
    res = DD.verify_consistency(sid)
    assert res["contradictions"] == 1, res
    fs = [json.loads(l) for l in
          open(os.path.join(os.path.dirname(__file__), "..", "sessions",
                            sid, "evidence.jsonl"))]
    contra = [f for f in fs if "Unrendered route" in f.get("title", "")]
    assert len(contra) == 1
    assert contra[0]["classification"] == "UNVERIFIED"
    assert "https://x.test/b" in contra[0]["title"]


def test_consistency_corroborates_dual_engine_endpoints():
    sid = "test-consistency-2"
    _mk_session(sid, [
        {"type": "endpoint", "title": "e1", "endpoint": "/api/x",
         "classification": "INFERRED", "engine": "static",
         "confidence_why": "static extraction from JS bundle"},
        {"type": "endpoint", "title": "e2", "endpoint": "/api/x",
         "classification": "OBSERVED", "engine": "network",
         "confidence_why": "observed in network capture"},
    ])
    res = DD.verify_consistency(sid)
    assert res["agreements"] == 1, res
    fs = [json.loads(l) for l in
          open(os.path.join(os.path.dirname(__file__), "..", "sessions",
                            sid, "evidence.jsonl"))]
    corr = [f for f in fs if "Corroborated endpoint" in f.get("title", "")]
    assert len(corr) == 1
    assert corr[0]["classification"] == "SOURCE_VERIFIED"
    assert corr[0]["confidence"] == 0.95


def test_consistency_empty_ledger():
    res = DD.verify_consistency("test-consistency-nonexistent")
    assert res["checked"] == 0


def test_replay_script_is_valid_python():
    steps = [
        {"action": "click 'Home' (link)", "observed": True,
         "url_after": "https://x.test/"},
        {"action": "click 'About' (link)", "observed": False,
         "url_after": ""},
    ]
    script = DD.build_replay_script(steps, "https://x.test")
    compile(script, "replay.py", "exec")
    assert "sync_playwright" in script
    assert "https://x.test" in script
    assert "STEPS" in script


def test_probe_endpoints_honest_on_empty():
    sid = "test-probe-empty"
    _mk_session(sid, [
        {"type": "note", "title": "nothing here",
         "classification": "OBSERVED"},
    ])
    res = DD.probe_endpoints(sid, "https://example.com")
    assert res["probed"] == 0
    assert res["live"] == 0 and res["dead"] == 0


def test_sourcemap_honesty_when_absent(monkeypatch):
    """When no .map resolves, the finding must say so (OBSERVED), not invent."""
    import httpx

    class FakeResp:
        status_code = 404
        text = ""

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            return FakeResp()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    sid = "test-sourcemap-absent"
    _mk_session(sid, [])
    res = DD.recover_sourcemaps(sid, "https://x.test",
                                script_urls=["https://x.test/app.js"])
    assert res["maps_found"] == []
    fs = [json.loads(l) for l in
          open(os.path.join(os.path.dirname(__file__), "..", "sessions",
                            sid, "evidence.jsonl"))]
    notes = [f for f in fs if "No source maps" in f.get("title", "")]
    assert len(notes) == 1
    assert notes[0]["classification"] == "OBSERVED"


def test_new_tools_registered():
    for name in ("recon_verify_consistency", "recon_recover_sourcemaps",
                 "recon_probe_endpoints"):
        assert callable(getattr(SRV, name)), name
