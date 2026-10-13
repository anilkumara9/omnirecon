"""Tests for omnirecon.verify.compare_build against the local fixture site."""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omnirecon import verify as VERIFY

FIXTURE = ROOT / "benchmarks" / "fixtures" / "static-site"
PORT = 8141


def _serve():
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
        cwd=str(FIXTURE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("fixture server did not start")


def _seed_session(sdir: Path, sid: str):
    sdir.mkdir(parents=True, exist_ok=True)
    findings = [
        {"id": "F-0001", "type": "route", "title": "Route /",
         "detail": "home", "classification": "OBSERVED", "confidence": 0.9,
         "confidence_why": "t", "sources": [], "route": "/",
         "component": None, "endpoint": None, "artifact": None,
         "timestamp": "2026-10-12T00:00:00+00:00", "verification": "unverified",
         "limitations": ""},
        {"id": "F-0002", "type": "route", "title": "Route /about.html",
         "detail": "about", "classification": "OBSERVED", "confidence": 0.9,
         "confidence_why": "t", "sources": [], "route": "/about.html",
         "component": None, "endpoint": None, "artifact": None,
         "timestamp": "2026-10-12T00:00:00+00:00", "verification": "unverified",
         "limitations": ""},
        {"id": "F-0003", "type": "route", "title": "Route /missing.html",
         "detail": "recorded but absent from build", "classification": "OBSERVED",
         "confidence": 0.9, "confidence_why": "t", "sources": [],
         "route": "/missing.html", "component": None, "endpoint": None,
         "artifact": None, "timestamp": "2026-10-12T00:00:00+00:00",
         "verification": "unverified", "limitations": ""},
        {"id": "F-0004", "type": "endpoint", "title": "Endpoint /api/products",
         "detail": "kind=api", "classification": "OBSERVED", "confidence": 0.9,
         "confidence_why": "t", "sources": [], "route": None, "component": None,
         "endpoint": "/api/products", "artifact": None,
         "timestamp": "2026-10-12T00:00:00+00:00", "verification": "unverified",
         "limitations": ""},
    ]
    (sdir / "evidence.jsonl").write_text(
        "\n".join(json.dumps(f) for f in findings) + "\n")


def test_compare_build_against_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(VERIFY, "SESSIONS_ROOT", tmp_path)
    sid = "S-verify1"
    _seed_session(tmp_path / sid, sid)
    proc = _serve()
    try:
        res = VERIFY.compare_build(sid, f"http://127.0.0.1:{PORT}/")
    finally:
        proc.terminate()
    rc = res["route_coverage"]
    assert rc["total"] == 3, rc
    assert rc["matched"] >= 2, rc  # / and /about.html exist in the build
    assert "/missing.html" in rc["missing"]
    assert any(d["kind"] == "missing_route" and d["severity"] == "high"
               for d in res["deviations"])
    # /api/products is client-declared in app.js -> found in build surface
    eo = res["endpoint_overlap"]
    assert "/api/products" in eo["matched"], eo
    assert "screenshot" in res["screenshot_notes"].lower()
    assert "pixel" in res["screenshot_notes"].lower()  # honest scope note


def test_compare_build_empty_session(tmp_path, monkeypatch):
    monkeypatch.setattr(VERIFY, "SESSIONS_ROOT", tmp_path)
    sid = "S-empty"
    (tmp_path / sid).mkdir()
    res = VERIFY.compare_build(sid, "http://127.0.0.1:9/")
    assert res["route_coverage"]["total"] == 0
    assert "nothing to compare" in res["screenshot_notes"]


def test_compare_build_unreachable_build(tmp_path, monkeypatch):
    monkeypatch.setattr(VERIFY, "SESSIONS_ROOT", tmp_path)
    sid = "S-unreach"
    _seed_session(tmp_path / sid, sid)
    # nothing listens on port 9 -> crawl fails gracefully, no crash
    res = VERIFY.compare_build(sid, "http://127.0.0.1:9/")
    assert res["route_coverage"]["matched"] == 0
    assert len(res["route_coverage"]["missing"]) == 3
