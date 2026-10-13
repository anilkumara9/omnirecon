"""Tests for omnirecon.report exporters."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omnirecon import report as REPORT


def _make_session(tmp_path, sid="S-test001"):
    sdir = tmp_path / sid
    sdir.mkdir(parents=True)
    findings = [
        {"id": "F-0001", "type": "tech", "title": "Tech: Static HTML",
         "detail": "no framework markers", "classification": "INFERRED",
         "confidence": 0.7, "confidence_why": "t", "sources": ["https://x.test"],
         "route": None, "component": None, "endpoint": None, "artifact": None,
         "timestamp": "2026-10-12T00:00:00+00:00", "verification": "unverified",
         "limitations": ""},
        {"id": "F-0002", "type": "route", "title": "Route https://x.test/",
         "detail": "status=200", "classification": "OBSERVED", "confidence": 0.95,
         "confidence_why": "t", "sources": ["https://x.test/"],
         "route": "https://x.test/", "component": None, "endpoint": None,
         "artifact": None, "timestamp": "2026-10-12T00:00:00+00:00",
         "verification": "unverified", "limitations": ""},
        {"id": "F-0003", "type": "endpoint", "title": "Endpoint /api/things",
         "detail": "kind=api", "classification": "OBSERVED", "confidence": 0.9,
         "confidence_why": "t", "sources": ["https://x.test/"],
         "route": None, "component": None, "endpoint": "/api/things",
         "artifact": None, "timestamp": "2026-10-12T00:00:00+00:00",
         "verification": "unverified", "limitations": ""},
    ]
    (sdir / "evidence.jsonl").write_text(
        "\n".join(json.dumps(f) for f in findings) + "\n")
    session = {"id": sid, "target": "https://x.test", "target_kind": "url",
               "mode": "fast", "stage": 2, "status": "active"}
    (sdir / "session.json").write_text(json.dumps(session))
    return session


def test_export_markdown(tmp_path, monkeypatch):
    monkeypatch.setattr(REPORT, "SESSIONS_ROOT", tmp_path)
    session = _make_session(tmp_path)
    path, md = REPORT.export_markdown(session)
    assert Path(path).exists()
    assert path.endswith("report.md")
    for needle in ["# OmniRecon Report", "## Technology stack", "## Routes",
                   "## API endpoints", "## Workflows", "## Data entities",
                   "## Assets", "## Authentication", "## Open questions",
                   "## Limitations", "## Evidence appendix",
                   "F-0001", "F-0002", "F-0003", "/api/things"]:
        assert needle in md, f"missing {needle!r}"


def test_export_markdown_empty_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(REPORT, "SESSIONS_ROOT", tmp_path)
    sid = "S-empty"
    (tmp_path / sid).mkdir()
    session = {"id": sid, "target": "https://x.test", "target_kind": "url",
               "mode": "fast", "stage": 1, "status": "active"}
    _, md = REPORT.export_markdown(session)
    assert "_No routes discovered._" in md
    assert "_Ledger is empty._" in md


def test_export_json(tmp_path, monkeypatch):
    monkeypatch.setattr(REPORT, "SESSIONS_ROOT", tmp_path)
    session = _make_session(tmp_path, sid="S-test002")
    path, js = REPORT.export_json(session)
    assert Path(path).exists()
    payload = json.loads(js)
    assert payload["report"] == "omnirecon"
    assert len(payload["findings"]) == 3
    assert payload["session"]["id"] == "S-test002"
    assert payload["graph"] is None  # no graph.json written
    assert payload["spec"] is None


def test_export_requires_session_id(tmp_path, monkeypatch):
    monkeypatch.setattr(REPORT, "SESSIONS_ROOT", tmp_path)
    try:
        REPORT.export_markdown({})
        raise AssertionError("should have raised")
    except ValueError:
        pass
