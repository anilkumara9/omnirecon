"""Tests for the universal-target expansion: router, artifact intel,
API intel, and the REA bridge honesty contract."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnirecon.session import _detect_target_kind  # noqa: E402
from omnirecon import api_intel as AI  # noqa: E402
from omnirecon import artifact_intel as AR  # noqa: E402
from omnirecon import server as SRV  # noqa: E402


def test_router_url():
    assert _detect_target_kind("https://example.com") == ("url", "https://example.com")
    assert _detect_target_kind("example.com")[0] == "url"


def test_router_api_spec():
    k, t = _detect_target_kind("https://petstore.swagger.io/v2/swagger.json")
    assert k == "api_spec", k
    k, t = _detect_target_kind("https://api.example.com/openapi.json")
    assert k == "api_spec", k


def test_router_repo():
    assert _detect_target_kind("/tmp")[0] == "repo"
    k, t = _detect_target_kind("git@github.com:org/repo.git")
    assert k == "repo"


def test_router_artifact(tmp_path):
    p = tmp_path / "app.apk"
    p.write_bytes(b"PK\x03\x04fake")
    assert _detect_target_kind(str(p))[0] == "artifact"
    assert _detect_target_kind("/bin/ls")[0] == "artifact"


def test_router_invalid():
    try:
        _detect_target_kind("")
    except Exception as e:
        assert "empty" in str(e)
    else:
        raise AssertionError("expected ReconError")


def test_file_kind_elf():
    assert AR.file_kind("/bin/ls") == "elf"


def test_artifact_elf_honest():
    """ELF analysis must produce SOURCE_VERIFIED structure findings and a
    BLOCKED (not invented) note when REA providers are absent."""
    sid = "test-artifact-elf"
    sdir = os.path.join(os.path.dirname(__file__), "..", "sessions", sid)
    os.makedirs(sdir, exist_ok=True)
    led = os.path.join(sdir, "evidence.jsonl")
    if os.path.exists(led):
        os.remove(led)
    out = AR.analyze_artifact(sid, "/bin/ls")
    assert out["kind"] == "elf"
    assert out["format"] == "ELF"
    assert out["needed_libraries"], "expected shared-lib deps from readelf"
    findings = [json.loads(l) for l in open(led)]
    classes = {f["classification"] for f in findings}
    assert "SOURCE_VERIFIED" in classes
    # the REA bridge must never fake decompilation
    blocked = [f for f in findings if f["classification"] == "BLOCKED"]
    assert blocked, "expected honest BLOCKED note about decompilation"
    assert any("REA" in f["title"] or "decompil" in f["title"].lower()
               for f in blocked)


def test_rea_bridge_honest_when_missing(monkeypatch):
    monkeypatch.setattr(AR, "rea_cli_path", lambda: None)
    res = AR.rea_analyze("/bin/ls")
    assert res["ok"] is False
    assert res["reason"] == "rea-not-installed"
    assert "hint" in res


def test_ledger_to_openapi_provenance():
    findings = [
        {"id": "F-1", "type": "endpoint", "title": "Endpoint GET /pets",
         "endpoint": "GET /pets", "classification": "SOURCE_VERIFIED",
         "confidence": 0.95, "sources": ["https://api.example.com/openapi.json"]},
        {"id": "F-2", "type": "note", "title": "not an endpoint"},
        {"id": "F-3", "type": "endpoint", "title": "x",
         "endpoint": "POST /pets", "classification": "INFERRED",
         "confidence": 0.6, "sources": []},
    ]
    doc = AI.ledger_to_openapi(findings, title="T")
    assert doc["openapi"].startswith("3.1")
    assert "/pets" in doc["paths"]
    assert set(doc["paths"]["/pets"].keys()) == {"get", "post"}
    ev = doc["paths"]["/pets"]["post"]["x-omni-evidence"]
    assert ev["classification"] == "INFERRED"
    assert ev["finding_id"] == "F-3"


def test_analyze_api_spec_local():
    """api_intel must handle a local spec dict path gracefully."""
    res = AI.analyze_api_spec("http://127.0.0.1:1/swagger.json")
    assert res.get("error"), "unreachable host should produce an error, not raise"


def test_mcp_tool_registered():
    assert callable(SRV.recon_analyze_artifact)
    assert callable(SRV.recon_export_report)
