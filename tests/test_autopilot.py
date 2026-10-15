"""Tests for recon_auto_pilot: the one-shot full-pipeline tool."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omnirecon import server as SRV


def test_autopilot_quick_returns_spec():
    r = SRV.recon_auto_pilot("https://example.com", depth="quick", max_pages=1)
    assert "session_id" in r, f"autopilot failed: {r.get('error')}"
    assert "spec" in r or "error" in r
    assert "manifest" in r or "error" in r
    assert "tools_run" in r
    assert "recon_start" in r["tools_run"]
    assert "recon_generate_spec" in r["tools_run"]


def test_autopilot_graceful_degradation():
    # Even if browser tools fail (no browser in CI), pipeline completes
    r = SRV.recon_auto_pilot("https://example.com", depth="quick", max_pages=1)
    assert "session_id" in r
    # tools_failed is a list (may be non-empty in sandbox), not a crash
    assert isinstance(r.get("tools_failed", []), list)
    assert isinstance(r.get("tools_run", []), list)


def test_autopilot_manifest_structure():
    r = SRV.recon_auto_pilot("https://example.com", depth="quick", max_pages=1)
    m = r.get("manifest", {})
    assert "build_tasks" in m
    assert "research_tasks" in m
    assert "next_steps" in r
    assert "build_tasks" in r["next_steps"] or "Build" in r["next_steps"]


def test_autopilot_tool_registered():
    import asyncio
    tools = asyncio.run(SRV.mcp.list_tools())
    names = [t.name for t in tools]
    assert "recon_auto_pilot" in names
    t = [x for x in tools if x.name == "recon_auto_pilot"][0]
    # all params have descriptions (P0 UX fix)
    for pname, pspec in t.inputSchema["properties"].items():
        assert pspec.get("description"), f"{pname} missing description"
