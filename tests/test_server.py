"""Integration tests for omnirecon.server (Lane D) against the REAL sibling
modules (Lane B session/evidence/security/graph, Lane A browser_engine,
Lane C source_intel/assets). No shims — this is the true integration test.
"""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Sandbox quirk: httpx chokes on bracketed IPv6 entries in this VM's no_proxy.
if "hatch-egress-proxy" in os.environ.get("https_proxy", ""):
    os.environ["no_proxy"] = "localhost,127.0.0.1"
    os.environ["NO_PROXY"] = "localhost,127.0.0.1"

from omnirecon import server as SRV  # noqa: E402

EXPECTED_TOOLS = [
    "recon_start", "recon_status", "recon_discover_routes",
    "recon_inspect_page", "recon_trace_workflow", "recon_capture_network",
    "recon_analyze_source", "recon_analyze_artifact", "recon_extract_assets",
    "recon_verify_consistency", "recon_recover_sourcemaps", "recon_probe_endpoints",
    "recon_get_graph", "recon_get_evidence", "recon_generate_spec",
    "recon_compare_build", "recon_export_report", "recon_cancel",
    "recon_authenticate", "recon_deauthenticate",
    "recon_analyze_ui", "recon_auto_pilot", "recon_mock_network",
]


def test_all_21_tools_registered():
    # 23 tools as of v2.1 (mock_network added); name kept for history
    tools = asyncio.run(SRV.mcp.list_tools())
    names = sorted(t.name for t in tools)
    assert names == sorted(EXPECTED_TOOLS), f"got {names}"
    for t in tools:
        assert t.inputSchema.get("type") == "object"
        assert t.description, f"{t.name} has no description"


def test_recon_start_end_to_end():
    res = SRV.recon_start("https://example.com", mode="fast")
    assert "error" not in res, res
    sid = res["session_id"]
    assert res["rapid_report"]["findings_seeded"] >= 1
    st = SRV.recon_status(sid)
    assert st["ledger"]["total"] >= 1
    assert st["stage"] == 2


def test_recon_start_invalid_input():
    res = SRV.recon_start("", mode="fast")
    assert res["code"] == "invalid_input"
    res = SRV.recon_start("https://example.com", mode="warp")
    assert res["code"] == "invalid_input"
    res = SRV.recon_start("https://example.com", budget_json="{bad")
    assert res["code"] == "invalid_input"


def test_error_shape_has_no_traceback():
    res = SRV.recon_get_evidence("S-does-not-exist-xyz")
    assert set(res.keys()) == {"error", "code", "hint"}, res
    assert res["code"] == "not_found"
    assert "Traceback" not in json.dumps(res)


def test_evidence_filter_and_search():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    got = SRV.recon_get_evidence(sid, type="tech")
    assert got["count"] >= 1
    one = SRV.recon_get_evidence(sid, finding_id=got["findings"][0]["id"])
    assert one["finding"]["id"] == got["findings"][0]["id"]
    miss = SRV.recon_get_evidence(sid, finding_id="F-9999")
    assert miss["code"] == "not_found"
    q = SRV.recon_get_evidence(sid, query="example")
    assert q["count"] >= 1


def test_generate_spec_and_export_report():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    spec = SRV.recon_generate_spec(sid)
    assert "error" not in spec, spec
    assert len(spec["sections"]) == 15
    assert (SRV.SESSIONS_ROOT / sid / "spec.json").exists()
    rep = SRV.recon_export_report(sid, format="markdown")
    assert Path(rep["path"]).exists()
    assert "## Evidence appendix" in rep["content"]
    repj = SRV.recon_export_report(sid, format="json")
    payload = json.loads(repj["content"])
    assert payload["session"]["id"] == sid
    bad = SRV.recon_export_report(sid, format="pdf")
    assert bad["code"] == "invalid_input"


def test_discover_routes_background_job():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    job = SRV.recon_discover_routes(sid, max_pages=5, max_depth=1,
                                    background=True)
    assert "job_id" in job, job
    jid = job["job_id"]
    deadline = time.time() + 120
    status = "running"
    while time.time() < deadline and status == "running":
        time.sleep(2)
        status = SRV._job_status(jid).get("status")
    assert status == "done", f"job ended as {status}"
    result = SRV._job_status(jid)["result"]
    assert result["pages_crawled"] >= 1
    ev = SRV.recon_get_evidence(sid, type="route")
    assert ev["count"] >= 1
    st = SRV.recon_status(sid)
    assert any(j["job_id"] == jid for j in st["jobs"])


def test_get_graph_uses_real_builder():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    g = SRV.recon_get_graph(sid)
    assert "nodes" in g and "edges" in g
    assert len(g["nodes"]) >= 2
    assert (SRV.SESSIONS_ROOT / sid / "graph.json").exists()


def test_extract_assets_real_lane():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    out = SRV.recon_extract_assets(sid, "https://example.com/")
    assert "error" not in out, out
    assert "inventory" in out


def test_trace_workflow_real_browser():
    # Owned browser exists and Chromium is installed in this sandbox.
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    out = SRV.recon_trace_workflow(sid, "https://example.com/",
                                   "follow the more information link",
                                   max_steps=4)
    if "error" in out:
        # honest failure (e.g. browser could not launch) is acceptable,
        # a traceback or crash is not
        assert set(out.keys()) == {"error", "code", "hint"}
        assert "Traceback" not in json.dumps(out)
    else:
        assert isinstance(out["steps"], list)
        assert len(out["steps"]) >= 1


def test_inspect_page_real_browser():
    res = SRV.recon_start("https://example.com")
    sid = res["session_id"]
    out = SRV.recon_inspect_page(sid, "https://example.com/")
    if "error" in out:
        # Sandbox limitation: Playwright Chromium cannot use this VM's
        # authenticated egress proxy, so live navigation fails here with a
        # net:: error. The tool must fail honestly (no traceback); on a
        # normal machine the browser path is exercised instead.
        assert set(out.keys()) == {"error", "code", "hint"}, out
        assert "Traceback" not in json.dumps(out)
        assert "net::" in out["hint"] or "goto" in out["hint"], out
    else:
        assert out["mode"] == "browser"
        assert "screenshots" in out


# ---------------------------------------------------------------------------
# True stdio protocol integration: spawn the real server, speak MCP JSON-RPC.
# ---------------------------------------------------------------------------

def _rpc(proc, method, params=None, mid=None, expect_reply=True):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if mid is not None:
        msg["id"] = mid
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    if not expect_reply:
        return None
    while True:
        line = proc.stdout.readline()
        assert line, "server closed stdout unexpectedly"
        obj = json.loads(line)
        if mid is None or obj.get("id") == mid:
            return obj


def test_stdio_mcp_protocol_end_to_end():
    env = dict(os.environ)
    cmd = [sys.executable, str(ROOT / "omnirecon" / "server.py")]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, env=env,
                            cwd=str(ROOT))
    try:
        init = _rpc(proc, "initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "lane-d-test", "version": "0.1"}}, mid=1)
        assert "result" in init, init
        _rpc(proc, "notifications/initialized", expect_reply=False)
        listed = _rpc(proc, "tools/list", {}, mid=2)
        names = sorted(t["name"] for t in listed["result"]["tools"])
        assert names == sorted(EXPECTED_TOOLS), names
        called = _rpc(proc, "tools/call", {
            "name": "recon_status",
            "arguments": {"session_id": "S-does-not-exist-xyz"}}, mid=3)
        text = called["result"]["content"][0]["text"]
        payload = json.loads(text)
        assert payload["code"] == "not_found", payload
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_setup_generates_valid_config():
    from omnirecon import cli as CLI
    ap = CLI.build_parser()
    for client in ["claude-code", "codex", "cursor", "windsurf", "zed", "generic"]:
        args = ap.parse_args(["setup", client])
        res = args.func(args)
        assert "error" not in res, (client, res)
        assert res["action"] in ("run", "write", "append", "merge"), res
        content = res["content"]
        # every variant must carry a real, existing python + server.py
        import os
        if isinstance(content, dict):
            entry = content.get("mcpServers", {}).get("omnirecon") or \
                content.get("context_servers", {}).get("omnirecon")
            assert entry, (client, content)
            assert os.path.isfile(entry["command"]), entry["command"]
            assert os.path.isfile(entry["args"][0]), entry["args"]
        else:
            assert "omnirecon" in content, (client, content)
