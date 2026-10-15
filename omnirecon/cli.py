#!/usr/bin/env python3
"""OmniRecon CLI — terminal mirror of the MCP tool surface.

REA-inspired CLI/MCP parity: every subcommand calls the *exact same function*
the MCP server exposes (imported from omnirecon.server), so terminal runs and
agent runs can never diverge.

Usage:
    ~/workspace/venvs/recon/bin/python -m omnirecon.cli recon-start https://example.com --mode fast
    ~/workspace/venvs/recon/bin/python -m omnirecon.cli recon-status <session-id>
    ~/workspace/venvs/recon/bin/python -m omnirecon.cli recon-generate-spec <session-id>

All output is JSON on stdout. Exit code is 1 when the result carries "error".
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Make `import omnirecon...` work both as `python -m omnirecon.cli` (project
# root on sys.path already) and as `python omnirecon/cli.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omnirecon import server as SRV  # noqa: E402


def _emit(result: dict) -> int:
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 1 if isinstance(result, dict) and result.get("error") else 0


def _add_session_arg(p: argparse.ArgumentParser):
    p.add_argument("session", help="session id returned by recon-start")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="omnirecon",
        description="OmniRecon reverse-engineering CLI (mirrors the MCP tools).",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("recon-start", help="Start a session: validate target + rapid recon.")
    p.add_argument("target", help="URL (https://…) or local repo path")
    p.add_argument("--mode", choices=("fast", "thorough"), default="fast")
    p.add_argument("--budget", default="{}",
                   help='JSON budget object, e.g. \'{"max_pages": 40}\'')
    p.set_defaults(func=lambda a: SRV.recon_start(a.target, a.mode, a.budget))

    p = sub.add_parser("auto-pilot",
                       help="AUTOPILOT: full pipeline in one call — recon → inspect → spec.")
    p.add_argument("target", help="URL (https://…) or local repo path")
    p.add_argument("--depth", choices=("quick", "standard", "deep"),
                   default="standard")
    p.add_argument("--max-pages", type=int, default=5)
    p.set_defaults(func=lambda a: SRV.recon_auto_pilot(
        a.target, a.depth, a.max_pages))

    p = sub.add_parser("mock-network",
                       help="Mock API responses to reveal edge-state UI.")
    p.add_argument("--session", required=True)
    p.add_argument("url", help="Page URL to load and mock")
    p.add_argument("--scenario",
                   choices=("api_down", "slow", "empty", "unauthorized"),
                   default="api_down")
    p.add_argument("--url-pattern", default="**/api/*")
    p.set_defaults(func=lambda a: SRV.recon_mock_network(
        a.session, a.url, a.scenario, a.url_pattern))

    p = sub.add_parser("trace-signatures",
                       help="Trace how sign=/token= params are computed (live JS hooking).")
    p.add_argument("--session", required=True)
    p.add_argument("url", help="Page URL to load with crypto hooks armed")
    p.add_argument("--wait-ms", type=int, default=9000,
                   help="Observation window after load, in ms")
    p.set_defaults(func=lambda a: SRV.recon_trace_signatures(
        a.session, a.url, a.wait_ms))

    p = sub.add_parser("recon-status", help="Stage, progress, jobs, ledger stats.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_status(a.session))

    p = sub.add_parser("recon-discover-routes", help="Crawl internal routes + endpoint index.")
    _add_session_arg(p)
    p.add_argument("--max-pages", type=int, default=40)
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--background", action="store_true",
                   help="run the crawl as a background job; poll with recon-status")
    p.set_defaults(func=lambda a: SRV.recon_discover_routes(
        a.session, a.max_pages, a.max_depth, a.background))

    p = sub.add_parser("recon-inspect-page", help="Deep-inspect one page (DOM, controls, screenshots).")
    _add_session_arg(p)
    p.add_argument("url")
    p.set_defaults(func=lambda a: SRV.recon_inspect_page(a.session, a.url))

    p = sub.add_parser("recon-trace-workflow", help="Bounded user-journey exploration.")
    _add_session_arg(p)
    p.add_argument("start_url")
    p.add_argument("--goal", required=True, help="what the journey is trying to reach/do")
    p.add_argument("--max-steps", type=int, default=15)
    p.set_defaults(func=lambda a: SRV.recon_trace_workflow(
        a.session, a.start_url, a.goal, a.max_steps))

    p = sub.add_parser("recon-capture-network", help="Capture real XHR/fetch traffic (redacted).")
    _add_session_arg(p)
    p.add_argument("url")
    p.add_argument("--duration-ms", type=int, default=8000)
    p.set_defaults(func=lambda a: SRV.recon_capture_network(
        a.session, a.url, a.duration_ms))

    p = sub.add_parser("recon-analyze-source", help="Analyze a local codebase or git repo URL.")
    _add_session_arg(p)
    p.add_argument("path_or_repo_url")
    p.set_defaults(func=lambda a: SRV.recon_analyze_source(a.session, a.path_or_repo_url))

    p = sub.add_parser("recon-analyze-artifact", help="Analyze an APK/IPA/native binary/JS bundle.")
    _add_session_arg(p)
    p.add_argument("path")
    p.set_defaults(func=lambda a: SRV.recon_analyze_artifact(a.session, a.path))

    p = sub.add_parser("recon-verify-consistency", help="Cross-check findings between engines.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_verify_consistency(a.session))

    p = sub.add_parser("recon-recover-sourcemaps", help="Recover original source tree from .js.map files.")
    _add_session_arg(p)
    p.add_argument("page_url")
    p.set_defaults(func=lambda a: SRV.recon_recover_sourcemaps(a.session, a.page_url))

    p = sub.add_parser("recon-probe-endpoints", help="Live-probe discovered API endpoints.")
    _add_session_arg(p)
    p.add_argument("--base-url", default="")
    p.set_defaults(func=lambda a: SRV.recon_probe_endpoints(a.session, a.base_url))

    p = sub.add_parser("recon-extract-assets", help="Inventory images, fonts, design tokens.")
    _add_session_arg(p)
    p.add_argument("url")
    p.set_defaults(func=lambda a: SRV.recon_extract_assets(a.session, a.url))

    p = sub.add_parser("recon-analyze-ui", help="Designer-grade UI analysis: computed tokens, components, frameworks.")
    _add_session_arg(p)
    p.add_argument("url")
    p.set_defaults(func=lambda a: SRV.recon_analyze_ui(a.session, a.url))

    p = sub.add_parser("recon-get-graph", help="Route/component/API dependency graph.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_get_graph(a.session))

    p = sub.add_parser("recon-get-evidence", help="Query the evidence ledger.")
    _add_session_arg(p)
    p.add_argument("--finding-id", default="")
    p.add_argument("--type", default="")
    p.add_argument("--classification", default="")
    p.add_argument("--query", default="")
    p.set_defaults(func=lambda a: SRV.recon_get_evidence(
        a.session, a.finding_id, a.type, a.classification, a.query))

    p = sub.add_parser("recon-generate-spec", help="Generate the 15-section reconstruction blueprint.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_generate_spec(a.session))

    p = sub.add_parser("recon-compare-build", help="Compare a rebuilt implementation vs reference.")
    _add_session_arg(p)
    p.add_argument("build_url")
    p.set_defaults(func=lambda a: SRV.recon_compare_build(a.session, a.build_url))

    p = sub.add_parser("recon-export-report", help="Export Markdown or JSON report.")
    _add_session_arg(p)
    p.add_argument("--format", choices=("markdown", "json", "openapi"), default="markdown")
    p.add_argument("--out", default="",
                   help="also write the report content to this file")
    def _export(a):
        res = SRV.recon_export_report(a.session, a.format)
        if not res.get("error") and a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(res.get("content", ""))
            res = dict(res)
            res["written_to"] = os.path.abspath(a.out)
        return res
    p.set_defaults(func=_export)

    p = sub.add_parser("recon-cancel", help="Stop a session safely.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_cancel(a.session))

    p = sub.add_parser("recon-authenticate", help="Log in with your own credentials; save session cookies.")
    _add_session_arg(p)
    p.add_argument("login_url")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("--username-selector", default="")
    p.add_argument("--password-selector", default="")
    p.add_argument("--submit-selector", default="")
    p.set_defaults(func=lambda a: SRV.recon_authenticate(
        a.session, a.login_url, a.username, a.password,
        a.username_selector, a.password_selector, a.submit_selector))

    p = sub.add_parser("recon-deauthenticate", help="Delete saved session cookies.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_deauthenticate(a.session))

    p = sub.add_parser("setup", help="Generate MCP client config with correct paths (no copy-paste errors).")
    p.add_argument("client", choices=["claude-code", "codex", "cursor", "windsurf", "zed", "generic"],
                   help="Which agent/IDE to configure.")
    p.add_argument("--project", default="",
                   help="For claude-code: project dir to scope the config to (writes .mcp.json there).")
    p.set_defaults(func=_setup_client)

    return ap


def _setup_client(a) -> dict:
    """Generate MCP config with auto-detected absolute paths.

    Eliminates the #1 first-run failure: wrong paths in the client config.
    """
    import shutil

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_py = os.path.join(root, "omnirecon", "server.py")
    # Prefer the venv Python next to the project, else the current interpreter.
    venv_py = os.path.join(root, ".venv", "bin", "python")
    if os.name == "nt":
        venv_py = os.path.join(root, ".venv", "Scripts", "python.exe")
    python = venv_py if os.path.isfile(venv_py) else sys.executable

    problems = []
    if not os.path.isfile(server_py):
        problems.append(f"server.py not found at {server_py}")
    if not os.path.isfile(python):
        problems.append(f"python not found at {python} — run ./install.sh first")
    if problems:
        return {"error": "; ".join(problems), "code": "setup_failed",
                "hint": "Run ./install.sh (or install.bat on Windows) first."}

    entry = {"command": python, "args": [server_py]}
    client = a.client

    if client == "claude-code":
        # Prefer the CLI if available; fall back to printing the JSON.
        claude = shutil.which("claude")
        if claude and not a.project:
            return {"action": "run",
                    "command": [claude, "mcp", "add", "omnirecon", "--",
                                python, server_py],
                    "note": "Run this command to register OmniRecon with Claude Code."}
        cfg = {"mcpServers": {"omnirecon": entry}}
        target = os.path.join(a.project or root, ".mcp.json")
        return {"action": "write", "path": target,
                "content": cfg,
                "note": f"Write this JSON to {target} (project-scoped for Claude Code)."}

    if client == "codex":
        snippet = ("[mcp_servers.omnirecon]\n"
                   f"command = \"{python}\"\n"
                   f"args = [\"{server_py}\"]\n")
        return {"action": "append",
                "path": os.path.expanduser("~/.codex/config.toml"),
                "content": snippet,
                "note": "Add to ~/.codex/config.toml, then restart Codex."}

    if client == "zed":
        cfg = {"context_servers": {"omnirecon": entry}}
        return {"action": "merge",
                "path": os.path.expanduser("~/.config/zed/settings.json"),
                "content": cfg,
                "note": "Merge context_servers into your Zed settings.json, then restart Zed."}

    # cursor / windsurf / generic: same mcpServers shape, different homes
    homes = {"cursor": os.path.expanduser("~/.cursor/mcp.json"),
             "windsurf": os.path.expanduser("~/.codeium/windsurf/mcp_config.json"),
             "generic": "<your-client-mcp-config.json>"}
    cfg = {"mcpServers": {"omnirecon": entry}}
    return {"action": "merge",
            "path": homes[client],
            "content": cfg,
            "note": f"Merge mcpServers into {homes[client]}, then restart {client}."}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = args.func(args)
    except Exception as e:  # noqa: BLE001 — CLI must never dump a traceback
        result = {"error": f"command failed: {e}", "code": "internal"}
    if not isinstance(result, dict):
        result = {"result": result}
    return _emit(result)


if __name__ == "__main__":
    sys.exit(main())
