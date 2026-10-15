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

    p = sub.add_parser("setup", help="Configure your agent to use OmniRecon (writes the config for you).")
    p.add_argument("client", choices=["claude-code", "codex", "cursor", "windsurf", "zed", "generic", "auto"],
                   help="Which agent/IDE to configure; 'auto' configures every client found on this machine.")
    p.add_argument("--project", default="",
                   help="For claude-code: project dir to scope the config to (writes .mcp.json there). Defaults to the current directory.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what would be done without writing anything.")
    p.set_defaults(func=_setup_client)

    return ap


def _detect_clients() -> list:
    """Best-effort detection of installed agent clients."""
    import shutil
    found = []
    if shutil.which("claude"):
        found.append("claude-code")
    home = os.path.expanduser("~")
    if os.path.isdir(os.path.join(home, ".codex")):
        found.append("codex")
    if shutil.which("cursor") or os.path.isdir(os.path.join(home, ".cursor")):
        found.append("cursor")
    if os.path.isdir(os.path.join(home, ".codeium")):
        found.append("windsurf")
    if shutil.which("zed") or os.path.isfile(
            os.path.join(home, ".config", "zed", "settings.json")):
        found.append("zed")
    return found


def _merge_mcp_json(path: str, key: str, entry: dict,
                    dry_run: bool = False) -> dict:
    """Merge {"<key>": {"omnirecon": entry}} into a JSON config file.

    Idempotent: a second run changes nothing. An unparseable existing file
    is backed up (.omnirecon.bak) rather than destroyed.
    """
    import json
    action = {"path": path}
    cfg = {}
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read().strip()
            cfg = json.loads(raw) if raw else {}
        except Exception:
            bak = path + ".omnirecon.bak"
            import shutil
            shutil.copy2(path, bak)
            action["backup"] = bak
            cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    servers = cfg.get(key)
    if not isinstance(servers, dict):
        servers = {}
        cfg[key] = servers
    if servers.get("omnirecon") == entry:
        action["changed"] = False
        action["note"] = "already configured"
        return action
    if dry_run:
        action["changed"] = True
        action["note"] = "dry-run: would write"
        action["content"] = {key: {"omnirecon": entry}}
        return action
    servers["omnirecon"] = entry
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    action["changed"] = True
    action["note"] = "written"
    return action


def _ensure_codex_toml(path: str, python: str, server_py: str,
                       dry_run: bool = False) -> dict:
    """Append the omnirecon server block to Codex's config.toml (idempotent)."""
    action = {"path": path}
    snippet = ("[mcp_servers.omnirecon]\n"
               f"command = \"{python}\"\n"
               f"args = [\"{server_py}\"]\n")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            if "[mcp_servers.omnirecon]" in fh.read():
                action["changed"] = False
                action["note"] = "already configured"
                return action
    if dry_run:
        action["changed"] = True
        action["note"] = "dry-run: would append"
        action["content"] = snippet
        return action
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    needs_nl = os.path.isfile(path) and os.path.getsize(path) > 0
    with open(path, "a", encoding="utf-8") as fh:
        if needs_nl:
            fh.write("\n")
        fh.write(snippet)
    action["changed"] = True
    action["note"] = "appended"
    return action


def _setup_one_client(client: str, python: str, server_py: str,
                      project: str, dry_run: bool) -> dict:
    """Configure a single client. Returns a result dict for that client."""
    import shutil
    import subprocess
    home = os.path.expanduser("~")
    entry = {"command": python, "args": [server_py]}

    if client == "claude-code":
        claude = shutil.which("claude")
        if claude:
            cmd = [claude, "mcp", "add", "omnirecon", "--", python, server_py]
            if dry_run:
                return {"client": client, "changed": True,
                        "note": "dry-run: would run: " + " ".join(cmd)}
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=60)
            except Exception as e:
                return {"client": client, "changed": False,
                        "error": f"could not run 'claude mcp add': {e}"}
            if proc.returncode == 0:
                return {"client": client, "changed": True,
                        "note": "registered via 'claude mcp add'",
                        "restart": "restart Claude Code"}
            return {"client": client, "changed": False,
                    "error": (proc.stderr or proc.stdout or
                              "'claude mcp add' failed")[:300]}
        target = os.path.join(project or os.getcwd(), ".mcp.json")
        res = _merge_mcp_json(target, "mcpServers", entry, dry_run)
        res["client"] = client
        res["restart"] = "restart Claude Code (project .mcp.json is picked up automatically)"
        return res

    if client == "codex":
        res = _ensure_codex_toml(os.path.join(home, ".codex", "config.toml"),
                                 python, server_py, dry_run)
        res["client"] = client
        res["restart"] = "restart Codex"
        return res

    if client == "zed":
        res = _merge_mcp_json(
            os.path.join(home, ".config", "zed", "settings.json"),
            "context_servers", entry, dry_run)
        res["client"] = client
        res["restart"] = "restart Zed"
        return res

    homes = {"cursor": os.path.join(home, ".cursor", "mcp.json"),
             "windsurf": os.path.join(home, ".codeium", "windsurf",
                                      "mcp_config.json")}
    if client in homes:
        res = _merge_mcp_json(homes[client], "mcpServers", entry, dry_run)
        res["client"] = client
        res["restart"] = f"restart {client}"
        return res

    # generic: nothing to write to; print the block.
    return {"client": client, "changed": False,
            "note": "add this to your MCP client's config, then restart it",
            "content": {"mcpServers": {"omnirecon": entry}}}


def _setup_client(a) -> dict:
    """Configure agent client(s) to use OmniRecon — actually writes the
    config files, so setup is one command with no manual JSON editing.

    Eliminates the #1 first-run failure: wrong paths in the client config
    (paths are auto-detected from this install).
    """
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

    clients = _detect_clients() if a.client == "auto" else [a.client]
    if a.client == "auto" and not clients:
        return {"error": "no supported agent client detected",
                "code": "setup_failed",
                "hint": "Install Claude Code, Codex, Cursor, Windsurf or Zed, "
                        "or run with an explicit client name."}
    results = [_setup_one_client(c, python, server_py, a.project, a.dry_run)
               for c in clients]
    ok = [r for r in results if r.get("changed")]
    return {"ok": True, "clients": results,
            "summary": f"{len(ok)}/{len(results)} client(s) configured",
            "dry_run": bool(a.dry_run)}


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
