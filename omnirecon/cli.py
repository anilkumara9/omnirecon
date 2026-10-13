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

    p = sub.add_parser("recon-status", help="Stage, progress, jobs, ledger stats.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_status(a.session))

    p = sub.add_parser("recon-discover-routes", help="Crawl internal routes + endpoint index.")
    _add_session_arg(p)
    p.add_argument("--max-pages", type=int, default=40)
    p.add_argument("--max-depth", type=int, default=3)
    p.set_defaults(func=lambda a: SRV.recon_discover_routes(
        a.session, a.max_pages, a.max_depth))

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

    p = sub.add_parser("recon-extract-assets", help="Inventory images, fonts, design tokens.")
    _add_session_arg(p)
    p.add_argument("url")
    p.set_defaults(func=lambda a: SRV.recon_extract_assets(a.session, a.url))

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

    p = sub.add_parser("recon-generate-spec", help="Generate the 14-section reconstruction blueprint.")
    _add_session_arg(p)
    p.set_defaults(func=lambda a: SRV.recon_generate_spec(a.session))

    p = sub.add_parser("recon-compare-build", help="Compare a rebuilt implementation vs reference.")
    _add_session_arg(p)
    p.add_argument("build_url")
    p.set_defaults(func=lambda a: SRV.recon_compare_build(a.session, a.build_url))

    p = sub.add_parser("recon-export-report", help="Export Markdown or JSON report.")
    _add_session_arg(p)
    p.add_argument("--format", choices=("markdown", "json"), default="markdown")
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

    return ap


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
