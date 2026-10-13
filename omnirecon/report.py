"""Report exporter: Markdown + machine-readable JSON from a session.

export_markdown(session) -> (path, markdown_string)
export_json(session)     -> (path, json_string)

`session` is the session dict (must contain "id"). Findings are read from
sessions/<id>/evidence.jsonl, the graph from graph.json and the blueprint from
spec.json when present. Artifacts are written back into the session dir.
"""
from __future__ import annotations

import json
import datetime
from pathlib import Path

SESSIONS_ROOT = Path(__file__).resolve().parent.parent / "sessions"


def _sid_of(session) -> str | None:
    if isinstance(session, dict):
        return session.get("id")
    return getattr(session, "id", None)


def _session_dir(session_id: str) -> Path:
    # fixed layout per ARCHITECTURE.md §3 — no traversal possible (id is ours)
    return SESSIONS_ROOT / session_id


def _load_findings(session_id: str) -> list[dict]:
    p = _session_dir(session_id) / "evidence.jsonl"
    out = []
    if p.exists():
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except Exception:
                continue
    return out


def _load_json(session_id: str, name: str):
    p = _session_dir(session_id) / name
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _esc(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def export_markdown(session) -> tuple[str, str]:
    session_id = _sid_of(session)
    if not session_id:
        raise ValueError("session has no 'id'")
    findings = _load_findings(session_id)
    spec = _load_json(session_id, "spec.json")
    graph = _load_json(session_id, "graph.json")
    meta = session if isinstance(session, dict) else {}

    L: list[str] = []
    L.append(f"# OmniRecon Report — {session_id}")
    L.append("")
    L.append(f"- **Target:** {_esc(meta.get('target', 'unknown'))} "
             f"({meta.get('target_kind', '?')}, mode={meta.get('mode', '?')})")
    L.append(f"- **Stage:** {meta.get('stage', '?')} · "
             f"**Status:** {meta.get('status', '?')}")
    L.append(f"- **Findings:** {len(findings)} · "
             f"**Generated:** {_utcnow()}")
    L.append("")

    # summary
    L.append("## Summary")
    if spec:
        sec = spec.get("sections", {}).get("overview", {})
        for b in sec.get("bullets", []):
            L.append(f"- {b.get('text', '')}")
    else:
        L.append("- No reconstruction blueprint generated yet "
                 "(`recon_generate_spec`).")
    L.append("")

    # tech
    L.append("## Technology stack")
    tech = [f for f in findings if f.get("type") == "tech"]
    if tech:
        L.append("| Finding | Classification | Confidence | Evidence |")
        L.append("|---|---|---|---|")
        for f in tech:
            L.append(f"| {_esc(f.get('id'))} | {f.get('classification')} | "
                     f"{f.get('confidence')} | {_esc(f.get('detail'))} |")
    else:
        L.append("_No tech-stack findings recorded._")
    L.append("")

    # routes
    L.append("## Routes")
    routes = [f for f in findings if f.get("type") == "route"]
    if routes:
        L.append("| ID | Route | Classification | Detail |")
        L.append("|---|---|---|---|")
        for f in routes:
            L.append(f"| {_esc(f.get('id'))} | `{_esc(f.get('route') or '')}` | "
                     f"{f.get('classification')} | {_esc(f.get('detail'))} |")
    else:
        L.append("_No routes discovered._")
    L.append("")

    # endpoints
    L.append("## API endpoints")
    eps = [f for f in findings if f.get("type") == "endpoint"]
    if eps:
        L.append("| ID | Endpoint | Classification | Confidence |")
        L.append("|---|---|---|---|")
        for f in eps:
            L.append(f"| {_esc(f.get('id'))} | `{_esc(f.get('endpoint') or '')}` | "
                     f"{f.get('classification')} | {f.get('confidence')} |")
    else:
        L.append("_No endpoints recorded._")
    L.append("")

    # workflows
    L.append("## Workflows")
    flows = [f for f in findings if f.get("type") == "workflow"]
    if flows:
        for f in flows:
            L.append(f"- **{_esc(f.get('id'))}** [{f.get('classification')}] "
                     f"{_esc(f.get('title'))} — {_esc(f.get('detail'))}")
    else:
        L.append("_No workflows traced._")
    L.append("")

    # entities
    L.append("## Data entities (inferred)")
    ents = [f for f in findings if f.get("type") == "entity"]
    if ents:
        for f in ents:
            L.append(f"- **{_esc(f.get('id'))}** [{f.get('classification')}] "
                     f"{_esc(f.get('title'))} — {_esc(f.get('detail'))}")
    else:
        L.append("_No data entities inferred._")
    L.append("")

    # assets
    L.append("## Assets & design tokens")
    assets = [f for f in findings if f.get("type") == "asset"]
    if assets:
        for f in assets:
            L.append(f"- **{_esc(f.get('id'))}** {_esc(f.get('title'))} — "
                     f"{_esc(f.get('detail'))}")
    else:
        L.append("_No asset inventory._")
    L.append("")

    # auth
    L.append("## Authentication & access boundaries")
    auth = [f for f in findings if f.get("type") == "auth"]
    if auth:
        for f in auth:
            L.append(f"- **{_esc(f.get('id'))}** [{f.get('classification')}] "
                     f"{_esc(f.get('title'))} — {_esc(f.get('detail'))}")
    else:
        L.append("_No auth evidence — access boundaries UNVERIFIED._")
    L.append("")

    # open questions
    L.append("## Open questions")
    if spec:
        for b in spec.get("sections", {}).get("open_questions", {}).get("bullets", []):
            ids = ", ".join(b.get("finding_ids", []))
            L.append(f"- {b.get('text', '')}"
                     + (f" _(refs: {ids})_" if ids else ""))
    else:
        L.append("_Generate the spec to populate open questions._")
    L.append("")

    # limitations
    L.append("## Limitations")
    L.append("- Findings marked INFERRED/UNVERIFIED are hypotheses, not facts.")
    L.append("- Endpoints listed are *observed* client-side calls; backend "
             "schemas are not verified unless SOURCE_VERIFIED.")
    L.append("- Authenticated areas were not entered without explicit "
             "authorization.")
    if graph:
        L.append(f"- Graph: {len(graph.get('nodes', []))} nodes, "
                 f"{len(graph.get('edges', []))} edges.")
    L.append("")

    # evidence appendix
    L.append("## Evidence appendix")
    if findings:
        L.append("| ID | Type | Classification | Conf | Title | Sources |")
        L.append("|---|---|---|---|---|---|")
        for f in findings:
            srcs = ", ".join(str(s) for s in (f.get("sources") or [])[:2])
            L.append(f"| {_esc(f.get('id'))} | {f.get('type')} | "
                     f"{f.get('classification')} | {f.get('confidence')} | "
                     f"{_esc(f.get('title'))} | {_esc(srcs)} |")
    else:
        L.append("_Ledger is empty._")

    md = "\n".join(L) + "\n"
    out_path = _session_dir(session_id) / "report.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md)
    return str(out_path), md


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def export_json(session) -> tuple[str, str]:
    session_id = _sid_of(session)
    if not session_id:
        raise ValueError("session has no 'id'")
    findings = _load_findings(session_id)
    payload = {
        "report": "omnirecon",
        "generated_utc": _utcnow(),
        "session": session if isinstance(session, dict)
        else {"id": session_id},
        "findings": findings,
        "graph": _load_json(session_id, "graph.json"),
        "spec": _load_json(session_id, "spec.json"),
    }
    js = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    out_path = _session_dir(session_id) / "report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(js)
    return str(out_path), js
