#!/usr/bin/env python3
"""OmniRecon MCP server — session-based, evidence-driven reverse engineering.

Run:
    ~/workspace/venvs/recon/bin/python ~/workspace/omnirecon/omnirecon/server.py
Transport: stdio. FastMCP name: "omnirecon".

Sibling modules (evidence, session, security, graph, browser_engine,
source_intel, assets) are owned by other lanes and imported lazily: every tool
degrades to an honest {"error","code","hint"} dict when a module is missing,
never a traceback.
"""
from __future__ import annotations

from typing import Annotated

import datetime
import importlib
import json
import os
import sys
import threading
import uuid
from pathlib import Path

# Make `import omnirecon...` work when launched as `python omnirecon/server.py`
# (script dir, not the project root, lands on sys.path in that case).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pydantic import Field
from mcp.server.fastmcp import FastMCP  # noqa: E402

from omnirecon import recon_primitives as RP
from omnirecon import spec as SPEC
from omnirecon import report as REPORT
from omnirecon import verify as VERIFY

mcp = FastMCP("omnirecon")

SESSIONS_ROOT = Path(__file__).resolve().parent.parent / "sessions"
VALID_CLASS = ("OBSERVED", "SOURCE_VERIFIED", "INFERRED", "UNVERIFIED", "BLOCKED")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _err(message: str, code: str = "internal", hint: str = "") -> dict:
    return {"error": message, "code": code, "hint": hint}


# Output contract: every tool tells the agent what it knows, what it
# doesn't, and what got cut. Stolen from REA's evidence-plus-unknowns,
# fixed with budgeting (REA's #1 complaint is context thrashing).
_MAX_RESPONSE_CHARS = 120_000  # ~30k tokens; prevents context death

def _contract(result: dict, unknowns: list[str] | None = None,
              limitations: list[str] | None = None) -> dict:
    """Wrap a tool result with the output contract.

    - unknowns: what the tool tried but couldn't resolve
    - limitations: what the results can't guarantee
    - truncated: whether the payload was cut by the budget
    """
    if not isinstance(result, dict) or "error" in result:
        return result
    result["unknowns"] = list(unknowns or [])
    result["limitations"] = list(limitations or [])
    # Budget: truncate large string fields, mark truncated
    import json as _json
    try:
        size = len(_json.dumps(result, default=str))
    except Exception:
        size = 0
    result["truncated"] = False
    if size > _MAX_RESPONSE_CHARS:
        # Truncate the largest list fields first
        for key in ("spec", "manifest", "findings", "sections"):
            if key in result and isinstance(result[key], (list, dict)):
                original = result[key]
                if isinstance(original, list) and len(original) > 20:
                    result[key] = original[:20]
                    result["truncated"] = True
                    result["unknowns"].append(
                        f"{key} truncated to 20 items by response budget "
                        f"({len(original)} total)")
                    break
                elif isinstance(original, dict) and len(original) > 10:
                    keys = list(original.keys())[:10]
                    result[key] = {k: original[k] for k in keys}
                    result["truncated"] = True
                    result["unknowns"].append(
                        f"{key} truncated by response budget")
                    break
    return result


def _lane(name: str):
    """Lazy import of a sibling lane module. Returns (module, None) or
    (None, error_dict)."""
    try:
        return importlib.import_module(f"omnirecon.{name}"), None
    except Exception as e:  # noqa: BLE001 - must never leak tracebacks
        return None, _err(f"sibling module 'omnirecon.{name}' is unavailable",
                          "unavailable", str(e)[:200])


def _session_manager():
    mod, err = _lane("session")
    if err:
        return None, err
    try:
        return mod.SessionManager(str(SESSIONS_ROOT)), None
    except Exception as e:  # noqa: BLE001
        return None, _err("could not initialise SessionManager",
                          "internal", str(e)[:200])


def _redact(obj):
    mod, _ = _lane("security")
    if mod is not None and hasattr(mod, "redact"):
        try:
            return mod.redact(obj)
        except Exception:
            # fail CLOSED: never return a possibly-secret object unredacted
            return {"redacted": True,
                    "note": "redaction failed; content withheld"}
    return obj


def _audit(session_id: str, action: str, detail: str = ""):
    mod, _ = _lane("security")
    if mod is not None and hasattr(mod, "audit"):
        try:
            mod.audit(session_id, action, detail, base_dir=str(SESSIONS_ROOT))
        except Exception:
            pass


def _check_scope(url: str, allowed: list[str]) -> bool:
    mod, _ = _lane("security")
    if mod is not None and hasattr(mod, "check_scope"):
        try:
            return bool(mod.check_scope(url, allowed))
        except Exception:
            return True
    return True


def _read_ledger(session_id: str) -> list[dict]:
    p = SESSIONS_ROOT / session_id / "evidence.jsonl"
    out = []
    if p.exists():
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except Exception:
                    continue
    return out


def _ledger_add(session_id: str, mgr, items: list[dict]) -> list[str]:
    """Append findings through the real EvidenceLedger when available.

    IMPORTANT: SessionManager caches the ledger in memory and checkpoint()
    rewrites evidence.jsonl from that cache — so findings must go through
    mgr.ledger(sid).add(), never appended to the file directly, or the next
    checkpoint would silently discard them.
    """
    if mgr is not None and hasattr(mgr, "ledger"):
        try:
            led = mgr.ledger(session_id)
            ids = [led.add(it) for it in items]
            try:
                mgr.checkpoint(session_id)
            except Exception:
                pass
            return ids
        except Exception:
            pass
    return _append_findings(session_id, items)


def _append_findings(session_id: str, items: list[dict]) -> list[str]:
    """Fallback writer — goes through EvidenceLedger for validation + redaction.

    One code path for all writes. The old raw-dict writer bypassed central
    redaction (secrets in sources[]/detail persisted verbatim); this version
    gets redaction, id assignment, and validation for free.
    """
    from omnirecon import evidence as ev
    sdir = SESSIONS_ROOT / session_id
    sdir.mkdir(parents=True, exist_ok=True)
    path = sdir / "evidence.jsonl"
    ledger = ev.EvidenceLedger.load(str(path)) \
        if path.exists() else ev.EvidenceLedger()
    ids = []
    for it in items:
        if not isinstance(it, dict):
            continue
        it = dict(it)
        # fallback leniency: coerce instead of dropping on bad enums
        if str(it.get("classification", "UNVERIFIED")).upper() not in ev.CLASSIFICATIONS:
            it["classification"] = "INFERRED"
        if str(it.get("type", "note")) not in ev.FINDING_TYPES:
            it["type"] = "note"
        try:
            ids.append(ledger.add(it))
        except Exception:
            continue
    ledger.save(str(path))
    return ids


def _finding(ftype: str, title: str, detail: str = "", classification: str = "INFERRED",
             confidence: float = 0.5, why: str = "", sources=None, route=None,
             component=None, endpoint=None, artifact=None, limitations="",
             engine=None) -> dict:
    return {"type": ftype, "title": title, "detail": detail,
            "classification": classification, "confidence": confidence,
            "confidence_why": why, "sources": list(sources or []),
            "route": route, "component": component, "endpoint": endpoint,
            "artifact": artifact, "limitations": limitations, "engine": engine}


def _open_browser(bmod):
    """Launch the owned browser for recon.

    Honors OMNIRECON_IGNORE_HTTPS_ERRORS=1 (needed behind TLS-intercepting
    corporate/sandbox proxies whose CA the browser does not trust).
    """
    insecure = os.environ.get("OMNIRECON_IGNORE_HTTPS_ERRORS", "").strip() == "1"
    browser = bmod.OwnedBrowser()
    browser.launch(headless=True, ignore_https_errors=insecure)
    browser._omni_insecure = insecure
    return browser


def _goto_resilient(browser, bmod, url, session_id, mgr):
    """browser.goto with one automatic retry past certificate errors.

    Returns (browser_to_use, page_dict). If the first attempt fails with a
    certificate error and verification was not already disabled, the browser
    is relaunched with ignore_https_errors=True, an OBSERVED finding about
    the untrusted certificate is recorded (recon-relevant intel, common
    behind TLS-intercepting proxies), and the navigation is retried once.
    """
    try:
        return browser, browser.goto(url, session_id=session_id)
    except Exception as e:  # noqa: BLE001 - error text is the signal
        if "ERR_CERT" not in str(e) or getattr(browser, "_omni_insecure", False):
            raise
        try:
            browser.shutdown()
        except Exception:
            pass
        nb = bmod.OwnedBrowser()
        nb.launch(headless=True, ignore_https_errors=True)
        nb._omni_insecure = True
        try:
            _ledger_add(session_id, mgr, [_finding(
                "note", f"Untrusted TLS certificate on {url}",
                "browser TLS verification failed "
                f"({str(e)[:160]}); navigation retried with certificate "
                "verification disabled and succeeded.",
                "OBSERVED", 0.9, "browser TLS handshake observation",
                sources=[url],
                limitations="certificate chain details were not captured; "
                            "page content was still observed normally")])
        except Exception:
            pass
        return nb, nb.goto(url, session_id=session_id)


# --- background jobs ---------------------------------------------------------

class _LocalJobs:
    """Minimal thread job manager used when session.JobManager is unavailable."""

    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def submit(self, label: str, fn, *a, **kw) -> str:
        jid = "J-" + uuid.uuid4().hex[:8]
        rec = {"job_id": jid, "label": label, "status": "running",
               "result": None, "error": None, "started_utc": _utcnow()}

        def _run():
            try:
                res = fn(*a, **kw)
                with self._lock:
                    rec["status"] = "done"
                    rec["result"] = res
            except Exception as e:  # noqa: BLE001
                with self._lock:
                    rec["status"] = "failed"
                    rec["error"] = str(e)[:500]

        with self._lock:
            self._jobs[jid] = rec
        threading.Thread(target=_run, daemon=True).start()
        return jid

    def poll(self, job_id: str) -> dict:
        with self._lock:
            rec = self._jobs.get(job_id)
            if not rec:
                return {"status": "unknown", "error": "no such job"}
            return dict(rec)

    def for_session(self, session_id: str) -> list[dict]:
        with self._lock:
            return [{"job_id": j["job_id"], "label": j["label"],
                     "status": j["status"], "session_id": j.get("session_id")}
                    for j in self._jobs.values()
                    if j.get("session_id") == session_id]


_JOBS = _LocalJobs()


def _submit_job(session_id: str, label: str, fn, *a, **kw) -> str:
    mod, _ = _lane("session")
    jm = None
    if mod is not None and hasattr(mod, "JobManager"):
        try:
            jm = mod.JobManager()
        except Exception:
            jm = None
    if jm is not None:
        try:
            jid = jm.submit(fn, *a, **kw)
            # mirror into local registry so recon_status can report it
            _JOBS._jobs[jid] = {"job_id": jid, "label": label,
                                "status": "running", "session_id": session_id,
                                "_jm": jm}
            return jid
        except Exception:
            pass
    jid = _JOBS.submit(label, fn, *a, **kw)
    _JOBS._jobs[jid]["session_id"] = session_id
    return jid


def _job_status(job_id: str) -> dict:
    rec = _JOBS._jobs.get(job_id)
    if not rec:
        return {"status": "unknown"}
    jm = rec.get("_jm")
    if jm is not None:
        try:
            return jm.poll(job_id)
        except Exception:
            pass
    return _JOBS.poll(job_id)


def _run_or_bg(session_id: str, background: bool, label: str, fn, *a, **kw):
    if background:
        jid = _submit_job(session_id, label, fn, *a, **kw)
        _audit(session_id, "job_submitted", f"{label} -> {jid}")
        return {"job_id": jid, "status": "running", "label": label,
                "note": "poll progress via recon_status"}
    try:
        return fn(*a, **kw)
    except Exception as e:  # noqa: BLE001
        return _err(f"{label} failed", "internal", str(e)[:300])


def _get_session(mgr, session_id: str):
    try:
        s = mgr.get(session_id)
    except Exception as e:  # noqa: BLE001 - includes ReconError(session_not_found)
        code = getattr(e, "code", "") or "internal"
        if "not_found" in code or "not found" in str(e).lower():
            return None, _err(f"no session '{session_id}'", "not_found",
                              "call recon_start to create one")
        return None, _err("session lookup failed", code, str(e)[:200])
    if not s:
        return None, _err(f"no session '{session_id}'", "not_found",
                          "call recon_start to create one")
    return s, None


def _ledger_stats(mgr, session_id: str) -> dict:
    """Ledger stats via the real EvidenceLedger when available."""
    if mgr is not None and hasattr(mgr, "ledger"):
        try:
            return mgr.ledger(session_id).stats()
        except Exception:
            pass
    findings = _read_ledger(session_id)
    by_type: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for f in findings:
        by_type[f.get("type", "?")] = by_type.get(f.get("type", "?"), 0) + 1
        by_class[f.get("classification", "?")] = \
            by_class.get(f.get("classification", "?"), 0) + 1
    return {"total": len(findings), "by_type": by_type,
            "by_classification": by_class}


def _minimal_graph(findings: list[dict]) -> dict:
    nodes, edges = [], []
    seen = set()

    def add_node(nid, kind, label, fid):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": label,
                          "finding_id": fid})

    for f in findings:
        fid = f.get("id")
        if f.get("type") == "route" and f.get("route"):
            add_node("route:" + f["route"], "route", f["route"], fid)
        elif f.get("type") == "endpoint" and f.get("endpoint"):
            nid = "endpoint:" + f["endpoint"]
            add_node(nid, "endpoint", f["endpoint"], fid)
            if f.get("route"):
                edges.append({"from": "route:" + f["route"], "to": nid,
                              "rel": "calls"})
        elif f.get("type") == "component" and f.get("component"):
            add_node("component:" + f["component"], "component",
                     f["component"], fid)
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# 14 tools
# ---------------------------------------------------------------------------

@mcp.tool()
def recon_start(target: Annotated[str, Field(description="Target to reverse-engineer: full URL (https://...), OpenAPI doc URL, local repo path, or artifact file path (APK/binary/.asar)")],
                  mode: Annotated[str, Field(description='"fast" for rapid recon in seconds, "thorough" for deep multi-engine analysis')] = "fast",
                  budget_json: Annotated[str, Field(description='Optional JSON budget, e.g. {"max_pages": 40}; empty "{}" for defaults')] = "{}") -> dict:
    """FIRST CALL — start here. Start a reverse-engineering session for any target kind: web URL, OpenAPI/Swagger document URL, local repo path or git URL, or a shipped artifact file (APK/IPA/native binary/JS bundle/.asar).
    Runs Stage 1 (target validation) + Stage 2 (rapid recon) synchronously and
    returns {session_id, rapid_report}. mode is 'fast' or 'thorough'.
    budget_json is an optional JSON object, e.g. {"max_pages": 40}."""
    if not target or not target.strip():
        return _err("target is required", "invalid_input",
                    "pass a URL (https://…) or a local repo path")
    if mode not in ("fast", "thorough"):
        return _err(f"invalid mode '{mode}'", "invalid_input",
                    "mode must be 'fast' or 'thorough'")
    try:
        budget = json.loads(budget_json or "{}")
        if not isinstance(budget, dict):
            raise ValueError("budget must be a JSON object")
    except Exception as e:  # noqa: BLE001
        return _err("budget_json is not valid JSON", "invalid_input", str(e)[:200])
    mgr, err = _session_manager()
    if err:
        return err
    try:
        session = mgr.create(target.strip(), mode=mode, budget=budget)
    except Exception as e:  # noqa: BLE001
        return _err("recon_start failed", "internal", str(e)[:300])
    _audit(session.get("session_id") or session.get("id", ""), "recon_start",
           f"target={target.strip()} mode={mode}")
    return session


@mcp.tool()
def recon_status(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Session status: stage, progress, ledger stats, and background jobs."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    stats = _ledger_stats(mgr, session_id)
    jobs = []
    for jid, rec in list(_JOBS._jobs.items()):
        if rec.get("session_id") == session_id:
            st = _job_status(jid)
            jobs.append({"job_id": jid, "label": rec.get("label"),
                         "status": st.get("status")})
    out = dict(session)
    out["ledger"] = stats
    out["jobs"] = jobs
    return out


@mcp.tool()
def recon_discover_routes(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                           max_pages: Annotated[int, Field(description="Max pages to crawl; 40 covers most sites, 100 for large apps")] = 40,
                           max_depth: Annotated[int, Field(description="Link-follow depth from start; 3 is usually enough")] = 3,
                           background: Annotated[bool, Field(description="True for large crawls; poll progress with recon_status")] = False) -> dict:
    """Discover and classify reachable routes for the session target.
    Crawls internal pages and records route + endpoint findings. Long-running:
    pass background=true to get a job_id and poll via recon_status."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    max_pages = max(1, min(int(max_pages), 200))
    max_depth = max(0, min(int(max_depth), 4))
    target = session.get("target", "")

    def _do():
        crawl = RP.crawl_site(target, max_pages=max_pages, max_depth=max_depth)
        items = []
        for p in crawl.get("pages", []):
            items.append(_finding(
                "route", f"Route {p['url']}",
                f"title={p.get('title')!r} depth={p.get('depth')} "
                f"internal_links={p.get('internal_links')}",
                "OBSERVED", 0.9, "page fetched and parsed during crawl",
                sources=[p["url"]], route=p["url"], engine="static"))
        for e in crawl.get("api_endpoints", [])[:120]:
            items.append(_finding(
                "endpoint", f"Endpoint {e['endpoint']}",
                f"kind={e['kind']} scope={e['scope']} discovered across crawled pages",
                "OBSERVED", 0.75, "endpoint literal found in crawled page/JS text",
                sources=[target], endpoint=e["endpoint"], engine="static"))
        # Client-side routes from JS bundles (hash routes, router definitions)
        for cr in crawl.get("client_routes", [])[:60]:
            items.append(_finding(
                "route", f"Client route {cr}",
                "route definition extracted from JS bundle; not fetched via "
                "HTTP (SPA client-side navigation)",
                "INFERRED", 0.7, "route path literal in JS bundle",
                sources=[target], route=cr, engine="static"))
        ids = _ledger_add(session_id, mgr, items)
        try:
            mgr.update_stage(session_id, 3)
            mgr.checkpoint(session_id)
        except Exception:
            pass
        _audit(session_id, "discover_routes",
               f"pages={crawl.get('pages_crawled')} findings={len(ids)}")
        return {"pages_crawled": crawl.get("pages_crawled"),
                "routes_recorded": len(crawl.get("pages", [])),
                "endpoints_indexed": len(crawl.get("api_endpoints", [])),
                "finding_ids": ids}

    return _run_or_bg(session_id, background, "discover_routes", _do)


@mcp.tool()
def recon_inspect_page(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                        url: Annotated[str, Field(description="Full page URL to deep-inspect, e.g. https://site.com/pricing")] ) -> dict:
    """Deep-inspect one page: DOM structure, controls, forms, accessibility data,
    screenshots (desktop/tablet/mobile), console errors. Uses the owned browser
    when available; falls back to static analysis (marked 'limited')."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not url or not url.strip():
        return _err("url is required", "invalid_input", "pass the full page URL as the 'url' argument, e.g. https://site.com/pricing")
    url = url.strip()

    bmod, berr = _lane("browser_engine")
    if berr or not hasattr(bmod, "OwnedBrowser"):
        scan = RP.platform_scan(url)
        items = [_finding(
            "note", f"Static inspection of {url}",
            f"browser engine unavailable; static scan: status={scan.get('status')} "
            f"title={scan.get('title')!r} tech={[t['tech'] for t in scan.get('tech', [])]}",
            "OBSERVED", 0.6, "static fetch only — no rendered DOM observed",
            sources=[url], route=url,
            limitations="rendered DOM, AX tree, screenshots, and console "
                        "not captured (no browser engine)")]
        ids = _ledger_add(session_id, mgr, items)
        return {"url": url, "mode": "limited-static",
                "scan": _redact(scan), "finding_ids": ids,
                "note": "browser_engine unavailable; static fallback used"}

    try:
        browser = _open_browser(bmod)
        try:
            browser, page = _goto_resilient(browser, bmod, url,
                                            session_id, mgr)
            pid = page.get("page_id")
            snap = browser.snapshot(pid)
            # Screenshots live in the session dir (persistent), not /tmp.
            artifacts_dir = str(SESSIONS_ROOT / session_id / "artifacts")
            shots = {}
            for vp in ("desktop", "tablet", "mobile"):
                try:
                    shots[vp] = browser.screenshot(pid, viewport=vp,
                                                   artifacts_dir=artifacts_dir)
                except Exception:
                    pass
            console = browser.console_errors(pid)
            try:
                storage = browser.storage_snapshot(pid)
            except Exception:
                storage = {}
        finally:
            browser.shutdown()
    except Exception as e:  # noqa: BLE001
        return _err("browser inspection failed", "internal", str(e)[:300])

    snap = _redact(snap)
    # Login-wall detection: if the rendered page is an auth gate, say so
    # loudly instead of silently speccing the login form as the app.
    _is_login_wall = False
    _final_url = (snap.get("url") or url).lower()
    for form in snap.get("forms", []) or []:
        for inp in form.get("inputs", []) or []:
            if (inp.get("type") or "").lower() == "password":
                _is_login_wall = True
                break
        if _is_login_wall:
            break
    if "/login" in _final_url or "/signin" in _final_url or "/auth" in _final_url:
        # Only flag if the requested URL wasn't itself a login page
        _req_lower = url.lower()
        if "/login" not in _req_lower and "/signin" not in _req_lower \
                and "/auth" not in _req_lower:
            _is_login_wall = True
    items = []
    if _is_login_wall:
        items.append(_finding(
            "auth", f"Login wall at {url}",
            f"Rendered page is an authentication gate, not the app "
            f"(password field present; final URL {_final_url[:80]}). "
            f"Routes, components, and workflows behind the wall are UNVERIFIED. "
            f"Use recon_authenticate with operator credentials to proceed, "
            f"or treat authed areas as BLOCKED.",
            "BLOCKED", 0.95, "password input and/or auth redirect observed",
            sources=[url], route=url,
            limitations="content behind the login wall was not inspected"))
    items.append(_finding(
        "route", f"Inspected {snap.get('url', url)}",
        f"title={snap.get('title')!r} controls={len(snap.get('controls', []))} "
        f"forms={len(snap.get('forms', []))}",
        "OBSERVED", 0.9, "rendered in owned browser",
        sources=[url], route=snap.get("url", url), engine="rendered"))
    for form in snap.get("forms", [])[:10]:
        items.append(_finding(
            "component", f"Form -> {form.get('action')}",
            f"method={form.get('method')} inputs={[i.get('name') for i in form.get('inputs', [])]}",
            "OBSERVED", 0.85, "form observed in rendered DOM",
            sources=[url], route=snap.get("url", url),
            component=f"form:{form.get('action')}"))
    if console:
        items.append(_finding(
            "state", f"Console errors on {url}",
            "; ".join(console[:8]), "OBSERVED", 0.9,
            "console errors captured from the live page",
            sources=[url], route=url,
            limitations="errors observed at load; interaction-triggered errors not covered"))
    for vp, path in shots.items():
        if path:
            items.append(_finding(
                "asset", f"Screenshot ({vp}) of {url}",
                f"rendered {vp} viewport capture",
                "OBSERVED", 0.95, "screenshot taken in owned browser",
                sources=[url], route=snap.get("url", url), artifact=path,
                engine="rendered"))
    # Client-side storage: tokens, feature flags, cached state live here.
    if storage:
        ls_keys = list((storage.get("localStorage") or {}).keys())[:20]
        ss_keys = list((storage.get("sessionStorage") or {}).keys())[:20]
        cookies = (storage.get("cookies") or [])[:20]
        idbs = (storage.get("indexedDB") or [])[:10]
        # Redact values — only key names go to the ledger.
        detail = (f"localStorage keys: {ls_keys or 'none'}\n"
                  f"sessionStorage keys: {ss_keys or 'none'}\n"
                  f"cookie names: {cookies or 'none'}\n"
                  f"IndexedDB: {idbs or 'none'}")
        items.append(_finding(
            "state", f"Client storage on {url}",
            _redact(detail), "OBSERVED", 0.9,
            "storage dumped from the live page; values redacted, key names only",
            sources=[url], route=snap.get("url", url), engine="rendered",
            limitations="values never stored; IndexedDB contents not enumerated"))
    ids = _ledger_add(session_id, mgr, items)
    _audit(session_id, "inspect_page", url)
    return {"url": snap.get("url", url), "mode": "browser",
            "title": snap.get("title"),
            "controls": len(snap.get("controls", [])),
            "forms": snap.get("forms", []),
            "screenshots": shots,
            "console_errors": console,
            "finding_ids": ids}


@mcp.tool()
def recon_trace_workflow(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                         start_url: Annotated[str, Field(description="Full URL where the user journey begins")] ,
                         goal: Annotated[str, Field(description="Natural-language goal, e.g. 'add an item to cart and reach checkout'")] ,
                         max_steps: Annotated[int, Field(description="Max browser actions before stopping; 15 suffices for most flows")] = 15) -> dict:
    """Explore a bounded user journey from start_url toward a goal, recording
    state transitions (DOM changes, URL changes, network effects) per action.
    Safe actions only — never purchases, payments, deletions, or credential
    exfiltration. Requires the browser engine."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    bmod, berr = _lane("browser_engine")
    if berr or not hasattr(bmod, "OwnedBrowser"):
        return _err("workflow tracing requires the browser engine",
                    "unavailable",
                    "omnirecon.browser_engine is not available in this deployment")
    max_steps = max(1, min(int(max_steps), 40))
    try:
        browser = _open_browser(bmod)
        try:
            browser, page = _goto_resilient(browser, bmod, start_url,
                                            session_id, mgr)
            pid = page.get("page_id")
            steps: list[dict] = []
            tried_refs: set[str] = set()
            goal_words = [w.lower() for w in goal.split() if len(w) > 2]
            for _ in range(max_steps):
                snap = browser.snapshot(pid)
                controls = [c for c in snap.get("controls", [])
                            if c.get("visible", True)
                            and c.get("role") in ("button", "link")
                            and str(c.get("ref")) not in tried_refs]
                if not controls:
                    break

                def _score(c):
                    name = str(c.get("name", "")).lower()
                    return sum(1 for w in goal_words if w in name)

                controls.sort(key=_score, reverse=True)
                ctrl = controls[0]
                tried_refs.add(str(ctrl.get("ref")))
                try:
                    res = browser.interact(
                        pid, {"kind": "click", "ref": ctrl.get("ref")})
                except Exception as ie:  # noqa: BLE001 - one bad control
                    steps.append({"action": f"click {ctrl.get('name')}",
                                  "observed": False,
                                  "note": f"interact failed: {str(ie)[:120]}"})
                    continue
                res = _redact(res)
                steps.append({
                    "action": f"click '{ctrl.get('name')}'"
                              f" ({ctrl.get('role')})",
                    "observed": bool(res.get("observed")),
                    "url_before": res.get("url_before"),
                    "url_after": res.get("url_after"),
                    "dom_changed": res.get("dom_changed"),
                    "new_requests": (res.get("new_requests") or [])[:10],
                    "note": res.get("note", ""),
                })
                if res.get("url_after") and "logout" in goal.lower():
                    break
        finally:
            browser.shutdown()
    except Exception as e:  # noqa: BLE001
        return _err("workflow trace failed", "internal", str(e)[:300])
    items = []
    for s in steps:
        items.append(_finding(
            "workflow",
            f"Workflow step: {s['action']}",
            f"observed={s['observed']} {s['url_before']} -> {s['url_after']} "
            f"dom_changed={s['dom_changed']} "
            f"requests={len(s.get('new_requests', []))}",
            "OBSERVED" if s["observed"] else "UNVERIFIED",
            0.85 if s["observed"] else 0.3,
            "state transition recorded by the browser engine"
            if s["observed"]
            else "action produced no observable state change",
            sources=[start_url], route=s.get("url_after"), engine="rendered"))
    ids = _ledger_add(session_id, mgr, items)
    _audit(session_id, "trace_workflow",
           f"{start_url} goal={goal} steps={len(steps)}")
    replay_path = None
    try:
        dmod, _ = _lane("deep_dive")
        if dmod is not None and hasattr(dmod, "save_replay_script") and steps:
            replay_path = dmod.save_replay_script(
                session_id, steps, start_url, goal)
    except Exception:
        replay_path = None
    return {"goal": goal, "steps": steps, "finding_ids": ids,
            "replay_script": replay_path,
            "note": "only actions with observed DOM/URL/network effects are "
                    "marked OBSERVED; visible-but-untested controls are not "
                    "claimed to work"}


@mcp.tool()
def recon_capture_network(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                          url: Annotated[str, Field(description="Full page URL to load and monitor for network traffic")] ,
                          duration_ms: Annotated[int, Field(description="How long to record traffic in milliseconds; 8000 catches most XHR/fetch")] = 8000) -> dict:
    """Capture the page's real network traffic (XHR/fetch/WebSocket) and build
    a redacted endpoint catalog. Secrets are stripped before storage."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    duration_ms = max(1000, min(int(duration_ms), 30000))

    capture = None
    bmod, _ = _lane("browser_engine")
    if bmod is not None and hasattr(bmod, "OwnedBrowser"):
        try:
            browser = _open_browser(bmod)
            try:
                browser, page = _goto_resilient(browser, bmod, url,
                                                session_id, mgr)
                raw = browser.network_capture(
                    page.get("page_id"), duration_ms)
                # browser engine returns {requests, websocket_frames};
                # older shapes return a bare list.
                if isinstance(raw, dict) and "requests" in raw:
                    capture = raw
                else:
                    capture = {"requests": raw if isinstance(raw, list) else [],
                               "websocket_frames": []}
            finally:
                browser.shutdown()
        except Exception:
            capture = None
    if capture is None:
        raw = RP.capture_live_traffic(url, wait_ms=duration_ms)
        if raw.get("error"):
            return _err("network capture failed", "internal",
                        raw["error"][:300])
        capture = {"requests": raw.get("api_requests", []),
                   "websocket_frames": []}

    capture = _redact(capture)
    reqs = capture.get("requests", []) if isinstance(capture, dict) else []
    ws_frames = capture.get("websocket_frames", []) \
        if isinstance(capture, dict) else []
    seen_eps: dict[str, dict] = {}
    for r in reqs:
        u = r.get("url", "")
        if u and u not in seen_eps:
            seen_eps[u] = r
    items = [_finding(
        "endpoint", f"Observed {r.get('method', 'GET')} {u}",
        f"status={r.get('status')} type={r.get('type')}",
        "OBSERVED", 0.95, "request actually issued by the page in the browser",
        sources=[url], endpoint=u, engine="network") for u, r in list(seen_eps.items())[:150]]
    # values-free request/response shapes → schema findings (the keystone:
    # the agent gets data shapes, never example values)
    for u, r in list(seen_eps.items())[:150]:
        for kind, shape in (("request", r.get("request_shape")),
                            ("response", r.get("response_shape"))):
            if not isinstance(shape, dict):
                continue
            keys = ""
            if shape.get("type") == "object":
                props = shape.get("properties", {})
                keys = ", ".join(list(props.keys())[:12])
            f = _finding(
                "schema", f"{kind.title()} shape: {r.get('method', 'GET')} {u[:80]}",
                f"Observed {kind} shape — keys: {keys or shape.get('type')}. "
                f"Shapes only; no example values retained.",
                "OBSERVED", 0.9,
                f"{kind} body captured live and reduced to key/type shape",
                sources=[url], endpoint=u)
            f["shape"] = shape
            f["shape_kind"] = kind
            items.append(f)
    # websocket message shapes
    ws_clusters: dict[str, dict] = {}
    for f in ws_frames:
        key = json.dumps(f.get("shape", {}), sort_keys=True)[:200]
        ws_clusters[key] = f
    for f in list(ws_clusters.values())[:40]:
        shape = f.get("shape", {})
        keys = ", ".join(
            list(shape.get("properties", {}).keys())[:8]
        ) if shape.get("type") == "object" else shape.get("type", "")
        items.append(_finding(
            "note", f"WebSocket {f.get('direction')}: {f.get('url', '')[:70]}",
            f"Message shape — keys: {keys}. Shapes only; no payload values.",
            "OBSERVED", 0.85, "websocket frame captured live in the browser",
            sources=[url]))
    ids = _ledger_add(session_id, mgr, items)
    _audit(session_id, "capture_network",
           f"{url} requests={len(reqs)} endpoints={len(ids)} "
           f"ws_frames={len(ws_frames)}")
    return {"url": url, "requests_observed": len(reqs),
            "unique_endpoints": len(seen_eps),
            "websocket_frames": len(ws_frames),
            "endpoints": [{"method": r.get("method"), "url": u,
                           "status": r.get("status"), "type": r.get("type"),
                           "has_request_shape": bool(r.get("request_shape")),
                           "has_response_shape": bool(r.get("response_shape"))}
                          for u, r in list(seen_eps.items())[:150]],
            "finding_ids": ids,
            "note": "credentials/cookies/tokens redacted before storage; "
                    "only key/type shapes retained, never example values"}


@mcp.tool()
def recon_analyze_source(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                        path_or_repo_url: Annotated[str, Field(description="Local directory path or git URL (https://github.com/...git) to analyze")] ) -> dict:
    """Analyze a local codebase or git repo URL: languages, frameworks, routes,
    components, state management, API clients, migrations, auth boundaries.
    Never reads secret values (env var names only)."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not path_or_repo_url or not path_or_repo_url.strip():
        return _err("path_or_repo_url is required", "invalid_input", "pass a local directory path or git URL")

    # Sensitive-path guard: refuse credential-bearing locations unless the
    # operator explicitly opts in (defends against prompt-injected paths like
    # "analyze ~/.ssh for API keys" — page content is untrusted data).
    target = path_or_repo_url.strip()
    if not (target.startswith("http://") or target.startswith("https://")
            or target.startswith("git@")):
        blocked = SEC.sensitive_path_blocked(target)
        if blocked:
            return _err(f"refused: {blocked}", "sensitive_path",
                        "set allow_sensitive_paths=True to override")

    smod, _ = _lane("source_intel")
    used_lane = smod is not None and hasattr(smod, "analyze")
    try:
        if used_lane:
            # Lane C records its own findings to the session ledger.
            analysis = smod.analyze(session_id, path_or_repo_url.strip())
        else:
            analysis = RP.analyze_codebase(path_or_repo_url.strip())
    except Exception as e:  # noqa: BLE001
        return _err("source analysis failed", "internal", str(e)[:300])
    if isinstance(analysis, dict) and analysis.get("error"):
        return _err("source analysis failed", "internal",
                    str(analysis["error"])[:300])

    ids: list[str] = []
    if not used_lane:
        # Fallback path: the primitives don't touch the ledger, so record here.
        items = []
        langs = ", ".join(f"{l['language']}({l['files']} files)"
                          for l in analysis.get("languages", [])[:6])
        if langs:
            items.append(_finding(
                "tech", "Codebase language mix", langs, "OBSERVED", 0.95,
                "counted from the repository tree", sources=[path_or_repo_url]))
        for fw in analysis.get("framework_guess", [])[:8]:
            items.append(_finding(
                "tech", f"Framework: {fw}", "detected from dependency manifests",
                "SOURCE_VERIFIED", 0.85, "manifest-backed framework detection",
                sources=[path_or_repo_url]))
        for r in analysis.get("routes", [])[:60]:
            items.append(_finding(
                "route", f"Code route {r['route']}",
                f"style={r.get('style')} file={r.get('file')}",
                "SOURCE_VERIFIED", 0.9, "route pattern found in source",
                sources=[r.get("file", path_or_repo_url)], route=r["route"]))
        ids = _ledger_add(session_id, mgr, items)
    _audit(session_id, "analyze_source", path_or_repo_url.strip())
    return {"analysis": analysis, "finding_ids": ids,
            "note": "findings recorded by source_intel" if used_lane
            else "findings recorded by fallback"}


@mcp.tool()
def recon_extract_assets(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                        url: Annotated[str, Field(description="Full page URL to inventory images, fonts, icons from")] ) -> dict:
    """Inventory a page's assets: images, fonts, icons, and design tokens
    (colors, spacing, typography signals) from the DOM and CSS."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    amod, aerr = _lane("assets")
    if aerr or not hasattr(amod, "inventory"):
        return _err("asset extraction is unavailable", "unavailable",
                    "omnirecon.assets is not available in this deployment")
    try:
        # Lane C records its own findings to the session ledger.
        inv = amod.inventory(session_id, url.strip())
    except Exception as e:  # noqa: BLE001
        return _err("asset extraction failed", "internal", str(e)[:300])
    if isinstance(inv, dict) and inv.get("error"):
        return _err("asset extraction failed", "internal",
                    str(inv["error"])[:300])
    _audit(session_id, "extract_assets", url.strip())
    return {"url": url, "inventory": inv,
            "note": "findings recorded by assets.inventory"}


@mcp.tool()
def recon_analyze_ui(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                     url: Annotated[str, Field(description="Full page URL for designer-grade UI analysis; use flagship pages")] ) -> dict:
    """Designer-grade UI reverse engineering: computed design tokens (colors,
    typography, spacing, radii, shadows), component inventory grouped by visual
    signature, CSS framework detection, and layout sectioning — all from
    *rendered* computed styles, not stylesheets. Requires the browser engine."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not url or not url.strip():
        return _err("url is required", "invalid_input", "pass the full page URL as the 'url' argument, e.g. https://site.com/pricing")
    bmod, berr = _lane("browser_engine")
    if berr or not hasattr(bmod, "OwnedBrowser"):
        return _err("UI analysis requires the browser engine", "unavailable",
                    "omnirecon.browser_engine is not available in this deployment")
    umod, uerr = _lane("ui_intel")
    if uerr or not hasattr(umod, "analyze_ui"):
        return _err("UI analysis is unavailable", "unavailable",
                    "omnirecon.ui_intel is not available in this deployment")
    try:
        browser = _open_browser(bmod)
        try:
            browser, page = _goto_resilient(browser, bmod, url.strip(),
                                            session_id, mgr)
            result = browser._run(
                umod.analyze_ui(browser, page.get("page_id"),
                                session_id, url.strip()))
        finally:
            browser.shutdown()
    except Exception as e:  # noqa: BLE001
        return _err("UI analysis failed", "internal", str(e)[:300])
    try:
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "analyze_ui",
           f"{url} components={len(result.get('components', []))}")
    return result


@mcp.tool()
def recon_analyze_artifact(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                          path: Annotated[str, Field(description="Local file path to APK, IPA, ELF/PE/Mach-O binary, JS bundle, or .asar")] ) -> dict:
    """Analyze a shipped artifact: APK/IPA, native binary (ELF/PE/Mach-O),
    or JS bundle. Lightweight structural intel (format, symbols, manifest,
    string-mined URLs) is always produced; when the REA CLI is installed
    with a configured provider, deep decompilation results are fused into
    the evidence ledger. Honest about what it cannot do."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not path or not path.strip():
        return _err("path is required", "invalid_input", "pass the local file path to the APK/binary/.asar")
    path = os.path.expanduser(path.strip())
    if not os.path.isfile(path):
        return _err(f"file not found: {path}", "invalid_target",
                    "Pass a local APK/IPA/binary/JS-bundle file path.")

    amod, aerr = _lane("artifact_intel")
    if aerr or not hasattr(amod, "analyze_artifact"):
        return _err("artifact analysis is unavailable", "unavailable",
                    "omnirecon.artifact_intel is not available in this deployment")
    try:
        result = amod.analyze_artifact(session_id, path)
    except Exception as e:  # noqa: BLE001
        return _err("artifact analysis failed", "internal", str(e)[:300])
    try:
        mgr.update_stage(session_id, 3)
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "analyze_artifact", path)
    return result


@mcp.tool()
def recon_verify_consistency(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Cross-check findings between engines (static crawl vs rendered pages
    vs JS bundles vs network capture). Agreements are corroborated;
    contradictions are downgraded to UNVERIFIED/INFERRED with reasons —
    never silently dropped. This is the accuracy multiplier."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    dmod, derr = _lane("deep_dive")
    if derr or not hasattr(dmod, "verify_consistency"):
        return _err("consistency verification is unavailable", "unavailable",
                    "omnirecon.deep_dive is not available in this deployment")
    try:
        result = dmod.verify_consistency(session_id)
    except Exception as e:  # noqa: BLE001
        return _err("consistency verification failed", "internal", str(e)[:300])
    try:
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "verify_consistency",
           f"agreements={result.get('agreements')} "
           f"contradictions={result.get('contradictions')}")
    return result


@mcp.tool()
def recon_recover_sourcemaps(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                              page_url: Annotated[str, Field(description="Full page URL whose JS bundles to probe for .map files")] ) -> dict:
    """Fetch published *.js.map files for a page's scripts and recover the
    original source tree (webpack/parcel/vite paths). Reports honestly when
    the site ships no maps."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not page_url or not page_url.strip():
        return _err("page_url is required", "invalid_input", "pass the full page URL whose scripts to probe")
    dmod, derr = _lane("deep_dive")
    if derr or not hasattr(dmod, "recover_sourcemaps"):
        return _err("source-map recovery is unavailable", "unavailable",
                    "omnirecon.deep_dive is not available in this deployment")
    try:
        result = dmod.recover_sourcemaps(session_id, page_url.strip())
    except Exception as e:  # noqa: BLE001
        return _err("source-map recovery failed", "internal", str(e)[:300])
    try:
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "recover_sourcemaps",
           f"{page_url} maps={len(result.get('maps_found', []))}")
    return result


@mcp.tool()
def recon_probe_endpoints(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                           base_url: Annotated[str, Field(description="Origin to probe relative endpoints against, e.g. https://api.site.com; empty uses session target")] = "") -> dict:
    """Live-probe every discovered /api/* endpoint (HEAD then GET) and record
    live/dead verdicts with status codes. Auth-walled (401/403) counts as
    live-but-guarded. Turns INFERRED endpoints into OBSERVED ones."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    target = (base_url or "").strip() or session.get("target", "")
    if not target:
        return _err("base_url is required", "invalid_input", "pass the origin URL, e.g. https://api.site.com, or omit to use the session target")
    dmod, derr = _lane("deep_dive")
    if derr or not hasattr(dmod, "probe_endpoints"):
        return _err("endpoint probing is unavailable", "unavailable",
                    "omnirecon.deep_dive is not available in this deployment")
    try:
        result = dmod.probe_endpoints(session_id, target)
    except Exception as e:  # noqa: BLE001
        return _err("endpoint probing failed", "internal", str(e)[:300])
    try:
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "probe_endpoints",
           f"{target} live={result.get('live')} dead={result.get('dead')}")
    return result


@mcp.tool()
def recon_get_graph(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Return the route / component / workflow / API dependency graph as
    {nodes, edges}, built from the evidence ledger."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    gmod, _ = _lane("graph")
    graph = None
    if gmod is not None and hasattr(gmod, "build_graph") \
            and hasattr(mgr, "ledger"):
        try:
            graph = gmod.build_graph(mgr.ledger(session_id),
                                     target=session.get("target"))
        except Exception:
            graph = None
    if graph is None:
        graph = _minimal_graph(_read_ledger(session_id))
    try:
        with open(SESSIONS_ROOT / session_id / "graph.json", "w") as fh:
            json.dump(graph, fh, indent=2, default=str)
    except Exception:
        pass
    return graph


@mcp.tool()
def recon_get_evidence(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                       finding_id: Annotated[str, Field(description="Exact finding ID like F-0001; empty to filter instead")] = "",
                       type: Annotated[str, Field(description="Filter by type: route, endpoint, component, asset, schema, tech, state, note, auth")] = "",
                       classification: Annotated[str, Field(description="Filter by OBSERVED, SOURCE_VERIFIED, INFERRED, UNVERIFIED, BLOCKED")] = "",
                       query: Annotated[str, Field(description="Free-text search over finding titles and details")] = "") -> dict:
    """Retrieve ledger findings: by ID, by type/classification filter, or by
    free-text search over titles and details."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    # Prefer the real EvidenceLedger (filters + search); fall back to the file.
    if hasattr(mgr, "ledger"):
        try:
            led = mgr.ledger(session_id)
            if finding_id:
                f = led.get(finding_id)
                if not f:
                    return _err(f"no finding '{finding_id}'", "not_found", "list valid IDs with recon_get_evidence(session_id)")
                return {"finding": f}
            if classification and classification not in VALID_CLASS:
                return _err(f"invalid classification '{classification}'",
                            "invalid_input", f"one of {VALID_CLASS}")
            res = led.list(type=type or None,
                           classification=classification or None)
            if query:
                res = led.search(query)
                if type:
                    res = [f for f in res if f.get("type") == type]
                if classification:
                    res = [f for f in res
                           if f.get("classification") == classification]
            return {"count": len(res), "findings": res[:200]}
        except Exception:
            pass
    findings = _read_ledger(session_id)
    if finding_id:
        f = next((x for x in findings if x.get("id") == finding_id), None)
        if not f:
            return _err(f"no finding '{finding_id}'", "not_found", "list valid IDs with recon_get_evidence(session_id)")
        return {"finding": f}
    res = findings
    if type:
        res = [f for f in res if f.get("type") == type]
    if classification:
        if classification not in VALID_CLASS:
            return _err(f"invalid classification '{classification}'",
                        "invalid_input", f"one of {VALID_CLASS}")
        res = [f for f in res if f.get("classification") == classification]
    if query:
        q = query.lower()
        res = [f for f in res
               if q in str(f.get("title", "")).lower()
               or q in str(f.get("detail", "")).lower()]
    return {"count": len(res), "findings": res[:200]}


@mcp.tool()
def recon_generate_spec(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Call AFTER deep engines (discover/inspect/capture/analyze_ui). Generate the 15-section reconstruction blueprint from the evidence
    ledger + graph. Saved to spec.json. Every claim carries finding_ids;
    unevidenced areas are marked UNVERIFIED/BLOCKED, never invented."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    ledger = mgr.ledger(session_id) if hasattr(mgr, "ledger") else None
    findings = _read_ledger(session_id)
    gpath = SESSIONS_ROOT / session_id / "graph.json"
    graph = None
    if gpath.exists():
        try:
            graph = json.loads(gpath.read_text())
        except Exception:
            graph = None
    if graph is None:
        graph = _minimal_graph(findings)
    try:
        spec = SPEC.generate_spec(ledger if ledger is not None else findings,
                                  graph)
    except Exception as e:  # noqa: BLE001
        return _err("spec generation failed", "internal", str(e)[:300])
    try:
        with open(SESSIONS_ROOT / session_id / "spec.json", "w") as fh:
            json.dump(spec, fh, indent=2, ensure_ascii=False, default=str)
        mgr.update_stage(session_id, 5)
        mgr.checkpoint(session_id)
    except Exception:
        pass
    # Machine-readable build manifest: ordered task list for the rebuild loop.
    manifest = {"build_tasks": [], "research_tasks": []}
    manifest_path = ""
    try:
        manifest = SPEC.generate_manifest(spec, graph)
        manifest_path = str(SESSIONS_ROOT / session_id / "tasks.json")
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False, default=str)
    except Exception:
        manifest = {"build_tasks": [], "research_tasks": []}
        manifest_path = ""
    _audit(session_id, "generate_spec",
           f"findings={len(findings)} sections={len(spec.get('sections', {}))} "
           f"build_tasks={len(manifest.get('build_tasks', []))} "
           f"research_tasks={len(manifest.get('research_tasks', []))}")
    spec["manifest"] = manifest
    spec["manifest_path"] = manifest_path
    return spec


def _attach_deviation_evidence(session_id: str, result: dict) -> dict:
    """Join each deviation against the evidence ledger so fix-iterations can
    see exactly which findings define the missing route/endpoint. Additive
    only; never raises."""
    try:
        findings = _read_ledger(session_id)
    except Exception:
        return result
    from urllib.parse import urlparse as _up

    def _path(u: str) -> str:
        try:
            p = _up(u).path or "/"
        except Exception:
            return u
        return p if p.startswith("/") else "/" + p

    def _norm_ep(ep: str) -> str:
        ep = (ep or "").strip()
        if "://" in ep or ep.startswith("//"):
            return _path("https:" + ep if ep.startswith("//") else ep
                         ).rstrip("/") or "/"
        return ("/" + ep.lstrip("/")).split("?")[0].rstrip("/") or "/"

    route_index: dict[str, list[dict]] = {}
    ep_index: dict[str, list[dict]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        if f.get("route"):
            route_index.setdefault(_path(f["route"]), []).append(f)
        if f.get("endpoint"):
            ep_index.setdefault(_norm_ep(f["endpoint"]), []).append(f)

    missing_routes = set((result.get("route_coverage", {}) or {})
                         .get("missing", []) or [])
    missing_eps = set((result.get("endpoint_overlap", {}) or {})
                      .get("missing", []) or [])

    for d in result.get("deviations", []) or []:
        if not isinstance(d, dict):
            continue
        kind = d.get("kind", "")
        matched: list[dict] = []
        if kind == "missing_route":
            for r in missing_routes:
                if r in (d.get("detail", "") or ""):
                    matched.extend(route_index.get(r, []))
        elif kind == "missing_endpoint":
            for e in missing_eps:
                if e in (d.get("detail", "") or ""):
                    matched.extend(ep_index.get(e, []))
        if matched:
            fids = sorted({f.get("id") for f in matched if f.get("id")})
            srcs = sorted({s for f in matched
                           for s in (f.get("sources", []) or []) if s})[:5]
            d["evidence_refs"] = {"finding_ids": fids, "sources": srcs}
    return result


@mcp.tool()
def recon_compare_build(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                         build_url: Annotated[str, Field(description="Full URL of YOUR rebuild to diff against the recorded reference")] ) -> dict:
    """Call AFTER building from the spec. Compare a reconstructed build against the session's recorded reference:
    route coverage, endpoint overlap, deviations. Honest about limits — no
    pixel-perfect claims (screenshot comparison is out of scope)."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not build_url or not build_url.strip():
        return _err("build_url is required", "invalid_input", "pass the full URL of your rebuild to compare")
    try:
        result = VERIFY.compare_build(session_id, build_url.strip())
    except Exception as e:  # noqa: BLE001
        return _err("build comparison failed", "internal", str(e)[:300])
    # Loop memory: persist the run, attach a trend vs the previous run, and
    # cite the evidence behind each deviation. Never breaks the tool.
    try:
        prev_runs = VERIFY.list_comparisons(session_id)
        prev = prev_runs[-1] if prev_runs else None
        result["trend"] = VERIFY.compute_trend(result, prev)
        result = _attach_deviation_evidence(session_id, result)
        result["comparison_path"] = VERIFY.save_comparison(session_id, result)
        result["comparison_runs"] = len(prev_runs) + 1
    except Exception:
        pass
    _audit(session_id, "compare_build", build_url.strip())
    return result


@mcp.tool()
def recon_export_report(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")],
                         format: Annotated[str, Field(description='"markdown" for a report, "json" for raw data, "openapi" for an OpenAPI 3.1 document')] = "markdown") -> dict:
    """Call AFTER recon_generate_spec. Export the session findings as a Markdown report, machine-readable
    JSON, or an OpenAPI 3.1 document reconstructed from the evidence ledger.
    Returns {path, content}. Artifacts land in the session directory."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if format not in ("markdown", "json", "openapi"):
        return _err(f"invalid format '{format}'", "invalid_input",
                    "format must be 'markdown', 'json', or 'openapi'")
    try:
        if format == "json":
            path, content = REPORT.export_json(session)
        elif format == "openapi":
            from omnirecon import api_intel as AI
            ledger = mgr.ledger(session_id)
            findings = ledger.list()
            doc = AI.ledger_to_openapi(
                findings,
                title=f"Reconstructed API — {session.get('target', session_id)}")
            content = AI.dump_openapi_yaml(doc)
            sdir = os.path.join(str(SESSIONS_ROOT), session_id)
            os.makedirs(sdir, exist_ok=True)
            path = os.path.join(sdir, "openapi.yaml")
            with open(path, "w") as fh:
                fh.write(content)
        else:
            path, content = REPORT.export_markdown(session)
    except Exception as e:  # noqa: BLE001
        return _err("report export failed", "internal", str(e)[:300])
    _audit(session_id, "export_report", f"format={format} path={path}")
    return {"path": path, "content": content}


@mcp.tool()
def recon_cancel(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Stop a running analysis session safely."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    try:
        result = mgr.cancel(session_id)
    except Exception as e:  # noqa: BLE001
        return _err("cancel failed", "internal", str(e)[:300])
    _audit(session_id, "cancel", "")
    return result if isinstance(result, dict) else {"session_id": session_id,
                                                    "status": "cancelled"}


@mcp.tool()
def recon_authenticate(
    session_id: Annotated[str, Field(description="Session ID returned by recon_start")],
    login_url: Annotated[str, Field(description="Full URL of the login page")] ,
    username: Annotated[str, Field(description="Your own username/email for this target (authorized testing only)")] ,
    password: Annotated[str, Field(description="Your own password; used transiently, never stored")] ,
    username_selector: Annotated[str, Field(description="CSS selector for the username field; empty for auto-detect")] = "",
    password_selector: Annotated[str, Field(description="CSS selector for the password field; empty for auto-detect")] = "",
    submit_selector: Annotated[str, Field(description="CSS selector for the submit button; empty for auto-detect")] = "") -> dict:
    """Log in to a target with the operator's OWN credentials (authorized
    testing only) and persist the session cookies for all later browser
    tools in this session. The password is used transiently for the login
    form fill and is never stored — not in the session dir, not in the
    ledger, not in logs. Only the resulting cookies are saved (0600).
    After this, recon_inspect_page / discover / trace / capture / analyze_ui
    automatically browse as the logged-in user. Use recon_deauthenticate
    when done."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    for name, val in (("login_url", login_url), ("username", username),
                      ("password", password)):
        if not val or not val.strip():
            return _err(f"{name} is required", "invalid_input", f"pass a value for '{name}'")
    bmod, berr = _lane("browser_engine")
    if berr or not hasattr(bmod, "OwnedBrowser"):
        return _err("authentication requires the browser engine",
                    "unavailable",
                    "omnirecon.browser_engine is not available in this deployment")
    amod, aerr = _lane("auth")
    if aerr or not hasattr(amod, "perform_login"):
        return _err("authentication is unavailable", "unavailable",
                    "omnirecon.auth is not available in this deployment")
    try:
        browser = _open_browser(bmod)
        try:
            browser, page = _goto_resilient(browser, bmod, login_url.strip(),
                                            session_id, mgr)
            result = browser._run(amod.perform_login(
                browser, page.get("page_id"), session_id, login_url.strip(),
                username, password, username_selector, password_selector,
                submit_selector))
        finally:
            browser.shutdown()
    except Exception as e:  # noqa: BLE001
        return _err("authentication failed", "internal", str(e)[:300])
    # record THAT auth happened — never credential material (central
    # ledger redaction is the backstop, but we don't even send secrets)
    if result.get("ok"):
        _ledger_add(session_id, mgr, [_finding(
            "auth", f"Authenticated session: {login_url[:80]}",
            f"Login flow succeeded ({result.get('cookies_saved', 0)} cookies "
            f"saved). Evidence: {'; '.join(result.get('evidence', []))[:300]}. "
            "Later browser tools in this session browse as the logged-in user.",
            "OBSERVED", 0.85, "browser login flow + cookie capture",
            sources=[login_url], engine="rendered")])
    else:
        _ledger_add(session_id, mgr, [_finding(
            "auth", f"Authentication failed: {login_url[:80]}",
            f"Login flow did not succeed. Evidence: "
            f"{'; '.join(result.get('evidence', []))[:300]}. Auth-walled "
            "areas remain UNVERIFIED.",
            "UNVERIFIED", 0.6, "browser login flow attempted",
            sources=[login_url], engine="rendered")])
    try:
        mgr.checkpoint(session_id)
    except Exception:
        pass
    _audit(session_id, "authenticate",
           f"{login_url} ok={result.get('ok')}")
    # never return the password; redact the evidence (post-login landing URLs
    # can carry OAuth codes/tokens — the ledger copy is redacted centrally,
    # but this direct tool return bypasses it)
    return {"session_id": session_id, "ok": result.get("ok"),
            "evidence": _redact(result.get("evidence", [])),
            "cookies_saved": result.get("cookies_saved", 0),
            "note": "password was used transiently and not stored"}


@mcp.tool()
def recon_deauthenticate(session_id: Annotated[str, Field(description="Session ID returned by recon_start; every other tool needs it")]) -> dict:
    """Delete saved session cookies for a session (log out). Call when
    authenticated recon is done. Credentials were never stored; this
    removes the session cookies so later tools browse anonymously again."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    amod, aerr = _lane("auth")
    cleared = False
    if not aerr and hasattr(amod, "clear_cookies"):
        try:
            cleared = amod.clear_cookies(session_id)
        except Exception:
            pass
    _ledger_add(session_id, mgr, [_finding(
        "auth", "Session deauthenticated",
        "Saved auth cookies deleted; later browser tools browse anonymously.",
        "OBSERVED", 1.0, "cookie file removed", sources=[])])
    _audit(session_id, "deauthenticate", "")
    return {"session_id": session_id, "cookies_cleared": cleared}


@mcp.tool()
def recon_mock_network(
    session_id: Annotated[str, Field(description="Session ID returned by recon_start")],
    url: Annotated[str, Field(description="Full page URL to load and mock network on")],
    scenario: Annotated[str, Field(description="Edge state to simulate: 'api_down' (500s), 'slow' (3s delay), 'empty' (empty lists), 'unauthorized' (401s)")] = "api_down",
    url_pattern: Annotated[str, Field(description="Glob pattern for requests to mock, e.g. '**/api/*'")] = "**/api/*",
) -> dict:
    """Mock network responses to reveal edge-state UI. Real apps contain 2-3x
    more UI in error/empty/loading states than the happy path — this is how
    you see it. Loads the page, applies the mock scenario, captures the
    degraded UI (screenshot + DOM diff vs normal)."""
    mgr, err = _session_manager()
    if err:
        return err
    session, serr = _get_session(mgr, session_id)
    if serr:
        return serr
    if not url or not url.strip():
        return _err("url is required", "invalid_input",
                    "pass the full page URL as the 'url' argument")
    url = url.strip()

    bmod, berr = _lane("browser_engine")
    if berr or not hasattr(bmod, "OwnedBrowser"):
        return _err("browser engine unavailable", "internal",
                    "mock_network needs the Playwright browser")

    try:
        browser = _open_browser(bmod)
        try:
            browser, page = _goto_resilient(browser, bmod, url,
                                            session_id, mgr)
            pid = page.get("page_id")
            # Baseline: normal screenshot
            artifacts_dir = str(SESSIONS_ROOT / session_id / "artifacts")
            os.makedirs(artifacts_dir, exist_ok=True)
            baseline = browser.screenshot(pid, artifacts_dir=artifacts_dir)
            # Apply mock scenario and reload
            mock_result = browser.mock_scenario(pid, scenario, url_pattern)
            browser.goto(url, pid)
            # Wait for the app to react to mocked responses
            import time as _t
            _t.sleep(3)
            mocked_shot = browser.screenshot(pid, artifacts_dir=artifacts_dir)
            snap = browser.snapshot(pid)
            browser.clear_intercepts(pid)
        finally:
            browser.shutdown()
    except Exception as e:
        return _err("mock_network failed", "internal", str(e)[:300])

    items = [_finding(
        "workflow", f"Edge state: {scenario} on {url}",
        f"Mocked scenario '{scenario}' for {url_pattern}. "
        f"Compare baseline {baseline} vs mocked {mocked_shot} to see "
        f"error/empty/loading UI. Controls after mock: "
        f"{len(snap.get('controls', []))}.",
        "OBSERVED", 0.9, "network mocked in owned browser; UI re-rendered",
        sources=[url], route=url, engine="rendered",
        limitations="mocked responses are synthetic; real failure modes may differ")]
    ids = _ledger_add(session_id, mgr, items)
    return {"scenario": scenario, "url": url,
            "baseline_screenshot": baseline,
            "mocked_screenshot": mocked_shot,
            "finding_ids": ids,
            "note": "Compare the two screenshots to see edge-state UI"}


@mcp.tool()
def recon_auto_pilot(
    target: Annotated[str, Field(description="Target to reverse-engineer: full URL (https://...), OpenAPI doc URL, local repo path, or artifact file path")],
    depth: Annotated[str, Field(description="How deep to go: 'quick' (~2 min, rapid recon + top pages), 'standard' (~5 min, + network/UI/sourcemaps), 'deep' (~15 min, + all pages + endpoint probing)")] = "standard",
    max_pages: Annotated[int, Field(description="Max pages for deep browser inspection; 5 covers most sites")] = 5,
) -> dict:
    """AUTOPILOT — reverse-engineer a target with ONE call. Runs the full
    pipeline automatically (rapid recon → route discovery → deep page
    inspection → network capture → UI analysis → sourcemaps → endpoint
    probing → spec generation) and returns a build-ready reconstruction
    blueprint. Each step is isolated: one failing tool never kills the
    pipeline. Use this instead of orchestrating the individual tools."""
    import time
    t0 = time.time()
    ran, failed = [], []

    def _safe(name, fn, *args, **kwargs):
        try:
            out = fn(*args, **kwargs)
            if isinstance(out, dict) and out.get("error"):
                failed.append({"tool": name, "error": out.get("error", "")[:200]})
                return None
            ran.append(name)
            return out
        except Exception as e:
            failed.append({"tool": name, "error": str(e)[:200]})
            return None

    # Step 1: start session (rapid recon)
    start = _safe("recon_start", recon_start, target,
                  "thorough" if depth == "deep" else "fast")
    if not start or not start.get("session_id"):
        return {"error": "autopilot failed at recon_start",
                "detail": failed, "tools_run": ran}
    sid = start["session_id"]
    target_kind = start.get("target_kind", "url")

    # Branch on target kind: repos, artifacts, and API specs get their
    # dedicated engines, not the web crawl pipeline.
    if target_kind == "repo":
        _safe("recon_analyze_source", recon_analyze_source, sid, target)
        _safe("recon_verify_consistency", recon_verify_consistency, sid)
        spec_out = _safe("recon_generate_spec", recon_generate_spec, sid)
        elapsed = round(time.time() - t0, 1)
        ev2 = recon_get_evidence(sid)
        findings = ev2.get("findings", []) if isinstance(ev2, dict) else []
        by_class = {}
        for f in findings:
            c = f.get("classification", "?")
            by_class[c] = by_class.get(c, 0) + 1
        result = {
            "session_id": sid, "target": target, "target_kind": target_kind,
            "depth": depth, "elapsed_s": elapsed,
            "tools_run": ran, "tools_failed": failed,
            "evidence": {"total": len(findings), "by_classification": by_class},
        }
        if spec_out:
            result["spec"] = spec_out.get("sections", {})
            result["manifest"] = spec_out.get("manifest", {})
            result["manifest_path"] = spec_out.get("manifest_path", "")
            manifest = spec_out.get("manifest", {}) or {}
            build = manifest.get("build_tasks", [])
            research = manifest.get("research_tasks", [])
            result["next_steps"] = (
                f"Build {len(build)} tasks in manifest['build_tasks'] order. "
                f"{len(research)} research gaps to resolve. "
                f"Full blueprint in spec.sections.")
        return _contract(
            result,
            unknowns=[f["tool"] + ": " + f["error"] for f in failed],
            limitations=["repo analysis is static; runtime behavior not observed"])

    if target_kind == "artifact":
        _safe("recon_analyze_artifact", recon_analyze_artifact, sid, target)
        _safe("recon_verify_consistency", recon_verify_consistency, sid)
        spec_out = _safe("recon_generate_spec", recon_generate_spec, sid)
        elapsed = round(time.time() - t0, 1)
        ev2 = recon_get_evidence(sid)
        findings = ev2.get("findings", []) if isinstance(ev2, dict) else []
        by_class = {}
        for f in findings:
            c = f.get("classification", "?")
            by_class[c] = by_class.get(c, 0) + 1
        result = {
            "session_id": sid, "target": target, "target_kind": target_kind,
            "depth": depth, "elapsed_s": elapsed,
            "tools_run": ran, "tools_failed": failed,
            "evidence": {"total": len(findings), "by_classification": by_class},
        }
        if spec_out:
            result["spec"] = spec_out.get("sections", {})
            result["manifest"] = spec_out.get("manifest", {})
            result["manifest_path"] = spec_out.get("manifest_path", "")
            manifest = spec_out.get("manifest", {}) or {}
            build = manifest.get("build_tasks", [])
            research = manifest.get("research_tasks", [])
            result["next_steps"] = (
                f"Build {len(build)} tasks in manifest['build_tasks'] order. "
                f"{len(research)} research gaps to resolve. "
                f"Full blueprint in spec.sections.")
        return _contract(
            result,
            unknowns=[f["tool"] + ": " + f["error"] for f in failed],
            limitations=["binary analysis is static; method bodies not decompiled",
                         "string-mined URLs are unconfirmed until probed"])

    if target_kind == "api_spec":
        # Probe against the API's servers[0], not the spec document URL.
        base_url = ""
        try:
            from omnirecon import api_intel as AI
            info = AI.analyze_api_spec(target)
            servers = (info.get("servers") or [])
            if servers:
                base_url = servers[0].get("url", "") or ""
        except Exception:
            pass
        if depth != "quick":
            if base_url:
                _safe("recon_probe_endpoints", recon_probe_endpoints,
                       sid, base_url)
            else:
                _safe("recon_probe_endpoints", recon_probe_endpoints, sid)
        _safe("recon_verify_consistency", recon_verify_consistency, sid)
        spec_out = _safe("recon_generate_spec", recon_generate_spec, sid)
        elapsed = round(time.time() - t0, 1)
        ev2 = recon_get_evidence(sid)
        findings = ev2.get("findings", []) if isinstance(ev2, dict) else []
        by_class = {}
        for f in findings:
            c = f.get("classification", "?")
            by_class[c] = by_class.get(c, 0) + 1
        result = {
            "session_id": sid, "target": target, "target_kind": target_kind,
            "depth": depth, "elapsed_s": elapsed,
            "tools_run": ran, "tools_failed": failed,
            "evidence": {"total": len(findings), "by_classification": by_class},
        }
        if spec_out:
            result["spec"] = spec_out.get("sections", {})
            result["manifest"] = spec_out.get("manifest", {})
            result["manifest_path"] = spec_out.get("manifest_path", "")
            manifest = spec_out.get("manifest", {}) or {}
            build = manifest.get("build_tasks", [])
            research = manifest.get("research_tasks", [])
            result["next_steps"] = (
                f"Build {len(build)} tasks in manifest['build_tasks'] order. "
                f"{len(research)} research gaps to resolve. "
                f"Full blueprint in spec.sections.")
        return _contract(
            result,
            unknowns=[f["tool"] + ": " + f["error"] for f in failed],
            limitations=["API contract inferred from spec document; "
                         "behavioral probing results in manifest"])

    # Step 2: discover routes (url targets only)
    disc = _safe("recon_discover_routes", recon_discover_routes, sid,
                 max_pages=max_pages * 8 if depth == "deep" else 40,
                 max_depth=3)
    # Collect candidate page URLs from the ledger (route findings)
    ev = _safe("recon_get_evidence", recon_get_evidence, sid, type="route")
    page_urls = []
    if ev:
        for f in ev.get("findings", [])[: max_pages * 2]:
            u = f.get("route") or f.get("url")
            if u and u not in page_urls:
                page_urls.append(u)
    if not page_urls:
        # fall back to the target itself
        page_urls = [target] if target.startswith("http") else []
    main_url = page_urls[0] if page_urls else ""

    # Step 3: deep-inspect top pages (browser)
    inspect_n = {"quick": 2, "standard": max_pages, "deep": max_pages * 2}[depth]
    for url in page_urls[:inspect_n]:
        _safe("recon_inspect_page", recon_inspect_page, sid, url)

    # Step 4: network + UI + assets on the main page
    if main_url:
        _safe("recon_capture_network", recon_capture_network, sid, main_url)
        _safe("recon_analyze_ui", recon_analyze_ui, sid, main_url)
        _safe("recon_extract_assets", recon_extract_assets, sid, main_url)
        if depth != "quick":
            _safe("recon_recover_sourcemaps", recon_recover_sourcemaps,
                   sid, main_url)

    # Step 5: endpoint probing (standard/deep only)
    if depth != "quick":
        _safe("recon_probe_endpoints", recon_probe_endpoints, sid)

    # Step 5b: edge-state mocking (deep only) — reveal error/empty UI
    if depth == "deep" and main_url:
        _safe("recon_mock_network", recon_mock_network, sid, main_url,
              "api_down")

    # Step 6: consistency check + spec
    _safe("recon_verify_consistency", recon_verify_consistency, sid)
    spec_out = _safe("recon_generate_spec", recon_generate_spec, sid)

    elapsed = round(time.time() - t0, 1)
    # Evidence + manifest summary for the agent
    ev2 = recon_get_evidence(sid)
    findings = ev2.get("findings", []) if isinstance(ev2, dict) else []
    by_class = {}
    for f in findings:
        c = f.get("classification", "?")
        by_class[c] = by_class.get(c, 0) + 1

    result = {
        "session_id": sid,
        "target": target,
        "depth": depth,
        "elapsed_s": elapsed,
        "tools_run": ran,
        "tools_failed": failed,
        "evidence": {"total": len(findings), "by_classification": by_class},
    }
    if spec_out:
        result["spec"] = spec_out.get("sections", {})
        result["manifest"] = spec_out.get("manifest", {})
        result["manifest_path"] = spec_out.get("manifest_path", "")
        # Build-ready summary: what the agent should do next
        manifest = spec_out.get("manifest", {}) or {}
        build = manifest.get("build_tasks", [])
        research = manifest.get("research_tasks", [])
        result["next_steps"] = (
            f"Build {len(build)} tasks in manifest['build_tasks'] order "
            f"(routes → endpoints → components → workflows). "
            f"{len(research)} research gaps in manifest['research_tasks'] — "
            f"resolve BLOCKED/UNVERIFIED items before treating the spec as complete. "
            f"Full blueprint in spec.sections."
        )
    else:
        result["error"] = "spec generation failed"
    return _contract(
        result,
        unknowns=[f["tool"] + ": " + f["error"] for f in failed],
        limitations=[
            "browser tools may fail on bot-protected targets; "
            "static findings remain",
            "UNVERIFIED findings need targeted follow-up before building",
        ],
    )


if __name__ == "__main__":
    mcp.run()
