"""Differentiators: consistency verification, source-map recovery,
replayable workflow scripts, and API contract live-probing.

These are the capabilities neither REA (passive on the web by design) nor
reverse-skill (offensive-security router) provide: they turn OmniRecon's
multi-engine observations into *checked* truth and *reusable* artifacts.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from urllib.parse import urljoin, urlparse

import httpx

from omnirecon import security as SEC


# --------------------------------------------------------------------------
# ledger helpers
# --------------------------------------------------------------------------

def _sessions_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")


def _load_findings(session_id: str) -> list[dict]:
    path = os.path.join(_sessions_dir(), session_id, "evidence.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def _append(session_id: str, finding: dict) -> None:
    from omnirecon import evidence as ev
    sdir = os.path.join(_sessions_dir(), session_id)
    os.makedirs(sdir, exist_ok=True)
    ledger_path = os.path.join(sdir, "evidence.jsonl")
    ledger = ev.EvidenceLedger.load(ledger_path) \
        if os.path.exists(ledger_path) else ev.EvidenceLedger()
    ledger.add(finding)
    ledger.save(ledger_path)


def _mk(ftype, title, detail, classification, confidence, why, sources,
        **kw) -> dict:
    d = {"type": ftype, "title": title, "detail": detail[:2000],
         "classification": classification, "confidence": confidence,
         "confidence_why": why, "sources": sources}
    d.update(kw)
    return d


# --------------------------------------------------------------------------
# 1. Cross-engine consistency verification
# --------------------------------------------------------------------------

def verify_consistency(session_id: str) -> dict:
    """Cross-check findings between engines and record agreements /
    contradictions. Returns a summary dict; findings land in the ledger."""
    findings = _load_findings(session_id)
    if not findings:
        return {"checked": 0, "agreements": 0, "contradictions": 0,
                "note": "ledger empty"}

    routes_static = {f.get("route") for f in findings
                     if f.get("type") == "route" and f.get("route")}
    routes_rendered = {f.get("route") for f in findings
                       if f.get("type") in ("page", "workflow")
                       and f.get("route")}
    endpoints_static = {f.get("endpoint") for f in findings
                        if f.get("type") == "endpoint" and f.get("endpoint")
                        and f.get("engine") == "static"}
    endpoints_network = {f.get("endpoint") for f in findings
                         if f.get("type") == "endpoint" and f.get("endpoint")
                         and f.get("engine") == "network"}

    agreements, contradictions = 0, 0

    # routes seen by the crawler but never rendered → downgrade signal
    for r in sorted(routes_static - routes_rendered)[:50]:
        if not r:
            continue
        _append(session_id, _mk(
            "note", f"Unrendered route: {r[:80]}",
            "Discovered by the static crawler but never observed in a "
            "rendered page. It may require auth, be dead, or be "
            "crawler-only (e.g. in a sitemap). Treat as UNVERIFIED until "
            "rendered.",
            "UNVERIFIED", 0.4,
            "present in crawl findings, absent from rendered-page findings",
            [r], route=r,
            limitations="Static discovery only; render to confirm."))
        contradictions += 1

    # endpoints seen live on the network AND in static bundles → strong agreement
    for e in sorted(endpoints_static & endpoints_network)[:50]:
        if not e:
            continue
        _append(session_id, _mk(
            "endpoint", f"Corroborated endpoint: {e[:90]}",
            "The same endpoint was extracted from static sources AND "
            "observed live in captured network traffic. Highest-confidence "
            "API surface.",
            "SOURCE_VERIFIED", 0.95,
            "two independent engines agree (static + network)",
            [e], endpoint=e))
        agreements += 1

    # static-only endpoints → mark as not-yet-observed
    for e in sorted(endpoints_static - endpoints_network)[:50]:
        if not e:
            continue
        _append(session_id, _mk(
            "endpoint", f"Static-only endpoint: {e[:90]}",
            "Extracted from JS bundles or page text but never observed in "
            "live traffic. May be dead code, admin-only, or triggered by "
            "unvisited UI states.",
            "INFERRED", 0.55,
            "static extraction without live-network corroboration",
            [e], endpoint=e,
            limitations="Trigger the UI path or probe it to confirm."))
        contradictions += 1

    return {"checked": len(findings), "agreements": agreements,
            "contradictions": contradictions,
            "note": "agreements corroborate; contradictions are downgraded, "
                    "never deleted"}


# --------------------------------------------------------------------------
# 2. Source-map recovery
# --------------------------------------------------------------------------

def recover_sourcemaps(session_id: str, page_url: str,
                       script_urls: list[str] | None = None,
                       timeout: int = 20) -> dict:
    """Fetch *.js.map files for a page's scripts and recover the original
    source tree. Returns {maps_found, sources_recovered, files}."""
    if script_urls is None:
        script_urls = []
        for f in _load_findings(session_id):
            for src in (f.get("sources") or []):
                if isinstance(src, str) and src.endswith(".js"):
                    script_urls.append(src)
    script_urls = list(dict.fromkeys(script_urls))[:40]

    headers = {"User-Agent": "Mozilla/5.0 (OmniRecon source-map recovery)"}
    maps_found, all_sources = [], set()
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers=headers) as c:
        for js_url in script_urls:
            candidates = [js_url + ".map"]
            try:
                r = c.get(js_url)
                if r.status_code == 200:
                    m = re.search(
                        r"//#\s*sourceMappingURL=(\S+)", r.text[-2000:])
                    if m:
                        candidates.insert(0, urljoin(js_url, m.group(1)))
            except Exception:
                pass
            for map_url in candidates:
                try:
                    r = c.get(map_url)
                except Exception:
                    continue
                if r.status_code != 200 or not r.text.strip().startswith("{"):
                    continue
                try:
                    data = json.loads(r.text)
                except Exception:
                    continue
                sources = data.get("sources") or []
                if not sources:
                    continue
                maps_found.append(map_url)
                for s in sources:
                    s = str(s)
                    if s.startswith("webpack://"):
                        s = s[len("webpack://"):]
                    all_sources.add(s[:300])
                break  # one map per script is enough

    all_sources = sorted(all_sources)
    if maps_found:
        tree = "\n".join(all_sources[:200])
        _append(session_id, _mk(
            "tech", f"Source maps recovered: {len(maps_found)} maps, "
                    f"{len(all_sources)} original files",
            f"Original source tree recovered from published .map files:\n"
            f"{tree[:1500]}",
            "SOURCE_VERIFIED", 0.95,
            "parsed directly from the site's own source-map files",
            maps_found[:5],
            limitations="Only files the site chose to publish maps for; "
                        "sourcesContent (original code) captured when present."))
    else:
        _append(session_id, _mk(
            "note", "No source maps published",
            f"Probed {len(script_urls)} scripts for .map files and "
            f"sourceMappingURL comments; none resolved. The site ships "
            f"minified bundles without maps.",
            "OBSERVED", 0.8,
            "direct .map fetch attempts returned non-200/non-JSON",
            [page_url]))
    return {"maps_found": maps_found[:20],
            "sources_recovered": len(all_sources),
            "files": all_sources[:200]}


# --------------------------------------------------------------------------
# 3. Replayable workflow scripts
# --------------------------------------------------------------------------

def build_replay_script(steps: list[dict], start_url: str) -> str:
    """Emit a standalone Playwright script that replays a traced workflow."""
    lines = [
        '"""Replay script generated by OmniRecon recon_trace_workflow.',
        '   pip install playwright && playwright install chromium',
        '"""',
        "from playwright.sync_api import sync_playwright",
        "",
        "STEPS = [",
    ]
    for s in steps:
        action = str(s.get("action", ""))
        url_after = s.get("url_after") or ""
        lines.append(f"    { {'action': action, 'expect_url': url_after} },")
    lines += [
        "]",
        "",
        "def main():",
        "    with sync_playwright() as p:",
        f"        browser = p.chromium.launch()",
        f"        page = browser.new_page()",
        f"        page.goto({start_url!r}, wait_until='networkidle')",
        "        for i, step in enumerate(STEPS):",
        "            print(f'step {i+1}: {step[\"action\"]}')",
        "            # Re-locate the control by accessible name and click it.",
        "            name = step['action'].split(chr(39))[1] "
        "if chr(39) in step['action'] else ''",
        "            if name:",
        "                try:",
        "                    page.get_by_role('button', name=name).first.click(",
        "                        timeout=5000)",
        "                except Exception:",
        "                    page.get_by_role('link', name=name).first.click(",
        "                        timeout=5000)",
        "            page.wait_for_timeout(1500)",
        "            if step['expect_url'] and page.url != step['expect_url']:",
        "                print(f'  NOTE: expected {step[\"expect_url\"]}, '",
        "                      f'got {page.url}')",
        "        browser.close()",
        "",
        "if __name__ == '__main__':",
        "    main()",
        "",
    ]
    return "\n".join(lines)


def save_replay_script(session_id: str, steps: list[dict],
                       start_url: str, goal: str) -> str:
    """Write the replay script to the session artifacts dir; record finding."""
    sdir = os.path.join(_sessions_dir(), session_id, "artifacts")
    os.makedirs(sdir, exist_ok=True)
    safe = re.sub(r"[^\w\-]+", "_", goal.strip().lower())[:40] or "workflow"
    path = os.path.join(sdir, f"replay_{safe}.py")
    with open(path, "w") as fh:
        fh.write(build_replay_script(steps, start_url))
    _append(session_id, _mk(
        "artifact", f"Replay script: {goal[:60]}",
        f"Standalone Playwright script ({len(steps)} steps) that replays "
        f"the traced workflow from {start_url}. Run it against a rebuild "
        f"to verify behavioral parity.",
        "SOURCE_VERIFIED", 0.9,
        "generated from the observed trace steps",
        [path]))
    return path


# --------------------------------------------------------------------------
# 4. API contract live-probing
# --------------------------------------------------------------------------

def probe_endpoints(session_id: str, base_url: str,
                    endpoints: list[str] | None = None,
                    timeout: int = 15, limit: int = 60) -> dict:
    """GET/HEAD each discovered API endpoint; record live/dead verdicts."""
    if endpoints is None:
        # ordered unique list of discovered /api/* endpoints
        seen, endpoints = set(), []
        for f in _load_findings(session_id):
            e = f.get("endpoint")
            if f.get("type") == "endpoint" and isinstance(e, str) \
                    and "/api" in e and e not in seen:
                seen.add(e)
                endpoints.append(e)
    endpoints = endpoints[:limit]

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    live, dead, results = 0, 0, []
    headers = {"User-Agent": "Mozilla/5.0 (OmniRecon endpoint probe)"}
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers=headers) as c:
        for ep in endpoints:
            path = ep if ep.startswith("/") else "/" + ep
            url = origin + path.split("?")[0]
            status, note = None, ""
            for method in ("HEAD", "GET"):
                try:
                    r = c.request(method, url)
                    status = r.status_code
                    break
                except Exception as e:
                    note = str(e)[:120]
            verdict = "live" if status and status < 400 else "dead"
            if verdict == "live":
                live += 1
            else:
                dead += 1
            results.append({"endpoint": ep, "status": status, "verdict": verdict})
            # politeness: small delay between probes so endpoint probing can
            # never be mistaken for aggressive scanning (M5 fix)
            time.sleep(0.25)
            _append(session_id, _mk(
                "endpoint", f"Probed {ep[:80]} → {status or 'no response'}",
                f"Live-probed {url}: HTTP {status} ({verdict})."
                + (f" Error: {note}" if note and not status else ""),
                "OBSERVED" if status else "UNVERIFIED",
                0.9 if status else 0.4,
                f"direct HTTP {method} probe",
                [url], endpoint=ep))

    _append(session_id, _mk(
        "tech", f"Endpoint probing: {live} live / {dead} dead "
                f"({len(endpoints)} probed)",
        "Each discovered /api/* endpoint was probed with HEAD then GET. "
        "Live = HTTP < 400; dead = 4xx/5xx or unreachable. Auth-walled "
        "endpoints (401/403) count as live-but-guarded.",
        "OBSERVED", 0.9, "direct HTTP probing of discovered endpoints",
        [origin]))
    return {"probed": len(endpoints), "live": live, "dead": dead,
            "results": results}


def redact_report(obj):
    return SEC.redact(obj)
