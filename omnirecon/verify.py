"""Build verification: compare a reconstruction against recorded reference behavior.

compare_build(session_id, build_url) -> dict
Only compares what the session actually recorded (routes, endpoints). Honest
about what it cannot check: no pixel-perfect claim without screenshot
comparison, which is explicitly out of scope for this version.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from urllib.parse import urlparse

from . import recon_primitives as RP

SESSIONS_ROOT = Path(__file__).resolve().parent.parent / "sessions"


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _load_findings(session_id: str) -> list[dict]:
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


def _path_of(url: str) -> str:
    try:
        p = urlparse(url).path or "/"
    except Exception:
        return url
    return p if p.startswith("/") else "/" + p


def _norm_endpoint(ep: str) -> str:
    """Normalize an endpoint for comparison: strip query, trailing slash."""
    ep = (ep or "").strip()
    if "://" in ep or ep.startswith("//"):
        return _path_of("https:" + ep if ep.startswith("//") else ep).rstrip("/") or "/"
    return ("/" + ep.lstrip("/")).split("?")[0].rstrip("/") or "/"


def compare_build(session_id: str, build_url: str) -> dict:
    """Compare a rebuilt implementation against the session's recorded evidence."""
    findings = _load_findings(session_id)
    recorded_routes = sorted({
        _path_of(f["route"]) for f in findings
        if f.get("type") == "route" and f.get("route")
    })
    recorded_eps = sorted({
        _norm_endpoint(f.get("endpoint") or "") for f in findings
        if f.get("type") == "endpoint" and f.get("endpoint")
    })

    result: dict = {
        "session_id": session_id,
        "build_url": build_url,
        "checked_utc": _utcnow(),
        "recorded_routes": len(recorded_routes),
        "recorded_endpoints": len(recorded_eps),
    }

    if not recorded_routes and not recorded_eps:
        result.update({
            "route_coverage": {"total": 0, "matched": 0, "missing": []},
            "endpoint_overlap": {"recorded": 0, "found_in_build": 0,
                                 "matched": [], "missing": []},
            "deviations": [],
            "screenshot_notes": "No reference routes or endpoints were recorded "
                                "for this session, so there is nothing to "
                                "compare. Run recon_discover_routes and "
                                "recon_capture_network first.",
            "limitations": "comparison requires recorded reference evidence",
        })
        return result

    # Probe the build: crawl its routes + extract its API surface.
    try:
        crawl = RP.crawl_site(build_url, max_pages=40, max_depth=2)
        build_routes = sorted({_path_of(p["url"]) for p in crawl.get("pages", [])})
    except Exception as e:
        build_routes = []
        crawl_error = str(e)[:200]
    else:
        crawl_error = ""

    try:
        surf = RP.extract_api_surface(build_url)
        build_eps = sorted({_norm_endpoint(e["endpoint"])
                            for e in surf.get("internal_endpoints", [])})
    except Exception:
        build_eps = []

    matched_routes = [r for r in recorded_routes if r in build_routes]
    missing_routes = [r for r in recorded_routes if r not in build_routes]
    matched_eps = [e for e in recorded_eps if e in build_eps]
    missing_eps = [e for e in recorded_eps if e not in build_eps]

    deviations: list[dict] = []
    for r in missing_routes:
        deviations.append({"kind": "missing_route", "severity": "high",
                           "detail": f"Recorded route {r} not found in the build."})
    for e in missing_eps:
        deviations.append({"kind": "missing_endpoint", "severity": "high",
                           "detail": f"Recorded endpoint {e} not observed in "
                                     "the build's client surface."})
    for r in build_routes:
        if r not in recorded_routes:
            deviations.append({"kind": "extra_route", "severity": "info",
                               "detail": f"Build serves {r}, which was not in "
                                         "the recorded reference."})
    if crawl_error:
        deviations.append({"kind": "crawl_error", "severity": "medium",
                           "detail": f"Could not fully crawl the build: {crawl_error}"})

    result.update({
        "route_coverage": {
            "total": len(recorded_routes),
            "matched": len(matched_routes),
            "missing": missing_routes,
            "build_route_count": len(build_routes),
        },
        "endpoint_overlap": {
            "recorded": len(recorded_eps),
            "found_in_build": len(build_eps),
            "matched": matched_eps,
            "missing": missing_eps,
        },
        "deviations": deviations,
        "screenshot_notes": (
            "Screenshot/pixel comparison is NOT performed by this version. "
            "Visual fidelity (layout, typography, spacing, responsive "
            "behavior) was not measured — only route presence and "
            "client-observable endpoints were compared. Do not claim "
            "pixel-perfect or feature-complete reproduction from this report."
        ),
        "limitations": (
            "Compares only recorded routes and client-observable endpoints. "
            "Workflows, auth-gated areas, and backend schemas are not "
            "re-verified here."
        ),
    })
    return result
