"""Phase-1 scope ledger (analyst-dossier methodology).

Before any deep recon runs, record WHAT may be touched: target ownership,
Terms-of-Service status, robots.txt, the access method, and the in-scope /
out-of-scope boundary. The boundary is non-negotiable — anything outside it
becomes a BLOCKED finding, never an action.

Ownership tiers (from the methodology):
  - owned:       the operator's own target — full-depth analysis allowed
                 (source, API contracts, auth flows, config)
  - open-source: public project — source + public surface analysis allowed
  - third-party: default — public visitor surface only
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

OWNERSHIP_TIERS = ("owned", "open-source", "third-party")

_TOS_PATHS = ("/terms", "/terms-of-service", "/tos", "/legal/terms",
              "/legal")

# What a normal visitor's browser receives — always in scope.
IN_SCOPE_PUBLIC = [
    "public HTML, CSS, JS bundles served to every visitor",
    "HTTP response headers and status codes",
    "robots.txt and sitemap.xml",
    "public documentation, OpenAPI/GraphQL schemas, status pages, changelogs",
    "DNS records and TLS certificate metadata",
    "sourcemaps served at the URL the page itself references",
]

# Never in scope, regardless of tier.
OUT_OF_SCOPE_ALWAYS = [
    "auth bypass, credential brute-force, token replay",
    "calling undocumented or guessed endpoints; fuzzing",
    "testing authorization boundaries",
    "exceeding 1 request/second against the target",
    "evading bot protection, CAPTCHAs, or paywalls",
    "scraping behind logins without explicit operator credentials",
]


def _base_of(target: str) -> str:
    try:
        p = urlparse(target)
        if p.scheme in ("http", "https") and p.hostname:
            return urlunparse((p.scheme, p.hostname, "", "", "", ""))
    except Exception:
        pass
    return ""


def _looks_local(target: str) -> bool:
    t = (target or "").lower()
    return (t.startswith("http://127.") or t.startswith("http://localhost")
            or "localhost:" in t or t.startswith("file:")
            or not re.match(r"^https?://", t))


def check_tos(base_url: str, get=None) -> dict:
    """Polite ToS probe: GET common ToS paths, record what exists.

    `get` is an injectable (url, timeout) -> response for tests.
    Returns {"checked": [...], "found": <path|None>, "status": ...}.
    """
    import httpx
    checked = []
    found = None
    status = "not-found"
    for path in _TOS_PATHS:
        url = base_url + path
        checked.append(path)
        try:
            if get is not None:
                r = get(url, timeout=8)
            else:
                with httpx.Client(timeout=8, follow_redirects=True,
                                  headers={"User-Agent": "OmniRecon/2.3 (+scope-check)"}) as c:
                    r = c.get(url)
            code = getattr(r, "status_code", 0)
            if code == 200 and len(getattr(r, "content", b"") or b"") > 500:
                found, status = path, "found"
                break
            if code in (403, 401):
                status = "blocked"
        except Exception:
            continue
    return {"checked": checked, "found": found, "status": status}


def check_robots(base_url: str) -> dict:
    """Minimal robots.txt presence check (polite, single request)."""
    try:
        from omnirecon import recon_primitives as RP
        info = RP._robots(base_url)
        return {"present": bool(info.get("present")),
                "disallow_rules": info.get("disallow_rules", 0)}
    except Exception:
        return {"present": False, "disallow_rules": 0}


def build_scope(target: str, ownership: str = "third-party",
                tos_result: dict | None = None,
                robots_result: dict | None = None) -> dict:
    """Build the scope ledger table for a target. Pure logic; no I/O when
    tos_result/robots_result are supplied (tests inject them)."""
    ownership = (ownership or "third-party").lower()
    if ownership not in OWNERSHIP_TIERS:
        ownership = "third-party"
    # Local targets are the operator's own machine by construction.
    if _looks_local(target) and ownership == "third-party":
        ownership = "owned"

    base = _base_of(target)
    tos = tos_result or {"status": "not-checked", "found": None, "checked": []}
    robots = robots_result or {"present": False}

    if ownership == "owned":
        in_scope = IN_SCOPE_PUBLIC + [
            "local source code and configuration",
            "API contracts and auth flows (operator-authorized)",
        ]
        access = "operator-authorized (local target / explicit ownership)"
    elif ownership == "open-source":
        in_scope = IN_SCOPE_PUBLIC + [
            "public repository source code",
        ]
        access = "public visitor + public source"
    else:
        in_scope = list(IN_SCOPE_PUBLIC)
        access = "unauthenticated public visitor"

    return {
        "target": target,
        "base_url": base,
        "ownership": ownership,
        "tos": tos,
        "robots_txt": robots,
        "access_method": access,
        "in_scope": in_scope,
        "out_of_scope": list(OUT_OF_SCOPE_ALWAYS),
        "rate_limit": "max 1 request/second (self-imposed)",
    }


def scope_summary(ledger: dict) -> str:
    """One-paragraph human summary for findings and reports."""
    tos = ledger.get("tos", {}).get("status", "?")
    return (f"Target {ledger['target']} classified as {ledger['ownership']}; "
            f"access: {ledger['access_method']}; ToS: {tos}; "
            f"robots.txt: {'present' if ledger.get('robots_txt', {}).get('present') else 'absent'}. "
            f"{len(ledger['in_scope'])} in-scope categories, "
            f"{len(ledger['out_of_scope'])} hard out-of-scope rules.")
