"""Reconstruction blueprint generator.

generate_spec(ledger, graph) -> dict
Builds the evidence-linked reconstruction blueprint (§8 of ARCHITECTURE.md).

Inputs are duck-typed so the spec generator works with Lane B's EvidenceLedger
(ledger.list()) or a plain list of finding dicts, and with a graph dict
{nodes, edges} or an object exposing them.

Rules: every bullet carries finding_ids. Missing evidence is marked
UNVERIFIED/BLOCKED explicitly — nothing is invented.
"""
from __future__ import annotations

import datetime
from collections import Counter

VALID_CLASS = ("OBSERVED", "SOURCE_VERIFIED", "INFERRED", "UNVERIFIED", "BLOCKED")

# The 15 named sections from ARCHITECTURE.md §8 (listed as "14 sections").
SECTION_NAMES = [
    "overview", "tech_stack", "routes", "components", "user_journeys",
    "api_inventory", "data_entities", "assets_tokens", "auth_boundaries",
    "functional_requirements", "visual_requirements", "edge_cases",
    "test_plan", "open_questions", "priorities",
]


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _findings_of(ledger) -> list[dict]:
    if ledger is None:
        return []
    if isinstance(ledger, list):
        return [f for f in ledger if isinstance(f, dict)]
    if hasattr(ledger, "list"):
        try:
            res = ledger.list()
            if isinstance(res, list):
                return res
        except Exception:
            return []
    return []


def _graph_of(graph) -> dict:
    if graph is None:
        return {"nodes": [], "edges": []}
    if isinstance(graph, dict):
        return {"nodes": graph.get("nodes", []), "edges": graph.get("edges", [])}
    return {
        "nodes": list(getattr(graph, "nodes", []) or []),
        "edges": list(getattr(graph, "edges", []) or []),
    }


def _by_type(findings: list[dict], ftype: str) -> list[dict]:
    return [f for f in findings if f.get("type") == ftype]


def _b(text: str, finding_ids=None, classification: str = "INFERRED",
       confidence: float = 0.5, why: str = "") -> dict:
    if classification not in VALID_CLASS:
        classification = "INFERRED"
    return {
        "text": text,
        "finding_ids": list(finding_ids or []),
        "classification": classification,
        "confidence": max(0.0, min(1.0, float(confidence))),
        "confidence_why": why,
    }


def _section(name: str, bullets: list[dict], note: str = "") -> dict:
    if not bullets:
        status = "missing"
    elif all(b["classification"] in ("UNVERIFIED", "BLOCKED") for b in bullets):
        status = "missing"
    elif any(b["classification"] in ("UNVERIFIED", "BLOCKED") for b in bullets):
        status = "partial"
    else:
        status = "ok"
    return {"name": name, "status": status, "note": note, "bullets": bullets}


def _ids(findings: list[dict]) -> list[str]:
    return [f.get("id") for f in findings if f.get("id")]


# ---------------------------------------------------------------------------
# section builders
# ---------------------------------------------------------------------------

def _overview(findings: list[dict]) -> dict:
    by_class = Counter(f.get("classification", "?") for f in findings)
    by_type = Counter(f.get("type", "?") for f in findings)
    sources = Counter()
    for f in findings:
        for s in f.get("sources", []) or []:
            sources[str(s).split("?")[0].rstrip("/")] += 1
    target = sources.most_common(1)[0][0] if sources else None
    bullets = []
    if target:
        bullets.extend([
            _b(f"Reverse-engineering blueprint for {target}, derived from "
               f"{len(findings)} evidence findings.",
               _ids(findings), "INFERRED", 0.8,
               "target inferred from the most common finding source"),
            _b(f"Evidence mix: {dict(by_class)}. Finding types: {dict(by_type)}.",
               _ids(findings), "OBSERVED", 0.95,
               "counts computed directly from the evidence ledger"),
        ])
        blocked = [f for f in findings if f.get("classification") == "BLOCKED"]
        if blocked:
            bullets.append(_b(
                f"{len(blocked)} findings are BLOCKED (could not be investigated "
                "with available access); the blueprint marks dependent requirements "
                "as unverified rather than guessing.",
                _ids(blocked), "OBSERVED", 0.95,
                "blocked findings counted from the ledger"))
    else:
        bullets.append(_b(
            "Target unknown: no findings in the ledger, so the blueprint "
            "cannot describe any target. Run recon_start / "
            "recon_discover_routes / recon_inspect_page first.",
            [], "BLOCKED", 1.0, "ledger is empty"))
    return _section("overview", bullets)


def _tech_stack(findings: list[dict]) -> dict:
    tech = _by_type(findings, "tech")
    bullets = []
    for f in tech:
        bullets.append(_b(
            f"{f.get('title', 'technology')}: {f.get('detail', '')}".rstrip(": "),
            [f.get("id")] if f.get("id") else [],
            f.get("classification", "INFERRED"),
            f.get("confidence", 0.5),
            f.get("confidence_why", "")))
    if not bullets:
        bullets.append(_b(
            "No technology-stack evidence recorded. Framework, CDN, and "
            "infrastructure choices are unknown — do not assume React/Next.js.",
            [], "BLOCKED", 1.0,
            "no tech findings in the ledger"))
    return _section("tech_stack", bullets)


def _routes(findings: list[dict], graph: dict) -> dict:
    routes = _by_type(findings, "route")
    gnodes = [n for n in graph.get("nodes", [])
              if isinstance(n, dict) and n.get("kind") == "route"]
    seen: dict[str, dict] = {}
    for f in routes:
        key = f.get("route") or f.get("title")
        if key and key not in seen:
            seen[key] = f
    for n in gnodes:
        key = n.get("route") or n.get("id")
        if key and key not in seen:
            seen[key] = {"id": n.get("finding_id"), "title": key,
                         "classification": "INFERRED", "confidence": 0.4,
                         "confidence_why": "route appears only in the graph, "
                         "not as a direct finding"}
    bullets = []
    for key, f in sorted(seen.items()):
        fid = [f.get("id")] if f.get("id") else []
        bullets.append(_b(
            f"Route {key}" + (f" — {f.get('detail')}" if f.get("detail") else ""),
            fid, f.get("classification", "INFERRED"),
            f.get("confidence", 0.5), f.get("confidence_why", "")))
    if not bullets:
        bullets.append(_b(
            "No routes discovered. The route inventory is empty — run "
            "recon_discover_routes before planning any reconstruction.",
            [], "BLOCKED", 1.0, "no route findings and no route graph nodes"))
    return _section("routes", bullets)


def _components(findings: list[dict]) -> dict:
    comps = _by_type(findings, "component")
    bullets = [_b(
        f"{f.get('title', 'component')}"
        + (f" — {f.get('detail')}" if f.get("detail") else "")
        + (f" (route: {f.get('route')})" if f.get("route") else ""),
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "INFERRED"), f.get("confidence", 0.5),
        f.get("confidence_why", "")) for f in comps]
    if not bullets:
        bullets.append(_b(
            "No UI components extracted. Component hierarchy is UNVERIFIED; "
            "recon_inspect_page on key routes would populate this.",
            [], "UNVERIFIED", 1.0, "no component findings in the ledger"))
    return _section("components", bullets)


def _user_journeys(findings: list[dict]) -> dict:
    flows = _by_type(findings, "workflow")
    bullets = [_b(
        f"{f.get('title', 'workflow')}"
        + (f": {f.get('detail')}" if f.get("detail") else ""),
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "INFERRED"), f.get("confidence", 0.5),
        f.get("confidence_why", "")) for f in flows]
    if not bullets:
        bullets.append(_b(
            "No user journeys traced. Multi-step workflows, validation rules, "
            "and state transitions are UNVERIFIED — recon_trace_workflow has "
            "not produced evidence.",
            [], "UNVERIFIED", 1.0, "no workflow findings in the ledger"))
    return _section("user_journeys", bullets)


def _api_inventory(findings: list[dict]) -> dict:
    eps = _by_type(findings, "endpoint")
    bullets = []
    for f in eps:
        ep = f.get("endpoint") or f.get("title", "")
        bullets.append(_b(
            f"{ep}" + (f" — {f.get('detail')}" if f.get("detail") else ""),
            [f.get("id")] if f.get("id") else [],
            f.get("classification", "INFERRED"), f.get("confidence", 0.5),
            f.get("confidence_why", "")))
    if not bullets:
        bullets.append(_b(
            "No API endpoints recorded. Client-server boundaries are unknown; "
            "run recon_capture_network / extract_api_surface before designing "
            "any backend integration.",
            [], "BLOCKED", 1.0, "no endpoint findings in the ledger"))
    else:
        bullets.append(_b(
            "Only endpoints listed above may be treated as real. Do not invent "
            "undocumented backend behavior, request/response schemas, or auth "
            "requirements beyond what the findings state.",
            _ids(eps), "OBSERVED", 0.9,
            "scoping rule: evidence ledger is the closed world"))
    return _section("api_inventory", bullets)


def _data_entities(findings: list[dict]) -> dict:
    ents = _by_type(findings, "entity")
    bullets = [_b(
        f"{f.get('title', 'entity')}"
        + (f": {f.get('detail')}" if f.get("detail") else ""),
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "INFERRED"), f.get("confidence", 0.5),
        f.get("confidence_why", "")) for f in ents]
    if not bullets:
        bullets.append(_b(
            "No data entities inferred. Domain models, relationships, and "
            "schemas are UNVERIFIED — a reconstruction must treat persistence "
            "as an open design decision, not a recovered schema.",
            [], "UNVERIFIED", 1.0, "no entity findings in the ledger"))
    return _section("data_entities", bullets)


def _assets_tokens(findings: list[dict]) -> dict:
    assets = _by_type(findings, "asset")
    bullets = [_b(
        f"{f.get('title', 'asset')}"
        + (f": {f.get('detail')}" if f.get("detail") else ""),
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "INFERRED"), f.get("confidence", 0.5),
        f.get("confidence_why", "")) for f in assets]
    if not bullets:
        bullets.append(_b(
            "No asset/design-token inventory. Images, fonts, icons, colors, and "
            "spacing are UNVERIFIED — recon_extract_assets has not run.",
            [], "UNVERIFIED", 1.0, "no asset findings in the ledger"))
    return _section("assets_tokens", bullets)


def _auth_boundaries(findings: list[dict]) -> dict:
    auth = _by_type(findings, "auth")
    bullets = [_b(
        f"{f.get('title', 'auth finding')}"
        + (f": {f.get('detail')}" if f.get("detail") else ""),
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "INFERRED"), f.get("confidence", 0.5),
        f.get("confidence_why", "")) for f in auth]
    if not bullets:
        bullets.append(_b(
            "No authentication/authorization evidence. Login flows, session "
            "handling, and access boundaries are UNVERIFIED — do not assume "
            "the target is public or that any area requires login.",
            [], "UNVERIFIED", 1.0, "no auth findings in the ledger"))
    return _section("auth_boundaries", bullets)


def _functional_requirements(findings: list[dict]) -> dict:
    bullets = []
    for f in _by_type(findings, "workflow"):
        bullets.append(_b(
            f"Support the user journey: {f.get('title', '')}"
            + (f" — {f.get('detail')}" if f.get("detail") else ""),
            [f.get("id")] if f.get("id") else [], "INFERRED", 0.6,
            "requirement derived from an observed workflow"))
    for f in _by_type(findings, "route"):
        if f.get("route"):
            bullets.append(_b(
                f"Serve route {f.get('route')} with the recorded content and "
                "navigation behavior.",
                [f.get("id")] if f.get("id") else [], "INFERRED", 0.6,
                "requirement derived from an observed route"))
    for f in _by_type(findings, "endpoint"):
        if f.get("endpoint"):
            bullets.append(_b(
                f"Integrate endpoint {f.get('endpoint')} where the UI depends "
                "on it; if the backend is unavailable, simulate it explicitly "
                "and label the build 'frontend reconstruction'.",
                [f.get("id")] if f.get("id") else [], "INFERRED", 0.55,
                "requirement derived from an observed endpoint"))
    if not bullets:
        bullets.append(_b(
            "No functional requirements can be stated — no routes, workflows, "
            "or endpoints are evidenced. Requirements are BLOCKED on analysis.",
            [], "BLOCKED", 1.0, "no actionable findings in the ledger"))
    return _section("functional_requirements", bullets,
                    note="Derived requirements; each is only as strong as its evidence.")


def _visual_requirements(findings: list[dict]) -> dict:
    shots = [f for f in findings
             if str(f.get("artifact") or "").endswith(
                 (".png", ".jpg", ".jpeg", ".webp"))]
    bullets = [_b(
        f"Match the captured visual reference {f.get('artifact')} "
        f"({f.get('title', '')}).",
        [f.get("id")] if f.get("id") else [],
        f.get("classification", "OBSERVED"), f.get("confidence", 0.7),
        "screenshot artifact on file") for f in shots]
    if not bullets:
        bullets.append(_b(
            "No visual references captured. Layout, typography, spacing, and "
            "responsive behavior are UNVERIFIED — screenshots at desktop, "
            "tablet, and mobile viewports are needed before visual fidelity "
            "can be specified.",
            [], "UNVERIFIED", 1.0, "no screenshot artifacts in the ledger"))
    return _section("visual_requirements", bullets)


def _edge_cases(findings: list[dict]) -> dict:
    states = _by_type(findings, "state")
    notes = [f for f in _by_type(findings, "note")
             if "error" in (f.get("title", "") + f.get("detail", "")).lower()]
    bullets = []
    for f in states + notes:
        bullets.append(_b(
            f"{f.get('title', 'edge case')}"
            + (f": {f.get('detail')}" if f.get("detail") else ""),
            [f.get("id")] if f.get("id") else [],
            f.get("classification", "INFERRED"), f.get("confidence", 0.5),
            f.get("confidence_why", "")))
    if not bullets:
        bullets.append(_b(
            "No loading/empty/error states recorded. Edge-case behavior is "
            "UNVERIFIED — the reconstruction must still handle network "
            "failures, empty data, and invalid input defensively.",
            [], "UNVERIFIED", 1.0,
            "no state or error findings in the ledger"))
    return _section("edge_cases", bullets)


def _test_plan(findings: list[dict]) -> dict:
    bullets = []
    for f in _by_type(findings, "route"):
        if f.get("route"):
            bullets.append(_b(
                f"Route test: GET {f.get('route')} returns 2xx and renders the "
                "recorded title/content.",
                [f.get("id")] if f.get("id") else [], "INFERRED", 0.6,
                "plan item generated from an observed route; not yet executed"))
    for f in _by_type(findings, "endpoint"):
        if f.get("endpoint"):
            bullets.append(_b(
                f"API test: exercise {f.get('endpoint')} with the observed "
                "method and assert the recorded status/content-type.",
                [f.get("id")] if f.get("id") else [], "INFERRED", 0.55,
                "plan item generated from an observed endpoint; not yet executed"))
    for f in _by_type(findings, "workflow"):
        bullets.append(_b(
            f"Workflow test: replay '{f.get('title', '')}' and assert each "
            "recorded state transition.",
            [f.get("id")] if f.get("id") else [], "INFERRED", 0.55,
            "plan item generated from an observed workflow; not yet executed"))
    if _by_type(findings, "route"):
        bullets.append(_b(
            "Accessibility check: keyboard-navigate every recorded route; assert "
            "visible focus and no console errors on load.",
            _ids(_by_type(findings, "route")), "INFERRED", 0.5,
            "standard gate; not yet executed"))
    if len(bullets) == 1:
        bullets.insert(0, _b(
            "Test plan is skeletal — almost no routes, endpoints, or workflows "
            "are evidenced. Expand analysis before treating this plan as "
            "coverage.",
            [], "UNVERIFIED", 0.8,
            "plan generated from a near-empty ledger"))
    return _section("test_plan", bullets,
                    note="Plan items are generated, not executed. "
                    "recon_compare_build verifies a build against this plan.")


def _open_questions(findings: list[dict]) -> dict:
    bullets = []
    for f in findings:
        if f.get("classification") in ("BLOCKED", "UNVERIFIED") and f.get("limitations"):
            bullets.append(_b(
                f"{f.get('title', f.get('id', 'finding'))}: "
                f"{f.get('limitations')}",
                [f.get("id")] if f.get("id") else [],
                f.get("classification"), f.get("confidence", 0.5),
                "open because the underlying finding is "
                f"{f.get('classification')}"))
    if not _by_type(findings, "auth"):
        bullets.append(_b(
            "Is any part of the target behind authentication? No auth evidence "
            "was captured.",
            [], "UNVERIFIED", 0.7, "auth section empty"))
    if not _by_type(findings, "entity"):
        bullets.append(_b(
            "What is the domain data model? No entities were inferred from "
            "API responses or forms.",
            [], "UNVERIFIED", 0.7, "entity section empty"))
    if not findings:
        bullets.append(_b(
            "Everything: the ledger is empty, so every question about the "
            "target is open.",
            [], "BLOCKED", 1.0, "no findings at all"))
    return _section("open_questions", bullets)


def _priorities(findings: list[dict]) -> dict:
    b_blocked = [f for f in findings if f.get("classification") == "BLOCKED"]
    b_unver = [f for f in findings if f.get("classification") == "UNVERIFIED"]
    b_infer = [f for f in findings if f.get("classification") == "INFERRED"]
    bullets = []
    if b_blocked:
        bullets.append(_b(
            f"P0 — Unblock {len(b_blocked)} BLOCKED findings "
            f"({', '.join(_ids(b_blocked)[:8])}"
            f"{'…' if len(b_blocked) > 8 else ''}): they gate requirements.",
            _ids(b_blocked), "INFERRED", 0.85,
            "blocked evidence is the critical path"))
    if b_unver:
        bullets.append(_b(
            f"P1 — Verify {len(b_unver)} UNVERIFIED findings with targeted "
            "re-observation (inspect page, capture network, trace workflow).",
            _ids(b_unver), "INFERRED", 0.8,
            "unverified claims must not drive implementation"))
    if b_infer:
        bullets.append(_b(
            f"P2 — Strengthen {len(b_infer)} INFERRED findings to OBSERVED "
            "where the inference affects architecture choice.",
            _ids(b_infer), "INFERRED", 0.7,
            "inferences are the weakest load-bearing claims"))
    if findings:
        bullets.append(_b(
            "P3 — Implement routes, then API integration, then workflows, then "
            "visual polish — in that order, verifying each against "
            "recon_compare_build before moving on.",
            _ids(findings), "INFERRED", 0.75,
            "order minimizes rework: structure before behavior before surface"))
    else:
        bullets.insert(0, _b(
            "P0 — Run the analysis pipeline: the ledger is empty and there is "
            "nothing to prioritize yet.",
            [], "BLOCKED", 1.0, "no findings at all"))
    return _section("priorities", bullets)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def generate_spec(ledger, graph=None) -> dict:
    """Build the reconstruction blueprint from evidence.

    ledger: EvidenceLedger (has .list()) or list of finding dicts.
    graph:  {nodes, edges} dict or object with .nodes/.edges.
    Returns a JSON-serializable dict with the §8 sections.
    """
    findings = _findings_of(ledger)
    g = _graph_of(graph)
    sections = {
        "overview": _overview(findings),
        "tech_stack": _tech_stack(findings),
        "routes": _routes(findings, g),
        "components": _components(findings),
        "user_journeys": _user_journeys(findings),
        "api_inventory": _api_inventory(findings),
        "data_entities": _data_entities(findings),
        "assets_tokens": _assets_tokens(findings),
        "auth_boundaries": _auth_boundaries(findings),
        "functional_requirements": _functional_requirements(findings),
        "visual_requirements": _visual_requirements(findings),
        "edge_cases": _edge_cases(findings),
        "test_plan": _test_plan(findings),
        "open_questions": _open_questions(findings),
        "priorities": _priorities(findings),
    }
    return {
        "meta": {
            "generated_utc": _utcnow(),
            "finding_count": len(findings),
            "by_classification": dict(Counter(
                f.get("classification", "?") for f in findings)),
            "by_type": dict(Counter(f.get("type", "?") for f in findings)),
            "graph_nodes": len(g.get("nodes", [])),
            "graph_edges": len(g.get("edges", [])),
            "sections": list(sections.keys()),
        },
        "sections": sections,
    }
