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
import re
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
            _b(f"{len(findings)} findings: "
               + ", ".join(f"{v} {k}" for k, v in by_class.most_common())
               + ". Types: "
               + ", ".join(f"{v} {k}" for k, v in by_type.most_common()) + ".",
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
    # Deduplicate by normalized endpoint: merge corroborating findings.
    seen: dict[str, dict] = {}
    for f in eps:
        ep = f.get("endpoint") or f.get("title", "")
        norm = ep.lower().split("?")[0].rstrip("/").strip()
        if not norm:
            continue
        if norm in seen:
            # Merge: keep the higher-confidence finding, union the IDs.
            cur = seen[norm]
            cur_ids = set(cur.get("finding_ids", []))
            if f.get("id"):
                cur_ids.add(f["id"])
            cur["finding_ids"] = sorted(cur_ids)
            if f.get("confidence", 0) > cur.get("confidence", 0):
                cur["text"] = f"{ep}" + (f" — {f.get('detail')}" if f.get("detail") else "")
                cur["classification"] = f.get("classification", cur["classification"])
                cur["confidence"] = f.get("confidence", cur["confidence"])
        else:
            seen[norm] = {
                "text": f"{ep}" + (f" — {f.get('detail')}" if f.get("detail") else ""),
                "finding_ids": [f["id"]] if f.get("id") else [],
                "classification": f.get("classification", "INFERRED"),
                "confidence": f.get("confidence", 0.5),
                "why": f.get("confidence_why", ""),
            }
    bullets = [_b(v["text"], v["finding_ids"], v["classification"],
                  v["confidence"], v["why"]) for v in seen.values()]
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
    routes = [f for f in _by_type(findings, "route") if f.get("route")]
    # Page-by-page build guidance, not robotic "serve route X".
    for f in routes:
        title = f.get("title", "")
        detail = f.get("detail", "")
        bullets.append(_b(
            f"BUILD PAGE: {f.get('route')}"
            + (f" (\u201c{title}\u201d)" if title else "")
            + f".\nReproduce its structure: {detail[:200]}"
            + "\nCheck the screenshots in visual_requirements for exact layout.",
            [f.get("id")] if f.get("id") else [], "INFERRED", 0.65,
            "page structure derived from observed route"))
    for f in _by_type(findings, "workflow"):
        bullets.append(_b(
            f"IMPLEMENT THIS USER FLOW: {f.get('title', '')}"
            + (f" \u2014 {f.get('detail')}" if f.get("detail") else "")
            + "\nEvery step must work end-to-end; test it in the browser.",
            [f.get("id")] if f.get("id") else [], "INFERRED", 0.6,
            "flow derived from observed workflow"))
    for f in _by_type(findings, "endpoint"):
        if f.get("endpoint"):
            bullets.append(_b(
                f"WIRE UP: {f.get('endpoint')}\n"
                "The UI calls this. Your rebuild must serve the same shape "
                "(see api_inventory for the observed schema). If you cannot "
                "reach the real backend, mock it with the recorded shape and "
                "label the build 'frontend reconstruction'.",
                [f.get("id")] if f.get("id") else [], "INFERRED", 0.6,
                "endpoint the UI depends on"))
    if not bullets:
        bullets.append(_b(
            "No functional requirements can be stated \u2014 no routes, workflows, "
            "or endpoints are evidenced. Requirements are BLOCKED on analysis.",
            [], "BLOCKED", 1.0, "no actionable findings in the ledger"))
    return _section("functional_requirements", bullets,
                    note="Build order: pages first, then flows, then API wiring. "
                         "Verify each against recon_compare_build.")


def _visual_requirements(findings: list[dict]) -> dict:
    shots = [f for f in findings
             if str(f.get("artifact") or "").endswith(
                 (".png", ".jpg", ".jpeg", ".webp"))]
    bullets = []
    # 1. Screenshot references — the agent MUST study these before building.
    for f in shots:
        bullets.append(_b(
            f"STUDY THIS SCREENSHOT BEFORE BUILDING: {f.get('artifact')} "
            f"({f.get('title', '')}). Match layout, spacing, colors, and "
            f"typography to what you see \u2014 not to your defaults.",
            [f.get("id")] if f.get("id") else [],
            f.get("classification", "OBSERVED"), 0.95,
            "screenshot artifact on file"))
    # 2. Design tokens as copy-paste CSS variables.
    for f in _by_type(findings, "tech"):
        if "Design tokens:" in str(f.get("title", "")):
            css = _tokens_to_css(f.get("detail", ""))
            if css:
                bullets.append(_b(
                    "USE THIS DESIGN SYSTEM \u2014 start your CSS with these "
                    f"variables, do not invent your own palette:\n{css}",
                    [f.get("id")] if f.get("id") else [],
                    "OBSERVED", 0.9,
                    "computed styles sampled from rendered elements"))
    # 3. Component variants with exact values.
    for f in _by_type(findings, "component"):
        if "Visual signature" in str(f.get("detail", "")):
            bullets.append(_b(
                f"REBUILD THIS COMPONENT EXACTLY: {f.get('title', '')} \u2014 "
                f"{f.get('detail', '')}",
                [f.get("id")] if f.get("id") else [],
                "OBSERVED", 0.9,
                "grouped by computed-style signature"))
    if not bullets:
        bullets.append(_b(
            "No visual references captured. Layout, typography, spacing, and "
            "responsive behavior are UNVERIFIED \u2014 screenshots at desktop, "
            "tablet, and mobile viewports are needed before visual fidelity "
            "can be specified.",
            [], "UNVERIFIED", 1.0, "no screenshot artifacts in the ledger"))
    return _section("visual_requirements", bullets,
                    note="Designer handoff: study screenshots, use the design "
                         "system variables, rebuild components to spec.")


def _tokens_to_css(detail: str) -> str:
    """Convert a design-tokens finding detail into CSS variables."""
    import re
    lines = [":root {"]
    colors = re.findall(r"rgb\(\d+, \d+, \d+\)", detail)
    seen = set()
    for c in colors:
        if c not in seen and len(seen) < 8:
            seen.add(c)
            lines.append(f"  --color-{len(seen)}: {c};")
    m = re.search(r"Fonts: ([^\n]+)", detail)
    if m:
        fonts = [f.strip() for f in m.group(1).split(",")[:3] if f.strip()]
        if fonts:
            lines.append(f"  --font-family: {', '.join(fonts)}, sans-serif;")
    m = re.search(r"Radii: ([^\n]+)", detail)
    if m and "sharp" not in m.group(1):
        radii = [r.strip() for r in m.group(1).split(",")[:3] if r.strip()]
        for i, r in enumerate(radii, 1):
            lines.append(f"  --radius-{i}: {r};")
    lines.append("}")
    return "\n".join(lines) if len(lines) > 2 else ""


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
    routes = [f for f in _by_type(findings, "route") if f.get("route")]
    endpoints = [f for f in _by_type(findings, "endpoint") if f.get("endpoint")]
    workflows = _by_type(findings, "workflow")
    bullets = []
    # Parameterized templates, not one bullet per item (saves context).
    if routes:
        bullets.append(_b(
            f"Route tests ({len(routes)} routes): for EACH route, GET it and "
            f"assert 2xx + recorded title. Routes: "
            f"{', '.join(f.get('route', '')[:60] for f in routes[:10])}"
            f"{'...' if len(routes) > 10 else ''}.",
            _ids(routes), "INFERRED", 0.6,
            "parameterized plan; not yet executed"))
    if endpoints:
        bullets.append(_b(
            f"API tests ({len(endpoints)} endpoints): for EACH endpoint, "
            f"exercise with the observed method and assert recorded "
            f"status/content-type.",
            _ids(endpoints), "INFERRED", 0.55,
            "parameterized plan; not yet executed"))
    if workflows:
        bullets.append(_b(
            f"Workflow tests ({len(workflows)} flows): replay each recorded "
            f"journey and assert every state transition.",
            _ids(workflows), "INFERRED", 0.55,
            "parameterized plan; not yet executed"))
    if routes:
        bullets.append(_b(
            "Accessibility check: keyboard-navigate every recorded route; assert "
            "visible focus and no console errors on load.",
            _ids(routes), "INFERRED", 0.5,
            "standard gate; not yet executed"))
    if not bullets:
        bullets.append(_b(
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
# machine-readable build manifest
# ---------------------------------------------------------------------------

# Sections whose INFERRED bullets are load-bearing for a rebuild (others are
# advisory prose and don't become strengthen-tasks).
_LOAD_BEARING = {"routes", "api_inventory", "components", "user_journeys",
                 "functional_requirements"}


def _manifest_bullets(spec: dict, name: str) -> list[dict]:
    sections = (spec or {}).get("sections", {}) or {}
    s = sections.get(name, {}) or {}
    return [b for b in (s.get("bullets", []) or []) if isinstance(b, dict)]


def generate_manifest(spec: dict, graph=None) -> list[dict]:
    """Build a machine-readable, ordered task list from a generated spec.

    One task per route / endpoint / workflow bullet, plus one task per
    BLOCKED / UNVERIFIED / load-bearing INFERRED bullet. Deterministic:
    the same spec always yields the same task list.

    Task shape: {id, title, section, finding_ids, priority, depends_on,
    acceptance, status}. Ordering: P0 (unblock) -> P1 (verify) -> P2
    (strengthen) -> P3 (build: routes, then endpoints, then workflows, so a
    workflow depends_on the route tasks it visits — wired from graph edges
    when available, else substring matching on bullet text).
    """
    g = _graph_of(graph)
    tasks: list[dict] = []
    seq = [0]

    def _tid() -> str:
        seq[0] += 1
        return f"T-{seq[0]:03d}"

    def _mk(title: str, section: str, fids, priority: str,
            depends_on=None, acceptance=None) -> dict:
        return {
            "id": _tid(),
            "title": title[:140],
            "section": section,
            "finding_ids": sorted(set(fids or [])),
            "priority": priority,
            "depends_on": list(depends_on or []),
            "acceptance": list(acceptance or []),
            "status": "pending",
        }

    # graph index: finding id -> route keys it visits; node id -> route key
    node_route: dict = {}
    visits: dict = {}
    for n in g.get("nodes", []):
        if isinstance(n, dict) and n.get("kind") == "route":
            key = n.get("route") or n.get("label")
            if n.get("id") and key:
                node_route[n["id"]] = key
    for e in g.get("edges", []):
        if isinstance(e, dict) and e.get("rel") == "visits" \
                and e.get("from") and e.get("to"):
            visits.setdefault(e["from"], set()).add(e["to"])

    test_bullets = _manifest_bullets(spec, "test_plan")

    def _acceptance(fids) -> list[str]:
        fset = set(fids or [])
        out = []
        for b in test_bullets:
            if fset & set(b.get("finding_ids", []) or []):
                t = b.get("text", "")
                if t and t not in out:
                    out.append(t)
        return out

    # ---- P3: routes (first, so workflows can depend on them) ----
    route_tasks: dict[str, dict] = {}
    for b in _manifest_bullets(spec, "routes"):
        text = b.get("text", "") or ""
        # Skip advisory placeholders ("No routes discovered...", UNVERIFIED)
        if b.get("classification") in ("UNVERIFIED", "BLOCKED"):
            continue
        m = re.match(r"^Route (\S+)", text)
        key = m.group(1) if m else text[:80]
        if not key:
            continue
        if key in route_tasks:
            t = route_tasks[key]
            t["finding_ids"] = sorted(set(t["finding_ids"])
                                      | set(b.get("finding_ids", []) or []))
            continue
        t = _mk(f"Build route {key}", "routes",
                b.get("finding_ids"), "P3",
                acceptance=_acceptance(b.get("finding_ids")) or
                [f"recon_compare_build reports route {key} as matched"])
        route_tasks[key] = t
        tasks.append(t)

    # ---- P3: endpoints ----
    for b in _manifest_bullets(spec, "api_inventory"):
        text = b.get("text", "") or ""
        if text.startswith("Only endpoints listed above"):
            continue  # scoping rule, not a build item
        if b.get("classification") in ("UNVERIFIED", "BLOCKED"):
            continue  # advisory placeholder, not a build item
        ep = text.split(" — ")[0].strip() or text[:80]
        t = _mk(f"Integrate endpoint {ep}", "api_inventory",
                b.get("finding_ids"), "P3",
                acceptance=_acceptance(b.get("finding_ids")) or
                [f"recon_compare_build reports endpoint {ep} as matched"])
        tasks.append(t)

    # ---- P3: components ----
    for b in _manifest_bullets(spec, "components"):
        text = b.get("text", "") or ""
        if "UNVERIFIED" in text and "recon_inspect_page" in text:
            continue  # advisory placeholder, not a build item
        t = _mk(f"Build component: {text[:100]}", "components",
                b.get("finding_ids"), "P3",
                acceptance=_acceptance(b.get("finding_ids")))
        tasks.append(t)

    # ---- P3: workflows (depend on the routes they visit) ----
    for b in _manifest_bullets(spec, "user_journeys"):
        text = b.get("text", "") or ""
        if "UNVERIFIED" in text and "recon_trace_workflow" in text:
            continue  # advisory placeholder
        fids = b.get("finding_ids", []) or []
        deps: list[str] = []
        for fid in fids:
            for node_id in visits.get(fid, ()):
                key = node_route.get(node_id)
                if key and key in route_tasks and \
                        route_tasks[key]["id"] not in deps:
                    deps.append(route_tasks[key]["id"])
        if not deps:
            # fallback: substring match of known route keys in bullet text
            for key, t in route_tasks.items():
                if key in text and t["id"] not in deps:
                    deps.append(t["id"])
        t = _mk(f"Implement workflow: {text[:100]}", "user_journeys",
                fids, "P3", depends_on=deps,
                acceptance=_acceptance(fids) or
                ["replay script from recon_trace_workflow passes against "
                 "the build"])
        tasks.append(t)

    # ---- Research tasks: evidence gaps with concrete resolution steps ----
    # Separated from build tasks: the agent researches FIRST, then builds.
    research_tasks: list[dict] = []
    seen_research: set = set()

    def _research_task(title: str, section: str, fids, how_to_resolve: str):
        key = title[:100]
        if key in seen_research:
            return
        seen_research.add(key)
        research_tasks.append(_mk(title, section, list(fids), "research",
                                  acceptance=[how_to_resolve]))

    for name in SECTION_NAMES:
        for b in _manifest_bullets(spec, name):
            cls = b.get("classification", "")
            text = b.get("text", "") or ""
            fids = b.get("finding_ids", []) or []
            if cls == "BLOCKED":
                _research_task(
                    f"Unblock: {text[:100]}", name, fids,
                    f"Run the relevant tool (see SKILL.md routing table) to "
                    f"observe this; if truly inaccessible, document why in the ledger.")
            elif cls == "UNVERIFIED":
                # Skip advisory placeholders that just say "tool X has not run"
                if "has not run" in text or "has not produced" in text:
                    tool_hint = ""
                    if "recon_" in text:
                        import re as _re
                        m = _re.search(r"(recon_\w+)", text)
                        if m:
                            tool_hint = f" Run {m.group(1)}."
                    _research_task(
                        f"Collect missing evidence: {text[:80]}", name, fids,
                        f"This is missing because a tool wasn't run.{tool_hint} "
                        f"Then re-run recon_generate_spec.")
                else:
                    _research_task(
                        f"Verify: {text[:100]}", name, fids,
                        "Re-observe with the relevant tool; mark SOURCE_VERIFIED "
                        "if corroborated, or document the contradiction.")
            elif cls == "INFERRED" and name in _LOAD_BEARING:
                _research_task(
                    f"Confirm inference: {text[:100]}", name, fids,
                    "This affects architecture. Verify with a targeted probe "
                    "or inspect; upgrade to OBSERVED if confirmed.")

    # ---- Build tasks: deduplicated by normalized target ----
    # (route_tasks, endpoint tasks, etc. are already in `tasks` from above)
    seen_build: set = set()
    deduped_build = []
    for t in tasks:
        # Normalize: lowercase URL path without query/fragment/trailing slash
        title = t.get("title", "")
        norm = title.lower().split("?")[0].split("#")[0].rstrip("/").strip()
        if norm in seen_build:
            continue
        seen_build.add(norm)
        deduped_build.append(t)

    # Order build tasks: routes -> endpoints -> components -> workflows
    section_order = {"routes": 0, "api_inventory": 1, "components": 2,
                     "user_journeys": 3}
    deduped_build.sort(key=lambda t: (section_order.get(t.get("section"), 9),
                                      t["id"]))

    # Re-number deterministically
    for i, t in enumerate(deduped_build, 1):
        old = t["id"]
        new = f"B-{i:03d}"
        t["id"] = new
        for other in deduped_build:
            other["depends_on"] = [new if d == old else d
                                   for d in other["depends_on"]]
    for i, t in enumerate(research_tasks, 1):
        t["id"] = f"R-{i:03d}"

    if not deduped_build:
        # Honest fallback: nothing evidenced to build from.
        deduped_build.append(_mk(
            "Run the analysis pipeline (recon_start, recon_discover_routes, "
            "recon_inspect_page): the ledger is empty and there is nothing "
            "to build from.", "overview", [], "P3",
            acceptance=["recon_generate_spec returns non-empty sections"]))

    return {"build_tasks": deduped_build, "research_tasks": research_tasks}


    return tasks


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
