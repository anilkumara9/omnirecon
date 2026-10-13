"""Relationship graph builder for OmniRecon.

build_graph(ledger) fuses findings into {nodes, edges}:

- one finding-node per finding: {id, kind, label, route}
- one route-hub node per distinct route: {id: "route:<route>", kind: "route", …}
- one platform-hub node when a target label is supplied
- edges link findings to the route hubs they belong to, entities to the
  endpoints that expose them, workflows to the routes they visit, and
  tech findings to the platform hub.

All output is plain JSON-serializable dicts, deterministic ordering.
"""
from __future__ import annotations

from .evidence import EvidenceLedger


def _norm_route(route: str | None) -> str | None:
    if not route:
        return None
    r = route.strip()
    return r or None


def build_graph(ledger: EvidenceLedger, target: str | None = None) -> dict:
    findings = ledger.list()
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    def add_node(nid: str, kind: str, label: str, route=None, **extra):
        if nid not in nodes:
            node = {"id": nid, "kind": kind, "label": label, "route": route}
            node.update(extra)
            nodes[nid] = node
        return nodes[nid]

    def add_edge(frm: str, to: str, rel: str):
        key = (frm, to, rel)
        if key not in seen_edges and frm in nodes and to in nodes:
            seen_edges.add(key)
            edges.append({"from": frm, "to": to, "rel": rel})

    # platform hub (optional but useful for tech findings)
    if target:
        add_node("platform", "platform", target)

    # route hubs
    routes = sorted({_norm_route(f["route"]) for f in findings
                     if _norm_route(f["route"])})
    for r in routes:
        add_node(f"route:{r}", "route", r, route=r)

    # finding nodes
    for f in findings:
        add_node(f["id"], f["type"], f["title"] or f["id"], route=f["route"],
                 classification=f["classification"], confidence=f["confidence"])

    # tech findings -> platform hub
    if target:
        for f in findings:
            if f["type"] == "tech":
                add_edge(f["id"], "platform", "built_with")

    # findings -> their route hub
    rel_by_type = {
        "route": "defines", "component": "renders_on", "endpoint": "exposed_at",
        "entity": "observed_at", "workflow": "visits", "state": "occurs_at",
        "auth": "guards", "asset": "served_at", "note": "about",
    }
    for f in findings:
        r = _norm_route(f["route"])
        if r:
            add_edge(f["id"], f"route:{r}", rel_by_type.get(f["type"], "about"))

    # entities -> endpoints that expose them (by endpoint association or URL in sources)
    endpoint_nodes = {f["endpoint"]: f["id"] for f in findings
                      if f["type"] == "endpoint" and f["endpoint"]}
    for f in findings:
        if f["type"] != "entity":
            continue
        if f["endpoint"] and f["endpoint"] in endpoint_nodes:
            add_edge(f["id"], endpoint_nodes[f["endpoint"]], "returned_by")
        else:
            blob = " ".join(f["sources"] or []).lower()
            for ep, eid in endpoint_nodes.items():
                if ep and ep.lower() in blob:
                    add_edge(f["id"], eid, "returned_by")
                    break

    # components -> endpoints they call (component detail/sources mentioning endpoint path)
    for f in findings:
        if f["type"] != "component":
            continue
        blob = (f["detail"] + " " + " ".join(f["sources"] or [])).lower()
        for ep, eid in endpoint_nodes.items():
            if ep and len(ep) > 2 and ep.lower() in blob:
                add_edge(f["id"], eid, "calls")
                break

    # workflows -> endpoints exercised (same association)
    for f in findings:
        if f["type"] != "workflow":
            continue
        if f["endpoint"] and f["endpoint"] in endpoint_nodes:
            add_edge(f["id"], endpoint_nodes[f["endpoint"]], "exercises")

    node_list = sorted(nodes.values(), key=lambda n: (n["kind"], n["id"]))
    return {
        "nodes": node_list,
        "edges": edges,
        "counts": {
            "nodes": len(node_list),
            "edges": len(edges),
            "routes": len(routes),
            "findings": len(findings),
        },
    }
