"""OpenAPI/Swagger document analysis.

Fetches a published OpenAPI (or Swagger 2.0) document, normalizes its paths
into the evidence model, and can emit an OpenAPI 3.1 document generated from
an evidence ledger (captured traffic + static extraction).
"""
from __future__ import annotations

import json
import re

import httpx
import yaml


def fetch_spec(url: str, timeout: int = 25) -> dict:
    """Download and parse an OpenAPI/Swagger document (JSON or YAML)."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as c:
            r = c.get(url, headers={"Accept": "application/json, application/yaml"})
    except Exception as e:
        return {"url": url, "error": f"fetch failed: {e!s}"[:300]}
    if r.status_code != 200:
        return {"url": url, "error": f"HTTP {r.status_code}"}
    text = r.text.strip()
    try:
        data = json.loads(text) if text[:1] in "{[" else yaml.safe_load(text)
    except Exception as e:
        return {"url": url, "error": f"spec parse failed: {e!s}"[:300]}
    if not isinstance(data, dict):
        return {"url": url, "error": "spec is not a mapping document"}
    return {"url": url, "spec": data}


def analyze_api_spec(url: str) -> dict:
    """Normalize an OpenAPI/Swagger document into paths + metadata."""
    res = fetch_spec(url)
    if res.get("error"):
        return res
    spec = res["spec"]
    version = str(spec.get("openapi", spec.get("swagger", "?")))
    info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
    servers = []
    for s in spec.get("servers", []) or []:
        if isinstance(s, dict) and s.get("url"):
            servers.append(str(s["url"])[:200])
    if not servers and isinstance(spec.get("host"), str):
        base = f"{spec.get('schemes', ['https'])[0]}://{spec['host']}"
        servers.append(base + str(spec.get("basePath", "")))

    sec_defs = spec.get("components", {}).get("securitySchemes", {}) \
        or spec.get("securityDefinitions", {}) or {}
    global_sec = bool(spec.get("security"))

    paths, schemas = [], set()
    raw_paths = spec.get("paths", {}) or {}
    for path, item in raw_paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            m = method.lower()
            if m not in ("get", "post", "put", "patch", "delete", "head",
                         "options", "trace"):
                continue
            op = op if isinstance(op, dict) else {}
            auth = bool(op.get("security")) or (global_sec and "security" not in op)
            paths.append({
                "method": m.upper(), "path": path,
                "summary": str(op.get("summary", "") or "")[:200],
                "operation_id": str(op.get("operationId", "") or "")[:120],
                "auth_required": auth,
                "tags": [str(t)[:60] for t in (op.get("tags") or [])][:5],
            })
    for name in (spec.get("components", {}).get("schemas", {}) or {}):
        schemas.add(str(name)[:120])
    for name in (spec.get("definitions", {}) or {}):
        schemas.add(str(name)[:120])

    return {"url": url, "openapi_version": version,
            "title": str(info.get("title", "") or "")[:200],
            "version": str(info.get("version", "") or "")[:60],
            "servers": servers[:10], "security_schemes": sorted(sec_defs.keys())[:20],
            "paths_found": len(paths), "schemas_found": len(schemas),
            "paths": sorted(paths, key=lambda p: (p["path"], p["method"]))[:500],
            "schemas": sorted(schemas)[:200]}


def _shape_to_jsonschema(shape: dict) -> dict:
    """Convert an infer_shape() dict to JSON Schema (types only)."""
    if not isinstance(shape, dict):
        return {}
    t = shape.get("type")
    if t == "object":
        return {"type": "object",
                "properties": {k: _shape_to_jsonschema(v)
                               for k, v in
                               shape.get("properties", {}).items()},
                "x-omni-observed-keys": shape.get("keys", 0)}
    if t == "array":
        items = shape.get("items") or []
        return {"type": "array",
                "items": _shape_to_jsonschema(items[0]) if items else {}}
    if t in ("string", "integer", "number", "boolean", "null"):
        return {"type": t}
    return {}


def ledger_to_openapi(findings: list[dict], title: str = "Reconstructed API",
                       version: str = "1.0.0") -> dict:
    """Build an OpenAPI 3.1 document from evidence-ledger endpoint findings.

    Only findings with type 'endpoint' become paths; each carries its
    evidence classification as an x- extension so consumers know the
    provenance of every path. Findings with type 'schema' contribute
    requestBody / response schemas (values-free shapes).
    """
    # index schema findings by (endpoint, shape_kind)
    schemas: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f.get("type") == "schema" and f.get("endpoint") \
                and isinstance(f.get("shape"), dict):
            schemas[(str(f["endpoint"]), str(f.get("shape_kind", "")))] = \
                _shape_to_jsonschema(f["shape"])
    paths: dict[str, dict] = {}
    for f in findings:
        if f.get("type") != "endpoint":
            continue
        raw = str(f.get("endpoint", "") or "")
        m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)",
                     raw.strip(), re.IGNORECASE)
        if m:
            method, pth = m.group(1).lower(), m.group(2)
        else:
            method, pth = "get", raw.strip()
        if not pth.startswith("/"):
            continue
        pth = re.sub(r"\?.*$", "", pth)  # strip query examples
        op = {
            "summary": str(f.get("title", "") or "")[:200],
            "x-omni-evidence": {
                "classification": f.get("classification", "UNVERIFIED"),
                "confidence": f.get("confidence", 0.5),
                "finding_id": f.get("id"),
                "sources": (f.get("sources") or [])[:3],
            },
        }
        req_shape = schemas.get((raw.strip(), "request")) \
            or schemas.get((f.get("endpoint", ""), "request"))
        resp_shape = schemas.get((raw.strip(), "response")) \
            or schemas.get((f.get("endpoint", ""), "response"))
        if req_shape:
            op["requestBody"] = {
                "content": {"application/json": {"schema": req_shape}},
                "x-omni-observed": True,
            }
        if resp_shape:
            op["responses"] = {
                "200": {"description": "Observed response shape",
                        "content": {"application/json":
                                    {"schema": resp_shape}}}}
        paths.setdefault(pth, {})[method] = op
    return {"openapi": "3.1.0",
            "info": {"title": title, "version": version,
                     "description": "Reconstructed from observed evidence by "
                                    "OmniRecon. Classifications mark provenance; "
                                    "schemas are values-free shapes."},
            "paths": dict(sorted(paths.items()))}


def dump_openapi_yaml(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
