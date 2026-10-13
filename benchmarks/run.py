#!/usr/bin/env python3
"""OmniRecon benchmark runner — measured numbers only, nothing invented.

Targets:
  (a) local static fixture  benchmarks/fixtures/static-site/  (+ ground truth)
  (b) https://example.com
  (c) https://news.ycombinator.com

Metrics per target: time-to-first-report (rapid platform_scan), total recon
time, routes found, endpoints found, evidence counts by classification.
For the fixture: route precision/recall and endpoint recall vs the
hand-annotated ground_truth.json.

Output: benchmarks/results/<YYYY-MM-DD>.json + a printed summary table.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# Sandbox quirk: this VM's egress proxy breaks httpx when no_proxy contains
# bracketed IPv6 literals. Only touch env when that proxy is in play.
if "hatch-egress-proxy" in os.environ.get("https_proxy", ""):
    os.environ["no_proxy"] = "localhost,127.0.0.1"
    os.environ["NO_PROXY"] = "localhost,127.0.0.1"

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omnirecon import recon_primitives as RP  # noqa: E402

RESULTS_DIR = ROOT / "benchmarks" / "results"
FIXTURE_DIR = ROOT / "benchmarks" / "fixtures" / "static-site"
FIXTURE_PORT = 8137


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _norm_route(url: str) -> str:
    p = urlparse(url).path or "/"
    if p in ("/index.html", "/index.htm"):
        p = "/"
    return p.rstrip("/") or "/"


def _norm_endpoint(ep: str) -> str:
    ep = (ep or "").strip()
    if ep.startswith("//"):
        ep = "https:" + ep
    if "://" in ep:
        u = urlparse(ep)
        path = u.path.rstrip("/") or "/"
        return f"{u.scheme}://{u.netloc}{path}"
    ep = ep.split("?")[0].split("#")[0]
    return ("/" + ep.lstrip("/")).rstrip("/") or "/"


def _serve_fixture():
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(FIXTURE_PORT),
         "--bind", "127.0.0.1"],
        cwd=str(FIXTURE_DIR),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait for readiness
    import socket
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", FIXTURE_PORT), timeout=1):
                return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("fixture http.server did not start")


def recon_target(url: str, label: str) -> dict:
    """Run the Stage-2 rapid pipeline and time it. Returns metrics dict."""
    m: dict = {"label": label, "url": url, "checked_utc": _utcnow()}
    try:
        t0 = time.time()
        scan = RP.platform_scan(url)
        m["time_to_first_report_s"] = round(time.time() - t0, 2)
        if scan.get("error"):
            m["error"] = f"platform_scan: {scan['error']}"
            return m
        m["tech_detected"] = [t["tech"] for t in scan.get("tech", [])]

        t1 = time.time()
        crawl = RP.crawl_site(url, max_pages=25, max_depth=2)
        m["crawl_s"] = round(time.time() - t1, 2)

        t2 = time.time()
        surf = RP.extract_api_surface(url)
        m["extract_s"] = round(time.time() - t2, 2)
        m["total_recon_s"] = round(time.time() - t0, 2)

        routes = sorted({_norm_route(p["url"]) for p in crawl.get("pages", [])})
        api_eps = sorted({_norm_endpoint(e["endpoint"])
                          for e in (crawl.get("api_endpoints", []) or [])
                          if e.get("kind") == "api"})
        surf_eps = sorted({_norm_endpoint(e["endpoint"])
                           for e in (surf.get("internal_endpoints", []) or [])
                           if e.get("kind") == "api"})
        # HTML form actions are client-declared endpoints even when not
        # API-shaped (e.g. GET /search).
        form_eps = sorted({_norm_endpoint(f.get("action") or "")
                           for p in crawl.get("pages", [])
                           for f in p.get("forms", [])
                           if f.get("action")})
        endpoints = sorted(set(api_eps) | set(surf_eps) | set(form_eps))
        m["routes_found"] = routes
        m["endpoints_found"] = endpoints
        m["route_count"] = len(routes)
        m["endpoint_count"] = len(endpoints)
        # evidence classification counts for what this pipeline produces:
        # routes/endpoints/tech are OBSERVED; framework guesses are INFERRED.
        m["evidence_by_classification"] = {
            "OBSERVED": len(routes) + len(endpoints),
            "INFERRED": len(m["tech_detected"]),
        }
    except Exception as e:  # noqa: BLE001 - benchmark must not crash
        m["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    return m


def score_fixture(m: dict, ground: dict) -> dict:
    exp_routes = {_norm_route(r["path"]) for r in ground["routes"]}
    found_routes = {_norm_route(r) for r in m.get("routes_found", [])}
    exp_eps = {_norm_endpoint(e["endpoint"]) for e in ground["endpoints"]}
    found_eps = {_norm_endpoint(e) for e in m.get("endpoints_found", [])}
    tp_r = exp_routes & found_routes
    tp_e = exp_eps & found_eps
    return {
        "route_precision": round(len(tp_r) / len(found_routes), 3) if found_routes else 0.0,
        "route_recall": round(len(tp_r) / len(exp_routes), 3) if exp_routes else 0.0,
        "routes_expected": sorted(exp_routes),
        "routes_found": sorted(found_routes),
        "routes_missed": sorted(exp_routes - found_routes),
        "endpoint_recall": round(len(tp_e) / len(exp_eps), 3) if exp_eps else 0.0,
        "endpoints_expected": sorted(exp_eps),
        "endpoints_found": sorted(found_eps),
        "endpoints_missed": sorted(exp_eps - found_eps),
    }


def main() -> None:
    results: dict = {
        "benchmark": "omnirecon-stage2-recon",
        "date": datetime.date.today().isoformat(),
        "generated_utc": _utcnow(),
        "targets": {},
        "notes": [
            "Metrics are measured wall-clock on this machine; rerun to reproduce.",
            "The fixture's /api/* endpoints are fictional (404 on the static server); "
            "they are client-declared, so extraction recall is still meaningful.",
            "Targets (b) and (c) have no ground truth; only counts are reported.",
        ],
    }

    # (a) fixture
    proc = _serve_fixture()
    try:
        furl = f"http://127.0.0.1:{FIXTURE_PORT}/"
        fm = recon_target(furl, "fixture-static-site")
        ground = json.loads((FIXTURE_DIR / "ground_truth.json").read_text())
        fm["ground_truth_score"] = score_fixture(fm, ground)
        results["targets"]["fixture"] = fm
    finally:
        proc.terminate()

    # (b) + (c) live targets
    for label, url in (("example.com", "https://example.com"),
                       ("news.ycombinator.com", "https://news.ycombinator.com")):
        results["targets"][label] = recon_target(url, label)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"{datetime.date.today().isoformat()}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"wrote {out}\n")

    # summary table
    print(f"{'target':28} {'t_first':>8} {'total':>8} {'routes':>7} "
          f"{'endpts':>7} {'r_prec':>7} {'r_rec':>6} {'e_rec':>6}")
    for key, m in results["targets"].items():
        if m.get("error"):
            print(f"{key:28} ERROR: {m['error'][:60]}")
            continue
        gt = m.get("ground_truth_score", {})
        print(f"{key:28} {m.get('time_to_first_report_s', 0):>8} "
              f"{m.get('total_recon_s', 0):>8} {m.get('route_count', 0):>7} "
              f"{m.get('endpoint_count', 0):>7} "
              f"{gt.get('route_precision', '-'):>7} {gt.get('route_recall', '-'):>6} "
              f"{gt.get('endpoint_recall', '-'):>6}")


if __name__ == "__main__":
    main()
