"""Session lifecycle for OmniRecon: create / checkpoint / resume / cancel.

A session lives at <base_dir>/<sid>/ with session.json, evidence.jsonl,
graph.json, spec.json, report.md, audit.log and artifacts/.

create() runs Stage 1 (target validation) + Stage 2 (rapid recon) synchronously
via omnirecon.recon_primitives and seeds the evidence ledger. Long tools use
JobManager (thread pool with poll/cancel) instead of blocking the MCP server.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import recon_primitives as RP
from .evidence import EvidenceLedger
from .graph import build_graph
from .security import ReconError, audit as _audit, safe_join

STAGE_NAMES = {
    1: "target_validation",
    2: "rapid_recon",
    3: "parallel_investigation",
    4: "evidence_fusion",
    5: "reconstruction_planning",
    6: "implementation",
    7: "verification",
}

DEFAULT_BUDGETS = {
    "fast": {"max_pages": 15, "max_depth": 2, "max_steps": 10, "timeout_s": 300},
    "thorough": {"max_pages": 60, "max_depth": 3, "max_steps": 25, "timeout_s": 1800},
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


_ARTIFACT_EXTS = (".apk", ".ipa", ".dex", ".elf", ".so", ".dll", ".exe",
                  ".msi", ".dmg", ".bin", ".o", ".a", ".ko", ".fw", ".img")


def _detect_target_kind(target: str) -> tuple[str, str]:
    """Return (kind, normalized_target).

    kinds: 'url' (web platform), 'api_spec' (OpenAPI/Swagger document),
    'repo' (local dir or git URL), 'artifact' (APK/IPA/native binary file).
    """
    t = (target or "").strip()
    if not t:
        raise ReconError("target must not be empty", code="invalid_target")
    # OpenAPI / Swagger document URL → API pipeline
    if re.match(r"^https?://", t, re.IGNORECASE) and re.search(
            r"(openapi|swagger)[.\-_].*\.json$|\.ya?ml$|/openapi\.json$|/swagger\.json$",
            t, re.IGNORECASE):
        return "api_spec", t
    if re.match(r"^https?://", t, re.IGNORECASE):
        return "url", t
    expanded = os.path.expanduser(t)
    if os.path.isdir(expanded):
        return "repo", os.path.abspath(expanded)
    if os.path.isfile(expanded):
        if expanded.lower().endswith(_ARTIFACT_EXTS):
            return "artifact", os.path.abspath(expanded)
        # Any other file → treat as a single-file artifact target anyway;
        # the analyzer reports its type honestly.
        return "artifact", os.path.abspath(expanded)
    if t.endswith(".git") or re.match(r"^[\w.\-]+@[\w.\-]+:", t):
        return "repo", t  # remote git URL — analyze_codebase clones it
    if t.startswith(("/", ".", "~")):
        raise ReconError(f"local path does not exist: {t}", code="invalid_target",
                         hint="Pass an http(s) URL, a local directory, a git URL, "
                              "or a binary/APK file path.")
    # bare domain → treat as URL
    if re.match(r"^[\w.\-]+(\.[\w.\-]+)+(:\d+)?(/.*)?$", t):
        return "url", "https://" + t
    raise ReconError(f"could not interpret target {t!r}", code="invalid_target",
                     hint="Pass an http(s) URL, an OpenAPI document URL, a local "
                          "directory, a git URL, or a binary/APK file path.")


class SessionManager:
    def __init__(self, base_dir: str | None = None):
        self.base_dir = os.path.abspath(
            base_dir or os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))), "sessions"))
        os.makedirs(self.base_dir, exist_ok=True)
        self._ledgers: dict[str, EvidenceLedger] = {}
        self._lock = threading.Lock()

    # -- paths -------------------------------------------------------
    def _sdir(self, sid: str) -> str:
        if not sid or not re.fullmatch(r"[A-Za-z0-9_\-]{4,64}", sid):
            raise ReconError(f"invalid session id {sid!r}", code="invalid_session")
        return safe_join(self.base_dir, sid)

    def _read_session(self, sid: str) -> dict:
        path = os.path.join(self._sdir(sid), "session.json")
        if not os.path.exists(path):
            raise ReconError(f"session {sid} not found", code="session_not_found")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def _write_session(self, sid: str, data: dict) -> None:
        data["updated_utc"] = _utcnow()
        with open(os.path.join(self._sdir(sid), "session.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    # -- ledger access ------------------------------------------------
    def ledger(self, sid: str) -> EvidenceLedger:
        with self._lock:
            if sid in self._ledgers:
                return self._ledgers[sid]
        path = os.path.join(self._sdir(sid), "evidence.jsonl")
        led = EvidenceLedger.load(path) if os.path.exists(path) else EvidenceLedger()
        with self._lock:
            self._ledgers[sid] = led
        return led

    # -- lifecycle ----------------------------------------------------
    def create(self, target: str, mode: str = "fast",
               budget: dict | None = None) -> dict:
        if mode not in ("fast", "thorough"):
            raise ReconError(f"mode must be fast|thorough, got {mode!r}",
                             code="invalid_mode")
        kind, norm_target = _detect_target_kind(target)
        sid = secrets.token_hex(8)
        sdir = self._sdir(sid)
        os.makedirs(os.path.join(sdir, "artifacts"), exist_ok=True)

        merged_budget = dict(DEFAULT_BUDGETS[mode])
        if budget:
            merged_budget.update({k: v for k, v in budget.items()
                                  if k in merged_budget})

        session = {
            "id": sid, "target": norm_target, "target_kind": kind, "mode": mode,
            "stage": 1, "status": "active",
            "created_utc": _utcnow(), "updated_utc": _utcnow(),
            "budget": merged_budget,
            "progress": {"stage_1": "done"},
            "jobs": [],
        }
        self._write_session(sid, session)
        _audit(sid, "session.create",
               f"target={norm_target} kind={kind} mode={mode}", self.base_dir)

        # ---- Stage 2: rapid recon (synchronous) ----
        t0 = time.time()
        ledger = self.ledger(sid)
        rapid = {"target": norm_target, "target_kind": kind}
        try:
            if kind == "url":
                self._rapid_url(sid, norm_target, ledger, rapid, session)
            elif kind == "repo":
                self._rapid_repo(sid, norm_target, ledger, rapid, session)
            elif kind == "api_spec":
                self._rapid_api_spec(sid, norm_target, ledger, rapid, session)
            elif kind == "artifact":
                self._rapid_artifact(sid, norm_target, ledger, rapid, session)
            else:
                self._rapid_repo(sid, norm_target, ledger, rapid, session)
            session["stage"] = 2
            session["progress"]["stage_2"] = "done"
        except ReconError:
            raise
        except Exception as e:  # never let stage 2 kill the session
            ledger.add({
                "type": "note", "title": "Rapid recon failed",
                "detail": f"Stage 2 raised {type(e).__name__}: {e}"[:500],
                "classification": "BLOCKED", "confidence": 1.0,
                "confidence_why": "The recon step itself errored; nothing was observed.",
                "sources": [norm_target],
                "limitations": "Rapid recon did not complete; deeper stages may still work.",
            })
            session["progress"]["stage_2"] = "failed"
        rapid["elapsed_s"] = round(time.time() - t0, 1)
        rapid["findings_seeded"] = len(ledger)
        rapid["ledger_stats"] = ledger.stats()
        session["progress"]["rapid_report"] = rapid

        self.checkpoint(sid, session)  # persists session.json + evidence.jsonl + graph.json
        _audit(sid, "session.stage2_done",
               f"findings={len(ledger)} elapsed_s={rapid['elapsed_s']}", self.base_dir)
        return {
            "session_id": sid, "target": norm_target, "target_kind": kind,
            "mode": mode, "stage": session["stage"], "status": session["status"],
            "rapid_report": rapid,
        }

    def _rapid_url(self, sid: str, url: str, ledger: EvidenceLedger,
                   rapid: dict, session: dict) -> None:
        scan = RP.platform_scan(url)
        if scan.get("error"):
            ledger.add({
                "type": "note", "title": f"Target unreachable: {url}",
                "detail": scan["error"][:500],
                "classification": "BLOCKED", "confidence": 1.0,
                "confidence_why": "Direct fetch failed; the target could not be observed.",
                "sources": [url],
                "limitations": "No page content, tech, or endpoints could be observed.",
            })
            rapid["error"] = scan["error"][:300]
            session["progress"]["reachable"] = False
            return
        session["progress"]["reachable"] = True
        rapid["status_code"] = scan.get("status")
        rapid["final_url"] = scan.get("final_url")
        rapid["title"] = scan.get("title")
        rapid["tech"] = [t["tech"] for t in scan.get("tech", [])]
        rapid["forms"] = len(scan.get("forms", []))
        rapid["scripts"] = scan.get("script_tags")
        rapid["robots_txt"] = scan.get("robots_txt", {}).get("present")
        rapid["sitemap"] = scan.get("sitemap", {}).get("present")

        for t in scan.get("tech", []):
            ledger.add({
                "type": "tech", "title": f"Platform uses {t['tech']}",
                "detail": f"Evidence: {t.get('evidence', '')}",
                "classification": "OBSERVED", "confidence": 0.85,
                "confidence_why": "Matched a known framework/infra marker in headers or HTML.",
                "sources": [scan.get("final_url") or url],
                "limitations": "Heuristic fingerprint; markers can be spoofed or hidden.",
            })
        ledger.add({
            "type": "note", "title": f"Rapid recon: {scan.get('title') or url}",
            "detail": ("HTTP %(status)s at %(final)s; %(forms)d form(s), "
                       "%(scripts)s script tag(s); robots.txt present=%(robots)s, "
                       "sitemap.xml present=%(sitemap)s." % {
                           "status": scan.get("status"), "final": scan.get("final_url"),
                           "forms": len(scan.get("forms", [])),
                           "scripts": scan.get("script_tags"),
                           "robots": scan.get("robots_txt", {}).get("present"),
                           "sitemap": scan.get("sitemap", {}).get("present")}),
            "classification": "OBSERVED", "confidence": 0.95,
            "confidence_why": "Values were read directly from the live HTTP response.",
            "sources": [scan.get("final_url") or url], "route": "/",
            "limitations": "Single-page snapshot; JS-rendered content not yet executed.",
        })

        host = urlparse(scan.get("final_url") or url).hostname or ""
        domain = RP.registrable_domain(host)
        if domain:
            dns = RP.dns_recon(domain)
            rapid["dns_a_records"] = len(dns.get("a", []))
            rapid["subdomains_found"] = len(dns.get("subdomains", []))
            for sub in dns.get("subdomains", [])[:20]:
                ledger.add({
                    "type": "note", "title": f"Subdomain: {sub}",
                    "detail": "Discovered via certificate-transparency logs (crt.sh).",
                    "classification": "OBSERVED", "confidence": 0.9,
                    "confidence_why": "crt.sh records real issued certificates.",
                    "sources": [f"https://crt.sh/?q=%25.{domain}"],
                    "limitations": "Cert exists ≠ host is live or in scope.",
                })
            session["progress"]["endpoints_hint"] = rapid["subdomains_found"]

    def _rapid_api_spec(self, sid: str, target: str, ledger: EvidenceLedger,
                        rapid: dict, session: dict) -> None:
        """Rapid recon for an OpenAPI/Swagger document URL."""
        from omnirecon import api_intel as AI
        info = AI.analyze_api_spec(target)
        if info.get("error"):
            ledger.add({
                "type": "note", "title": "API spec fetch failed",
                "detail": info["error"][:500],
                "classification": "BLOCKED", "confidence": 1.0,
                "confidence_why": "The spec document could not be retrieved.",
                "sources": [target],
                "limitations": "No API surface could be inventoried.",
            })
            rapid["error"] = info["error"][:300]
            return
        rapid["api_title"] = info.get("title")
        rapid["api_version"] = info.get("version")
        rapid["paths_found"] = info.get("paths_found")
        rapid["servers"] = info.get("servers", [])[:5]
        ledger.add({
            "type": "tech",
            "title": f"API: {info.get('title') or target} "
                     f"({info.get('paths_found', 0)} paths)",
            "detail": f"OpenAPI {info.get('openapi_version')}; "
                      f"{info.get('paths_found')} paths, "
                      f"{info.get('schemas_found')} schemas; "
                      f"servers: {', '.join(info.get('servers', [])[:3])}",
            "classification": "SOURCE_VERIFIED", "confidence": 0.95,
            "confidence_why": "Parsed directly from the published OpenAPI document.",
            "sources": [target],
            "limitations": "The spec may be stale relative to the live API.",
        })
        for p in info.get("paths", [])[:150]:
            ledger.add({
                "type": "endpoint", "title": f"Endpoint {p['method']} {p['path']}",
                "detail": (p.get("summary") or "")[:300] +
                          (" [auth required]" if p.get("auth_required") else ""),
                "classification": "SOURCE_VERIFIED", "confidence": 0.95,
                "confidence_why": "Declared in the OpenAPI document.",
                "sources": [target], "endpoint": f"{p['method']} {p['path']}",
            })

    def _rapid_artifact(self, sid: str, target: str, ledger: EvidenceLedger,
                        rapid: dict, session: dict) -> None:
        """Rapid recon for a shipped artifact (APK/binary/JS bundle)."""
        from omnirecon import artifact_intel as AR
        if not os.path.isfile(target):
            ledger.add({
                "type": "note", "title": "Artifact not found",
                "detail": f"No file at {target}",
                "classification": "BLOCKED", "confidence": 1.0,
                "confidence_why": "The path does not exist.",
                "sources": [target], "limitations": "Nothing was analyzed.",
            })
            rapid["error"] = "file not found"
            return
        info = AR.analyze_artifact(sid, target)
        rapid["artifact_kind"] = info.get("kind")
        rapid["artifact_format"] = info.get("format")
        rapid["size_bytes"] = info.get("size_bytes")
        session["progress"]["reachable"] = True

    def _rapid_repo(self, sid: str, target: str, ledger: EvidenceLedger,
                    rapid: dict, session: dict) -> None:
        info = RP.analyze_codebase(target)
        if info.get("error"):
            ledger.add({
                "type": "note", "title": "Repository analysis failed",
                "detail": info["error"][:500],
                "classification": "BLOCKED", "confidence": 1.0,
                "confidence_why": "The analyzer itself reported the failure.",
                "sources": [target],
                "limitations": "No structural claims can be made about this repo.",
            })
            rapid["error"] = info["error"][:300]
            return
        rapid["total_files"] = info.get("total_files")
        rapid["languages"] = [(l["language"], l["files"])
                              for l in info.get("languages", [])[:5]]
        rapid["framework_guess"] = info.get("framework_guess", [])
        rapid["routes_found"] = info.get("routes_found")

        for lang in info.get("languages", [])[:5]:
            ledger.add({
                "type": "tech", "title": f"Codebase language: {lang['language']}",
                "detail": f"{lang['files']} files, ~{lang['loc']} lines of code.",
                "classification": "OBSERVED", "confidence": 0.95,
                "confidence_why": "Counted directly from the repository tree.",
                "sources": [target], "limitations": "Generated/vendored files excluded by dir filter only.",
            })
        manifest_backed = bool(info.get("manifests"))
        for fw in info.get("framework_guess", [])[:5]:
            ledger.add({
                "type": "tech", "title": f"Framework: {fw}",
                "detail": "Detected from dependency manifests and project files.",
                "classification": "SOURCE_VERIFIED" if manifest_backed else "INFERRED",
                "confidence": 0.85 if manifest_backed else 0.65,
                "confidence_why": "Manifest-backed." if manifest_backed else "Heuristic match only.",
                "sources": [target],
                "limitations": "Does not prove the framework is actually used at runtime.",
            })
        for r in info.get("routes", [])[:20]:
            ledger.add({
                "type": "route", "title": f"Route {r['route']}",
                "detail": f"{r['style']} pattern in {r['file']}",
                "classification": "SOURCE_VERIFIED", "confidence": 0.9,
                "confidence_why": "Route literal read directly from source.",
                "sources": [r["file"]], "route": r["route"],
                "limitations": "Static literal; runtime mounting may differ.",
            })
        session["progress"]["routes_found"] = info.get("routes_found")

    # -- reads / writes -------------------------------------------------
    def get(self, sid: str) -> dict:
        return self._read_session(sid)

    def update_stage(self, sid: str, stage: int) -> dict:
        if not isinstance(stage, int) or stage not in STAGE_NAMES:
            raise ReconError(f"stage must be 1–7, got {stage!r}",
                             code="invalid_stage")
        session = self._read_session(sid)
        session["stage"] = stage
        session["progress"][f"stage_{stage}"] = "in_progress"
        self._write_session(sid, session)
        _audit(sid, "session.update_stage",
               f"stage={stage} ({STAGE_NAMES[stage]})", self.base_dir)
        return session

    def checkpoint(self, sid: str, session: dict | None = None) -> dict:
        """Persist session.json + evidence.jsonl + graph.json. Returns paths.

        If `session` is supplied it is written as-is (used by create() which
        holds newer in-memory state than the disk copy); otherwise the stored
        session.json is re-read.
        """
        stored = session if session is not None else self._read_session(sid)
        sdir = self._sdir(sid)
        ledger = self.ledger(sid)
        ev_path = os.path.join(sdir, "evidence.jsonl")
        ledger.save(ev_path)
        graph = build_graph(ledger, target=stored.get("target"))
        graph_path = os.path.join(sdir, "graph.json")
        with open(graph_path, "w", encoding="utf-8") as fh:
            json.dump(graph, fh, indent=2, ensure_ascii=False)
        self._write_session(sid, stored)
        return {"session_json": os.path.join(sdir, "session.json"),
                "evidence_jsonl": ev_path, "graph_json": graph_path,
                "findings": len(ledger)}

    def cancel(self, sid: str) -> dict:
        session = self._read_session(sid)
        if session["status"] == "cancelled":
            return session
        session["status"] = "cancelled"
        self._write_session(sid, session)
        _audit(sid, "session.cancel",
               f"cancelled at stage {session['stage']}", self.base_dir)
        return session

    def resume(self, sid: str) -> dict:
        session = self._read_session(sid)
        if session["status"] == "cancelled":
            raise ReconError(f"session {sid} was cancelled and cannot resume",
                             code="session_cancelled",
                             hint="Create a new session for a fresh analysis.")
        ledger = self.ledger(sid)  # reloads from disk if not cached
        remaining = [ {"stage": n, "name": STAGE_NAMES[n]}
                      for n in range(session["stage"] + 1, 8) ]
        if session["status"] == "done":
            remaining = []
        return {
            "session_id": sid, "target": session["target"],
            "target_kind": session["target_kind"], "mode": session["mode"],
            "stage": session["stage"], "stage_name": STAGE_NAMES[session["stage"]],
            "status": session["status"],
            "remaining_stages": remaining,
            "ledger_stats": ledger.stats(),
            "progress": session.get("progress", {}),
            "note": ("Ledger reloaded from evidence.jsonl; continue from stage "
                     f"{session['stage'] + 1}." if remaining else
                     "Session already complete; nothing remains."),
        }

    def list(self) -> list[dict]:
        out = []
        if not os.path.isdir(self.base_dir):
            return out
        for name in os.listdir(self.base_dir):
            path = os.path.join(self.base_dir, name, "session.json")
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    s = json.load(fh)
                out.append({
                    "session_id": s.get("id"), "target": s.get("target"),
                    "target_kind": s.get("target_kind"), "mode": s.get("mode"),
                    "stage": s.get("stage"), "status": s.get("status"),
                    "created_utc": s.get("created_utc"),
                    "findings": self.ledger(s.get("id")).stats()["total"]
                    if s.get("id") else 0,
                })
            except Exception:
                continue
        out.sort(key=lambda d: d.get("created_utc") or "", reverse=True)
        return out


# --------------------------------------------------------------------------
# JobManager — thread jobs with poll/cancel for long-running tools
# --------------------------------------------------------------------------

class JobManager:
    """Submit callables to background threads; poll for completion; cancel."""

    _PRUNE_AFTER_S = 3600

    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def submit(self, fn, *args, name: str = "job", **kwargs) -> str:
        if not callable(fn):
            raise ReconError("fn must be callable", code="invalid_job")
        self._prune()
        jid = "j-" + secrets.token_hex(4)
        cancel_event = threading.Event()
        job = {"job_id": jid, "name": name, "status": "running",
               "result": None, "error": None,
               "submitted_utc": _utcnow(), "cancel_event": cancel_event,
               "thread": None}
        def _run():
            try:
                if cancel_event.is_set():
                    return
                job["result"] = fn(*args, **kwargs)
                with self._lock:
                    if job["status"] == "running":
                        job["status"] = "done"
                        job["finished_utc"] = _utcnow()
            except Exception as e:  # noqa: BLE001 — surfaced via poll()
                with self._lock:
                    if job["status"] == "running":
                        job["status"] = "failed"
                        job["error"] = f"{type(e).__name__}: {e}"[:1000]
                        job["finished_utc"] = _utcnow()
        t = threading.Thread(target=_run, daemon=True,
                             name=f"omnirecon-{jid}")
        job["thread"] = t
        with self._lock:
            self._jobs[jid] = job
        t.start()
        return jid

    def poll(self, job_id: str) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                raise ReconError(f"job {job_id} not found", code="job_not_found")
            out = {"job_id": job_id, "name": job["name"],
                   "status": job["status"], "submitted_utc": job["submitted_utc"]}
            if job["status"] == "done":
                out["result"] = job["result"]
            elif job["status"] == "failed":
                out["error"] = job["error"]
            return out

    def cancel(self, job_id: str) -> bool:
        """Best-effort cancel. Returns True if the job was still running."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                raise ReconError(f"job {job_id} not found", code="job_not_found")
            if job["status"] != "running":
                return False
            job["cancel_event"].set()
            job["status"] = "cancelled"
            job["finished_utc"] = _utcnow()
            return True

    def _prune(self) -> None:
        """Drop finished jobs older than the retention window (keeps poll() useful)."""
        from datetime import datetime as _dt
        with self._lock:
            now = _dt.now(timezone.utc)
            for jid in list(self._jobs.keys()):
                jb = self._jobs[jid]
                if jb["status"] in ("done", "failed", "cancelled") \
                        and jb.get("finished_utc"):
                    try:
                        fin = _dt.fromisoformat(jb["finished_utc"])
                        if (now - fin).total_seconds() > self._PRUNE_AFTER_S:
                            self._jobs.pop(jid, None)
                    except Exception:
                        pass
