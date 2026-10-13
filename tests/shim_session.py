"""TEST-ONLY thin shim for omnirecon.session (Lane B not finished yet).

Implements the ARCHITECTURE.md §3 SessionManager/JobManager surface with the
real recon_primitives for Stage 1+2. Lives in tests/ only — never in omnirecon/.
Inject via: sys.modules["omnirecon.session"] = shim_session
"""
from __future__ import annotations

import datetime
import json
import threading
import uuid
from pathlib import Path

from omnirecon import recon_primitives as RP

VALID_CLASS = ("OBSERVED", "SOURCE_VERIFIED", "INFERRED", "UNVERIFIED", "BLOCKED")


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class SessionManager:
    def __init__(self, base_dir: str):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def _sdir(self, sid: str) -> Path:
        return self.base / sid

    def _write(self, sid: str, session: dict):
        (self._sdir(sid) / "session.json").write_text(
            json.dumps(session, indent=2, default=str))

    def _read(self, sid: str) -> dict | None:
        p = self._sdir(sid) / "session.json"
        if not p.exists():
            return None
        return json.loads(p.read_text())

    def create(self, target: str, mode: str = "fast", budget: dict | None = None) -> dict:
        sid = "S-" + uuid.uuid4().hex[:8]
        sdir = self._sdir(sid)
        sdir.mkdir(parents=True, exist_ok=True)
        target_kind = "url" if target.startswith(("http://", "https://")) else "repo"
        session = {
            "id": sid, "session_id": sid, "target": target,
            "target_kind": target_kind, "mode": mode,
            "stage": 1, "status": "active",
            "created_utc": _utcnow(), "updated_utc": _utcnow(),
            "budget": budget or {"max_pages": 40, "max_depth": 3,
                                 "max_steps": 15, "timeout_s": 600},
            "progress": {}, "jobs": [],
        }
        # Stage 2 rapid recon (synchronous)
        findings = []
        if target_kind == "url":
            scan = RP.platform_scan(target)
            if not scan.get("error"):
                for t in scan.get("tech", []):
                    findings.append({
                        "type": "tech", "title": f"Tech: {t['tech']}",
                        "detail": t.get("evidence", ""),
                        "classification": "INFERRED", "confidence": 0.7,
                        "confidence_why": "heuristic marker match",
                        "sources": [target], "route": None, "component": None,
                        "endpoint": None, "artifact": None,
                        "verification": "unverified", "limitations": ""})
                findings.append({
                    "type": "route", "title": f"Route {scan.get('final_url')}",
                    "detail": f"status={scan.get('status')} title={scan.get('title')!r}",
                    "classification": "OBSERVED", "confidence": 0.95,
                    "confidence_why": "page fetched during rapid recon",
                    "sources": [scan.get("final_url") or target],
                    "route": scan.get("final_url") or target, "component": None,
                    "endpoint": None, "artifact": None,
                    "verification": "unverified", "limitations": ""})
                session["rapid_report"] = {
                    "status": scan.get("status"), "title": scan.get("title"),
                    "tech": [t["tech"] for t in scan.get("tech", [])]}
            else:
                session["rapid_report"] = {"error": scan["error"]}
        else:
            session["rapid_report"] = {"note": "repo target; run recon_analyze_source"}
        session["stage"] = 2
        self._write(sid, session)
        # seed ledger
        lines = []
        for i, f in enumerate(findings, 1):
            f = dict(f)
            f["id"] = f"F-{i:04d}"
            f["timestamp"] = _utcnow()
            lines.append(json.dumps(f))
        if lines:
            (sdir / "evidence.jsonl").write_text("\n".join(lines) + "\n")
        return {"session_id": sid, "id": sid, "target": target,
                "target_kind": target_kind, "mode": mode,
                "rapid_report": session.get("rapid_report", {})}

    def get(self, sid: str) -> dict | None:
        return self._read(sid)

    def update_stage(self, sid: str, stage: int):
        s = self._read(sid)
        if s:
            s["stage"] = stage
            s["updated_utc"] = _utcnow()
            self._write(sid, s)

    def checkpoint(self, sid: str):
        s = self._read(sid)
        if s:
            s["updated_utc"] = _utcnow()
            self._write(sid, s)

    def cancel(self, sid: str) -> dict:
        s = self._read(sid)
        if not s:
            return {"session_id": sid, "status": "not_found"}
        s["status"] = "cancelled"
        s["updated_utc"] = _utcnow()
        self._write(sid, s)
        return {"session_id": sid, "status": "cancelled"}

    def resume(self, sid: str) -> dict:
        s = self._read(sid)
        if not s:
            return {"session_id": sid, "status": "not_found"}
        return {"session_id": sid, "status": s["status"], "stage": s["stage"],
                "remaining": f"resume from stage {s['stage']}"}

    def list(self) -> list[dict]:
        out = []
        for p in self.base.iterdir():
            s = self._read(p.name) if p.is_dir() else None
            if s:
                out.append({"id": s["id"], "target": s["target"],
                            "status": s["status"], "stage": s["stage"]})
        return out


class JobManager:
    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def submit(self, fn, *a, **kw) -> str:
        jid = "J-" + uuid.uuid4().hex[:8]
        rec = {"job_id": jid, "status": "running", "result": None,
               "error": None}

        def _run():
            try:
                res = fn(*a, **kw)
                with self._lock:
                    rec["status"] = "done"
                    rec["result"] = res
            except Exception as e:
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
            return dict(rec) if rec else {"status": "unknown"}

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec and rec["status"] == "running":
                rec["status"] = "cancelled"
            return {"job_id": job_id,
                    "status": rec["status"] if rec else "unknown"}
