"""Evidence model for OmniRecon: Finding dataclass + persistent EvidenceLedger.

Every significant observation becomes a Finding with an explicit
classification (OBSERVED | SOURCE_VERIFIED | INFERRED | UNVERIFIED | BLOCKED),
a confidence score with justification, and traceable sources.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from .security import ReconError, redact as _redact_finding

CLASSIFICATIONS = frozenset({
    "OBSERVED", "SOURCE_VERIFIED", "INFERRED", "UNVERIFIED", "BLOCKED",
})

# classification strength used to break confidence ties during dedup
_CLASS_RANK = {
    "OBSERVED": 4, "SOURCE_VERIFIED": 3, "INFERRED": 2,
    "UNVERIFIED": 1, "BLOCKED": 0,
}

FINDING_TYPES = frozenset({
    "route", "component", "endpoint", "entity", "workflow",
    "asset", "auth", "tech", "state", "note", "schema", "signature",
})

VERIFICATION_STATES = frozenset({"unverified", "verified", "contradicted"})


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    id: str = ""                      # "F-0001" — ledger-assigned, stable
    type: str = "note"                # route|component|endpoint|entity|workflow|asset|auth|tech|state|note
    title: str = ""
    detail: str = ""
    classification: str = "UNVERIFIED"
    confidence: float = 0.5
    confidence_why: str = ""
    sources: list[str] = field(default_factory=list)
    route: str | None = None
    component: str | None = None
    endpoint: str | None = None
    artifact: str | None = None       # relative path under session dir
    timestamp: str = ""
    verification: str = "unverified"
    limitations: str = ""
    engine: str | None = None         # which engine produced this finding:
                                      # static|rendered|network|spec|binary
    shape: dict | None = None         # machine-readable request/response
                                      # shape (values-free, redacted)
    shape_kind: str | None = None     # "request" | "response" | "websocket"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in known})


class EvidenceLedger:
    """In-memory finding store with JSONL persistence and dedup."""

    def __init__(self):
        self._findings: dict[str, Finding] = {}
        self._counter = 0
        self._lock = threading.Lock()

    # -- mutation ------------------------------------------------------
    def add(self, f: dict) -> str:
        """Validate, assign id + timestamp, store. Returns the finding id."""
        if not isinstance(f, dict):
            raise ReconError("finding must be a dict", code="invalid_finding")
        classification = str(f.get("classification", "UNVERIFIED")).upper()
        if classification not in CLASSIFICATIONS:
            raise ReconError(
                f"invalid classification {classification!r}; "
                f"must be one of {sorted(CLASSIFICATIONS)}",
                code="invalid_classification",
                hint="Use OBSERVED for captured evidence, INFERRED for derived claims.",
            )
        ftype = str(f.get("type", "note"))
        if ftype not in FINDING_TYPES:
            raise ReconError(
                f"invalid finding type {ftype!r}; must be one of {sorted(FINDING_TYPES)}",
                code="invalid_finding_type",
            )
        verification = str(f.get("verification", "unverified"))
        if verification not in VERIFICATION_STATES:
            raise ReconError(
                f"invalid verification {verification!r}",
                code="invalid_verification",
            )
        try:
            confidence = float(f.get("confidence", 0.5))
        except (TypeError, ValueError):
            raise ReconError("confidence must be a number 0.0–1.0",
                             code="invalid_confidence")
        if not 0.0 <= confidence <= 1.0:
            raise ReconError("confidence must be between 0.0 and 1.0",
                             code="invalid_confidence")

        # Central redaction: every finding is scrubbed before it becomes
        # durable ledger state, no matter which module recorded it. This is
        # the last line of defense — per-tool redaction at return boundaries
        # is not sufficient on its own. sources[] and limitations are
        # redacted too: captured URLs land in sources[] verbatim, and that
        # is where query-param secrets live.
        with self._lock:
            self._counter += 1
            finding = Finding(
                id=f"F-{self._counter:04d}",
                type=ftype,
                title=_redact_finding(str(f.get("title", ""))),
                detail=_redact_finding(str(f.get("detail", ""))),
                classification=classification,
                confidence=confidence,
                confidence_why=_redact_finding(str(f.get("confidence_why", ""))),
                sources=[_redact_finding(str(s)) for s in (f.get("sources") or [])],
                route=_redact_finding(f.get("route")) if f.get("route") else None,
                component=_redact_finding(f.get("component")) if f.get("component") else None,
                endpoint=_redact_finding(f.get("endpoint")) if f.get("endpoint") else None,
                artifact=f.get("artifact"),
                timestamp=_utcnow(),
                verification=verification,
                limitations=_redact_finding(str(f.get("limitations", ""))),
                engine=f.get("engine"),
                shape=_redact_finding(f.get("shape")) if f.get("shape") else None,
                shape_kind=str(f.get("shape_kind", "")) or None,
            )
            self._findings[finding.id] = finding
        return finding.id

    def dedup(self) -> int:
        """Merge duplicate findings keyed by (type, route or endpoint or title).

        Survivor = highest (confidence, classification rank); sources merged
        (order-preserving union); distinct limitations concatenated.
        Returns the number of findings merged away.
        """
        groups: dict[tuple, list[Finding]] = {}
        for f in self._findings.values():
            anchor = f.route or f.endpoint or f.title.strip().lower()
            groups.setdefault((f.type, anchor), []).append(f)

        merged_away = 0
        for key, members in groups.items():
            if len(members) < 2:
                continue
            members.sort(key=lambda f: (f.confidence, _CLASS_RANK[f.classification]),
                         reverse=True)
            survivor = members[0]
            for dup in members[1:]:
                for src in dup.sources:
                    if src not in survivor.sources:
                        survivor.sources.append(src)
                if dup.limitations and dup.limitations not in survivor.limitations:
                    survivor.limitations = (
                        (survivor.limitations + " | " + dup.limitations)
                        if survivor.limitations else dup.limitations
                    )
                if dup.artifact and not survivor.artifact:
                    survivor.artifact = dup.artifact
                del self._findings[dup.id]
                merged_away += 1
        return merged_away

    # -- reads ---------------------------------------------------------
    def get(self, fid: str) -> dict | None:
        f = self._findings.get(fid)
        return f.to_dict() if f else None

    def merge_from(self, other: "EvidenceLedger") -> int:
        """Absorb findings from another ledger that this one lacks (by id).

        Used by SessionManager.checkpoint() to pick up findings that modules
        wrote directly to evidence.jsonl, bypassing the in-memory cache —
        without this, checkpoint() would silently discard them. Returns the
        number of findings absorbed. Also syncs the id counter past the
        highest absorbed id to prevent id reuse collisions.
        """
        absorbed = 0
        for fid, f in other._findings.items():
            if fid not in self._findings:
                self._findings[fid] = f
                absorbed += 1
                try:
                    num = int(fid.split("-", 1)[1])
                    if num > self._counter:
                        self._counter = num
                except (ValueError, IndexError):
                    pass
        return absorbed

    def list(self, type: str | None = None, classification: str | None = None,
             min_confidence: float = 0.0) -> list[dict]:
        out = []
        for f in self._findings.values():
            if type and f.type != type:
                continue
            if classification and f.classification != classification:
                continue
            if f.confidence < min_confidence:
                continue
            out.append(f.to_dict())
        return out

    def search(self, text: str) -> list[dict]:
        q = (text or "").strip().lower()
        if not q:
            return []
        return [f.to_dict() for f in self._findings.values()
                if q in f.title.lower() or q in f.detail.lower()]

    def stats(self) -> dict:
        by_type: dict[str, int] = {}
        by_class: dict[str, int] = {}
        for f in self._findings.values():
            by_type[f.type] = by_type.get(f.type, 0) + 1
            by_class[f.classification] = by_class.get(f.classification, 0) + 1
        return {"total": len(self._findings),
                "by_type": by_type, "by_classification": by_class}

    # -- persistence ---------------------------------------------------
    def save(self, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for f in self._findings.values():
                fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
        return path

    @classmethod
    def load(cls, path: str) -> "EvidenceLedger":
        ledger = cls()
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                f = Finding.from_dict(json.loads(line))
                ledger._findings[f.id] = f
                try:
                    n = int(f.id.split("-")[1])
                    ledger._counter = max(ledger._counter, n)
                except (IndexError, ValueError):
                    pass
        return ledger

    def __len__(self) -> int:
        return len(self._findings)
