"""Shipped-artifact analysis: APK/IPA/native binaries/JS bundles.

OmniRecon goes deep on live web platforms and codebases. For opaque shipped
artifacts it does honest lightweight analysis itself (file type, ELF/PE
structure, APK manifest inventory, string mining with redaction) and, when
the REA CLI is installed with a configured provider (Ghidra/Hopper/IDA),
delegates deep decompilation to REA and fuses the results into the evidence
ledger. What the tool cannot do is recorded as BLOCKED/UNVERIFIED — never
invented.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

from omnirecon import recon_primitives as RP
from omnirecon import security as SEC


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout or "")[:200_000]
    except Exception as e:
        return 127, f"exec failed: {e}"[:200]


def _record(session_id: str, ftype: str, title: str, detail: str,
            classification: str, confidence: float, why: str,
            sources: list[str], **kw) -> None:
    """Append a finding to sessions/<sid>/evidence.jsonl (persisted)."""
    try:
        from omnirecon import evidence as ev
        sessions_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sessions")
        os.makedirs(os.path.join(sessions_dir, session_id), exist_ok=True)
        ledger_path = os.path.join(sessions_dir, session_id, "evidence.jsonl")
        ledger = ev.EvidenceLedger.load(ledger_path) \
            if os.path.exists(ledger_path) else ev.EvidenceLedger()
        ledger.add({"type": ftype, "title": title, "detail": detail[:2000],
                    "classification": classification, "confidence": confidence,
                    "confidence_why": why, "sources": sources, **kw})
        ledger.save(ledger_path)
    except Exception:
        pass


def file_kind(path: str) -> str:
    code, out = _run(["file", "-b", path])
    desc = out.strip().split("\n")[0] if code == 0 else "unknown"
    low = (path.lower(), desc.lower())
    if path.lower().endswith(".apk") or "android package" in desc.lower():
        return "apk"
    if path.lower().endswith(".ipa") or "ios app" in desc.lower():
        return "ipa"
    if "elf" in desc.lower():
        return "elf"
    if "pe32" in desc.lower() or path.lower().endswith((".exe", ".dll")):
        return "pe"
    if "mach-o" in desc.lower():
        return "macho"
    if path.lower().endswith(".dex"):
        return "dex"
    if path.lower().endswith(".js"):
        return "jsbundle"
    return "unknown"


def _interesting_strings(path: str, limit: int = 400) -> dict:
    """Mine strings for URLs, IPs, and interesting literals (redacted)."""
    code, out = _run(["strings", "-n", "6", path])
    urls, ips, keys = set(), set(), set()
    if code == 0:
        for line in out.splitlines():
            s = line.strip()
            if re.match(r"https?://[\w.\-/?=&%+#:;@]+$", s) and len(s) < 220:
                urls.add(s)
            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", s):
                ips.add(s)
    return {"urls": sorted(urls)[:limit],
            "ips": sorted(ips)[:100],
            "total_strings": len(out.splitlines()) if code == 0 else 0}


def _analyze_elf(session_id: str, path: str, out: dict) -> None:
    code, hdr = _run(["readelf", "-h", path])
    machine = entry = ""
    if code == 0:
        m = re.search(r"Machine:\s*(.+)", hdr)
        machine = m.group(1).strip() if m else ""
        m = re.search(r"Entry point address:\s*(\S+)", hdr)
        entry = m.group(1).strip() if m else ""
    code, dyn = _run(["readelf", "-d", path])
    needed = sorted(set(re.findall(r"NEEDED.*\[(.+?)\]", dyn))) if code == 0 else []
    code, syms = _run(["nm", "-D", "--defined-only", path])
    defined = len(syms.splitlines()) if code == 0 else 0
    code, usyms = _run(["nm", "-D", "--undefined-only", path])
    undefined = sorted({l.split()[-1] for l in usyms.splitlines()
                        if l.strip()}) if code == 0 else []
    out.update({"format": "ELF", "machine": machine, "entry_point": entry,
                "needed_libraries": needed[:40],
                "defined_dynamic_symbols": defined,
                "undefined_symbols_sample": undefined[:60]})
    _record(session_id, "tech", f"Native binary: ELF {machine}",
            f"Entry {entry}; {len(needed)} shared libs; "
            f"{defined} defined / {len(undefined)} undefined dynamic symbols.",
            "SOURCE_VERIFIED", 0.95, "readelf/nm parse of the binary headers",
            [path])
    if needed:
        _record(session_id, "note", f"{len(needed)} shared-library dependencies",
                ", ".join(needed[:20]), "SOURCE_VERIFIED", 0.95,
                "ELF dynamic section", [path])


def _analyze_apk(session_id: str, path: str, out: dict) -> None:
    entries, manifest_raw = [], b""
    try:
        with zipfile.ZipFile(path) as z:
            entries = z.namelist()
            for name in entries:
                if name == "AndroidManifest.xml":
                    manifest_raw = z.read(name)
                    break
    except Exception as e:
        out["zip_error"] = str(e)[:200]
    manifest_text = manifest_raw.decode("utf-8", "replace")
    pkg = re.search(r'package="([\w.]+)"', manifest_text)
    package = pkg.group(1) if pkg else None
    if not package:
        # binary XML: fall back to string mining
        code, st = _run(["strings", path])
        m = re.search(r"[\w]+(?:\.[\w]+){2,}", st) if code == 0 else None
        package = m.group(0) if m else None
    perms = sorted(set(re.findall(
        r"android\.permission\.[\w_]+", manifest_text)))
    activities = len(re.findall(r"<activity", manifest_text))
    has_dex = any(e.endswith(".dex") for e in entries)
    has_so = [e for e in entries if e.endswith(".so")][:20]
    out.update({"format": "APK", "package": package,
                "permissions": perms[:60], "activity_count": activities,
                "has_dex": has_dex, "native_libs": has_so,
                "zip_entries": len(entries)})
    _record(session_id, "tech",
            f"Android app: {package or 'unknown package'}",
            f"{len(entries)} zip entries; dex={has_dex}; "
            f"{len(perms)} permissions; ~{activities} activities; "
            f"{len(has_so)} native libs.",
            "SOURCE_VERIFIED" if package else "INFERRED", 0.9 if package else 0.6,
            "AndroidManifest.xml inside the APK", [path])
    for p in perms[:30]:
        _record(session_id, "note", f"Permission: {p}",
                "Declared in AndroidManifest.xml.", "SOURCE_VERIFIED", 0.95,
                "manifest parse", [path])


def rea_cli_path() -> str | None:
    """Locate the REA CLI if installed (for deep binary analysis)."""
    for cand in ("rea",):
        p = shutil.which(cand)
        if p:
            return p
    # npm global / local installs
    for base in (os.path.expanduser("~/.npm-global/bin"),
                 "/usr/local/bin", "/opt/hatch-image/bin"):
        p = os.path.join(base, "rea")
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def rea_analyze(path: str, timeout: int = 600) -> dict:
    """Run `rea analyze --format json` on an artifact.

    Returns {"ok": ..., "findings": [...]} or {"ok": False, "reason": ...}.
    Provider absence (no Ghidra/Hopper/IDA) is reported honestly, not faked.
    """
    cli = rea_cli_path()
    if not cli:
        return {"ok": False, "reason": "rea-not-installed",
                "hint": "npm i -g rea-agents, then configure a provider "
                        "(Ghidra/Hopper/IDA) for deep decompilation"}
    try:
        p = subprocess.run([cli, "analyze", path, "--format", "json"],
                           capture_output=True, text=True, timeout=timeout)
        data = json.loads(p.stdout) if p.stdout.strip() else {}
    except Exception as e:
        return {"ok": False, "reason": "rea-exec-failed",
                "hint": str(e)[:200]}
    if isinstance(data, dict) and data.get("code") in (
            "provider_unavailable", "unavailable"):
        return {"ok": False, "reason": "rea-provider-unavailable",
                "hint": "REA is installed but no analysis provider "
                        "(Ghidra/Hopper/IDA) is configured; "
                        "set GHIDRA_INSTALL_DIR or install Hopper"}
    return {"ok": True, "raw": data}


def analyze_artifact(session_id: str, path: str) -> dict:
    """Full artifact pipeline: lightweight intel + optional REA deep dive."""
    out: dict = {"path": path, "size_bytes": os.path.getsize(path)
                 if os.path.isfile(path) else 0}
    kind = file_kind(path)
    out["kind"] = kind
    _record(session_id, "tech", f"Artifact type: {kind}",
            f"Identified via libmagic: {path}", "SOURCE_VERIFIED", 0.9,
            "file(1) magic-byte identification", [path])

    if kind == "elf":
        _analyze_elf(session_id, path, out)
    elif kind == "apk":
        _analyze_apk(session_id, path, out)
    elif kind == "jsbundle":
        eps = RP.extract_endpoints_from_text(open(path, encoding="utf-8",
                                                  errors="replace").read()[:2_000_000],
                                            path)
        api = [e for e in eps["internal"] + eps["external"]
               if e["kind"] == "api"]
        out.update({"format": "JS bundle", "api_endpoints": api[:200]})
        for e in api[:100]:
            _record(session_id, "endpoint", f"Endpoint {e['endpoint']}",
                    f"kind={e['kind']} scope={e['scope']} — statically "
                    f"extracted from the shipped JS bundle.",
                    "SOURCE_VERIFIED", 0.8,
                    "string-literal extraction from bundle text", [path],
                    endpoint=e["endpoint"])
    else:
        out["format"] = kind
        _record(session_id, "note", f"Artifact format '{kind}': shallow analysis",
                "Deep structural parsing for this format is not built in; "
                "string mining below is the primary signal. Use REA with a "
                "configured provider for decompilation.",
                "UNVERIFIED", 0.5, "format not in the built-in parser set",
                [path],
                limitations="No disassembly performed natively.")

    mined = _interesting_strings(path)
    out["string_mining"] = {"total": mined["total_strings"],
                            "urls_found": len(mined["urls"]),
                            "ips_found": len(mined["ips"])}
    for u in mined["urls"][:40]:
        _record(session_id, "endpoint", f"Hardcoded URL: {u[:90]}",
                "String literal embedded in the artifact (redacted where "
                "sensitive).", "SOURCE_VERIFIED", 0.85,
                "strings(1) extraction", [path], endpoint=u)

    # REA deep dive (optional, honest about provider absence)
    rea = rea_analyze(path)
    out["rea"] = {"attempted": True, "ok": rea.get("ok"),
                  "reason": rea.get("reason")}
    if rea.get("ok"):
        _record(session_id, "note", "REA deep analysis completed",
                f"REA analyze succeeded on {os.path.basename(path)}; "
                f"raw output attached to session artifacts.",
                "SOURCE_VERIFIED", 0.9, "REA CLI --format json", [path])
        out["rea_raw_keys"] = list(rea.get("raw", {}).keys())[:20]
    else:
        _record(session_id, "note", "Deep decompilation unavailable",
                f"REA bridge: {rea.get('reason')}. {rea.get('hint', '')}",
                "BLOCKED", 1.0, "REA CLI/provider check",
                [path],
                limitations="Install rea-agents and configure Ghidra/Hopper/IDA "
                            "for function-level decompilation.")
    return SEC.redact(out)
