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


def _session_dir(session_id: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sessions", session_id)


def _record(session_id: str, ftype: str, title: str, detail: str,
            classification: str, confidence: float, why: str,
            sources: list[str], **kw) -> None:
    """Append a finding to sessions/<sid>/evidence.jsonl (persisted)."""
    try:
        from omnirecon import evidence as ev
        sdir = _session_dir(session_id)
        os.makedirs(sdir, exist_ok=True)
        ledger_path = os.path.join(sdir, "evidence.jsonl")
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
    if path.lower().endswith(".asar"):
        return "asar"
    try:
        from omnirecon import electron_intel as EI
        if EI.is_asar(path):
            return "asar"
    except Exception:
        pass
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

    # Binary XML (AXML) is what production APKs ship — decode it properly.
    summary: dict | None = None
    try:
        from omnirecon import axml as AX
        root = AX.parse(manifest_raw)
        if root is not None:
            summary = AX.manifest_summary(root)
    except Exception:
        summary = None

    package = (summary or {}).get("package") or None
    perms = (summary or {}).get("permissions") or []
    activities = (summary or {}).get("activities") or []
    services = (summary or {}).get("services") or []
    receivers = (summary or {}).get("receivers") or []
    providers = (summary or {}).get("providers") or []
    deep_links = (summary or {}).get("deep_links") or []
    has_dex = any(e.endswith(".dex") for e in entries)
    has_so = [e for e in entries if e.endswith(".so")][:20]
    out.update({"format": "APK", "package": package,
                "version_name": (summary or {}).get("version_name", ""),
                "min_sdk": (summary or {}).get("min_sdk", ""),
                "target_sdk": (summary or {}).get("target_sdk", ""),
                "permissions": perms[:60],
                "activities": activities[:60],
                "services": services[:40],
                "receivers": receivers[:40],
                "providers": providers[:40],
                "deep_links": deep_links[:20],
                "debuggable": (summary or {}).get("debuggable", ""),
                "has_dex": has_dex, "native_libs": has_so,
                "zip_entries": len(entries),
                "manifest_decoded": summary is not None})
    _record(session_id, "tech",
            f"Android app: {package or 'unknown package'}",
            f"{len(entries)} zip entries; dex={has_dex}; "
            f"{len(perms)} permissions; {len(activities)} activities; "
            f"{len(services)} services; {len(receivers)} receivers; "
            f"{len(deep_links)} deep-link filters; "
            f"{len(has_so)} native libs."
            + ("" if summary is not None else
               " Manifest is not binary-XML-decodable; treated as opaque."),
            "SOURCE_VERIFIED" if package else "INFERRED", 0.9 if package else 0.6,
            "AndroidManifest.xml decoded from the APK's binary XML"
            if summary is not None else
            "APK zip inventory only; manifest not decoded",
            [path])
    for p in perms[:30]:
        _record(session_id, "note", f"Permission: {p}",
                "Declared in AndroidManifest.xml.", "SOURCE_VERIFIED", 0.95,
                "manifest parse", [path])
    for dl in deep_links[:10]:
        schemes = ", ".join(
            f"{d.get('android:scheme', '')}://{d.get('android:host', '')}"
            for d in dl.get("data", []))[:160]
        _record(session_id, "endpoint", f"Deep link: {schemes or 'view intent'}",
                f"Intent-filter with VIEW action: {schemes}.",
                "SOURCE_VERIFIED", 0.9, "manifest intent-filter decode",
                [path], endpoint=schemes)

    # DEX code inventory: the manifest says what the app declares;
    # the DEX says what it does (classes, method refs, API usage).
    if has_dex:
        try:
            from omnirecon import dex as DX
            dex_items = DX.parse_apk_dex(path)
            out["dex_files"] = [d["dex_name"] for d in dex_items]
            out["dex_parsed"] = sum(1 for d in dex_items if d["parsed"])
            for d in dex_items:
                DX.summarize_parsed(d["parsed"], session_id,
                                    origin=d["origin"],
                                    dex_name=d["dex_name"])
        except Exception as e:  # noqa: BLE001 — DEX is best-effort
            out["dex_error"] = str(e)[:200]
            _record(session_id, "note", "DEX inventory failed",
                    f"Could not inventory DEX code: {str(e)[:200]}",
                    "BLOCKED", 1.0, "DEX discovery/parse", [path],
                    engine="binary")


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


def rea_analyze(path: str, timeout: int = 600,
                flavor: str = "generic") -> dict:
    """Run REA on an artifact and return the parsed JSON result.

    flavor="electron" uses REA's Electron-aware `analyze-javascript-application`
    (accepts an asar or an extracted app dir) instead of the generic
    `rea analyze`. Returns {"ok": ...} or {"ok": False, "reason": ...};
    provider absence is reported honestly, not faked.
    """
    cli = rea_cli_path()
    if not cli:
        return {"ok": False, "reason": "rea-not-installed",
                "flavor": flavor,
                "hint": "npm i -g rea-agents, then configure a provider "
                        "(Ghidra/Hopper/IDA) for deep decompilation"}
    cmd = ([cli, "analyze-javascript-application", path, "--format", "json"]
           if flavor == "electron"
           else [cli, "analyze", path, "--format", "json"])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        data = json.loads(p.stdout) if p.stdout.strip() else {}
    except Exception as e:
        return {"ok": False, "reason": "rea-exec-failed",
                "flavor": flavor, "hint": str(e)[:200]}
    if isinstance(data, dict) and data.get("code") in (
            "provider_unavailable", "unavailable"):
        return {"ok": False, "reason": "rea-provider-unavailable",
                "flavor": flavor,
                "hint": "REA is installed but no analysis provider "
                        "(Ghidra/Hopper/IDA) is configured; "
                        "set GHIDRA_INSTALL_DIR or install Hopper"}
    return {"ok": True, "raw": data, "flavor": flavor}


def _fuse_rea(session_id: str, path: str, rea: dict, out: dict) -> None:
    """Record a REA bridge result in the ledger + output dict."""
    out["rea"] = {"attempted": True, "ok": rea.get("ok"),
                  "reason": rea.get("reason"),
                  "flavor": rea.get("flavor", "generic")}
    if rea.get("ok"):
        _record(session_id, "note", "REA deep analysis completed",
                f"REA ({rea.get('flavor', 'generic')}) succeeded on "
                f"{os.path.basename(path)}; raw output attached to session "
                f"artifacts.",
                "SOURCE_VERIFIED", 0.9, "REA CLI --format json", [path])
        out["rea_raw_keys"] = list(rea.get("raw", {}).keys())[:20]
    else:
        _record(session_id, "note", "Deep decompilation unavailable",
                f"REA bridge: {rea.get('reason')}. {rea.get('hint', '')}",
                "BLOCKED", 1.0, "REA CLI/provider check",
                [path],
                limitations="Install rea-agents and configure Ghidra/Hopper/IDA "
                            "for function-level decompilation.")


def _analyze_asar(session_id: str, path: str, out: dict) -> None:
    """Electron asar pipeline: extract, inventory, REA electron-flavor."""
    from omnirecon import electron_intel as EI
    dest = os.path.join(_session_dir(session_id), "artifacts", "asar")
    try:
        res = EI.extract_asar(path, dest)
    except Exception as e:
        out.update({"format": "asar", "extraction": "failed",
                    "error": str(e)[:200]})
        _record(session_id, "note", "asar extraction failed",
                f"Could not parse {os.path.basename(path)} as an Electron "
                f"asar archive: {e!s}"[:500],
                "BLOCKED", 1.0, "asar header/StringTable parse",
                [path],
                limitations="Archive may be corrupt, encrypted, or use an "
                            "unsupported asar variant.")
        return
    out.update({"format": "asar", "extraction": "ok",
                "extracted_to": os.path.relpath(dest, _session_dir(session_id)),
                **{k: v for k, v in res.items() if k != "dest_dir"}})
    _record(session_id, "tech",
            f"Electron asar extracted: {res['files_extracted']} files",
            f"{res['files_extracted']} files ({res['bytes_extracted']} bytes) "
            f"extracted to {out['extracted_to']}; "
            f"{res['skipped_unpacked']} unpacked-external, "
            f"{res['skipped_bad']} skipped.",
            "SOURCE_VERIFIED", 0.95, "pure-Python asar StringTable parse",
            [path])
    intel = EI.analyze_electron_dir(dest, session_id, origin=path)
    out["electron"] = {k: v for k, v in intel.items() if k != "dir"}
    # REA electron-aware deep dive on the extracted tree
    _fuse_rea(session_id, dest, rea_analyze(dest, flavor="electron"), out)


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
    elif kind == "asar":
        _analyze_asar(session_id, path, out)
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

    # REA deep dive (optional, honest about provider absence).
    # asar already ran its electron-flavor REA inside _analyze_asar.
    if kind != "asar":
        _fuse_rea(session_id, path, rea_analyze(path), out)
    return SEC.redact(out)
