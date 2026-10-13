"""Electron application intelligence: asar extraction + IPC/API-surface inventory.

An installed Electron app is `resources/app.asar` — the entire app source in one
archive. This module detects asar files by header sniff, extracts them with a
pure-Python parser (no dependencies), and inventories the app's real API
surface: IPC channels (the desktop equivalent of REST routes), preload bridge
APIs, BrowserWindow security posture, auto-update endpoints, protocol handlers,
shortcuts, and native modules.

All findings use honest classifications: string literals parsed from shipped
code are SOURCE_VERIFIED; extraction failures are BLOCKED, never faked.
"""
from __future__ import annotations

import json
import os
import re
import struct

from omnirecon import recon_primitives as RP
from omnirecon import security as SEC

# ---------------------------------------------------------------------------
# asar format (Electron, chromium Pickle):
#   [u32=4][u32 H][u32 P][u32 json_len][json StringTable][data...]
# file data starts at offset 8 + H; per-file offsets in the JSON
# StringTable are relative to that data start.
# ---------------------------------------------------------------------------

_ASAR_U0 = 4  # size-pickle payload is always one UInt32


def _read_header(path: str) -> tuple[dict, int]:
    """Return (StringTable dict, data_start_offset). Raises on invalid.

    Real layout (electron/asar, chromium Pickle):
      [u32=4][u32 H][u32 P][u32 json_len][json][data...]
    with H = 8 + json_len, P = 4 + json_len, data at offset 8 + H.
    """
    size = os.path.getsize(path)
    if size < 20:
        raise ValueError("file too small to be asar")
    with open(path, "rb") as f:
        head = f.read(16)
        if len(head) < 16:
            raise ValueError("truncated asar header")
        u0, h, p, json_len = struct.unpack("<IIII", head)
        if u0 != _ASAR_U0:
            raise ValueError(f"bad asar size-pickle: {u0}")
        if h < 12 or 8 + h > size:
            raise ValueError(f"bad asar header_size: {h}")
        if p != h - 4:
            raise ValueError("asar payload size mismatch")
        if json_len != h - 8:
            raise ValueError("asar json length mismatch")
        raw = f.read(json_len)
        if len(raw) != json_len:
            raise ValueError("truncated asar StringTable")
    try:
        table = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"asar StringTable is not JSON: {e}") from e
    if not isinstance(table, dict) or "files" not in table:
        raise ValueError("asar StringTable has no 'files' tree")
    return table, 8 + h


def is_asar(path: str) -> bool:
    """Detect asar by header sniff (not just extension)."""
    try:
        if not os.path.isfile(path):
            return False
        size = os.path.getsize(path)
        if size < 20:
            return False
        with open(path, "rb") as f:
            head = f.read(16)
        u0, h, p, json_len = struct.unpack("<IIII", head)
        if u0 != _ASAR_U0:
            return False
        if h < 12 or 8 + h > size:
            return False
        if p != h - 4 or json_len != h - 8:
            return False
        with open(path, "rb") as f:
            f.seek(16)
            probe = f.read(min(json_len, 64)).lstrip()
        return probe.startswith(b'{"files"') or probe.startswith(b'{ "files"')
    except Exception:
        return False


def _safe_join(base: str, *parts: str) -> str | None:
    """Join and ensure the result stays inside base (path-traversal guard)."""
    p = os.path.abspath(os.path.join(base, *parts))
    if p != os.path.abspath(base) and not p.startswith(
            os.path.abspath(base) + os.sep):
        return None
    return p


def extract_asar(path: str, dest_dir: str) -> dict:
    """Extract an asar archive to dest_dir. Returns a summary dict.

    Raises ValueError on corrupt archives. Files marked "unpacked" live
    outside the archive (app.asar.unpacked/) and are skipped honestly.
    """
    table, data_offset = _read_header(path)
    os.makedirs(dest_dir, exist_ok=True)
    extracted, skipped_unpacked, skipped_bad = 0, 0, 0
    total_bytes = 0

    with open(path, "rb") as src:
        def _walk(node: dict, rel: str) -> None:
            nonlocal extracted, skipped_unpacked, skipped_bad, total_bytes
            files = node.get("files")
            if not isinstance(files, dict):
                return
            for name, meta in files.items():
                if not isinstance(name, str) or not name or name in (".", "..") \
                        or "/" in name or "\\" in name or not isinstance(meta, dict):
                    skipped_bad += 1
                    continue
                if "files" in meta:  # directory
                    _walk(meta, os.path.join(rel, name) if rel else name)
                    continue
                if meta.get("unpacked"):
                    skipped_unpacked += 1
                    continue
                try:
                    off = int(meta["offset"])
                    sz = int(meta["size"])
                except (KeyError, TypeError, ValueError):
                    skipped_bad += 1
                    continue
                if off < 0 or sz < 0:
                    skipped_bad += 1
                    continue
                dest = _safe_join(dest_dir, rel, name) if rel \
                    else _safe_join(dest_dir, name)
                if dest is None:
                    skipped_bad += 1
                    continue
                try:
                    os.makedirs(os.path.dirname(dest) or dest_dir, exist_ok=True)
                    src.seek(data_offset + off)
                    data = src.read(sz)
                    with open(dest, "wb") as fh:
                        fh.write(data)
                    extracted += 1
                    total_bytes += len(data)
                except (OSError, ValueError):
                    skipped_bad += 1

        _walk(table, "")

    return {"dest_dir": dest_dir, "files_extracted": extracted,
            "bytes_extracted": total_bytes,
            "skipped_unpacked": skipped_unpacked,
            "skipped_bad": skipped_bad,
            "data_offset": data_offset}


# ---------------------------------------------------------------------------
# ledger helper (same persisted pattern as artifact_intel._record)
# ---------------------------------------------------------------------------

def _record(session_id: str, ftype: str, title: str, detail: str,
            classification: str, confidence: float, why: str,
            sources: list, **kw) -> None:
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


# ---------------------------------------------------------------------------
# Electron API-surface regexes (string literals in shipped code)
# ---------------------------------------------------------------------------

_IPC_MAIN = re.compile(
    r"ipcMain\s*\.\s*(handle|on|once)\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]")
_IPC_RENDERER = re.compile(
    r"ipcRenderer\s*\.\s*(invoke|send|sendSync|on|once|postMessage)"
    r"\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]")
_EXPOSE = re.compile(
    r"exposeInMainWorld\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]")
_SHORTCUT = re.compile(
    r"globalShortcut\s*\.\s*register\s*\(\s*['\"`]([^'\"`]{1,80})['\"`]")
_PROTOCOL = re.compile(
    r"setAsDefaultProtocolClient\s*\(\s*['\"`]([^'\"`]{1,80})['\"`]")
_FEEDURL_STR = re.compile(
    r"setFeedURL\s*\(\s*['\"`]([^'\"`]{1,300})['\"`]")
_FEEDURL_OBJ = re.compile(
    r"setFeedURL\s*\(\s*\{[^}]{0,800}?\burl\s*:\s*['\"`]([^'\"`]{1,300})['\"`]")
_BROWSERWINDOW = re.compile(
    r"new\s+BrowserWindow\s*\(\s*\{", re.S)


# Minification-resilient IPC detection: production bundles rename the
# `ipcMain` identifier (e.g. `const{ipcMain:e}=require("electron")`), which
# defeats the literal regexes above. Track require("electron") dataflow and
# match the call SHAPE (alias.handle("channel")) instead of the identifier.
_REQUIRE_DESTRUCT = re.compile(
    r"(?:const|let|var)\s*\{\s*([^}]{0,400}?)\}\s*=\s*require\(\s*"
    r"['\"]electron['\"]\s*\)")
_REQUIRE_MODULE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]electron['\"]\s*\)")
_IPC_CALL = re.compile(
    r"(\w+)\s*\.\s*(handle|on|once|invoke|send|sendSync|postMessage)"
    r"\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]")


def _extract_ipc_aliased(text: str, ipc_main: dict, ipc_renderer: dict) -> None:
    """Find IPC channels through renamed require("electron") bindings."""
    main_aliases, renderer_aliases = set(), set()
    for m in _REQUIRE_DESTRUCT.finditer(text):
        for part in m.group(1).split(","):
            part = part.strip()
            if ":" in part:
                orig, alias = (p.strip() for p in part.split(":", 1))
            else:
                orig = alias = part
            if orig == "ipcMain" and alias.isidentifier():
                main_aliases.add(alias)
            elif orig == "ipcRenderer" and alias.isidentifier():
                renderer_aliases.add(alias)
    for m in _REQUIRE_MODULE.finditer(text):
        mod = m.group(1)
        # e.ipcMain.handle("ch") — module-object member access
        for mm in re.finditer(
                r"\b" + re.escape(mod) + r"\s*\.\s*ipcMain\s*\.\s*"
                r"(handle|on|once)\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]", text):
            ipc_main.setdefault(mm.group(2), set()).add(mm.group(1))
        for mm in re.finditer(
                r"\b" + re.escape(mod) + r"\s*\.\s*ipcRenderer\s*\.\s*"
                r"(invoke|send|sendSync|on|once|postMessage)"
                r"\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]", text):
            ipc_renderer.setdefault(mm.group(2), set()).add(mm.group(1))
    # inline require("electron").ipcMain.handle("ch")
    for mm in re.finditer(
            r"require\(\s*['\"]electron['\"]\s*\)\.ipcMain\s*\.\s*"
            r"(handle|on|once)\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]", text):
        ipc_main.setdefault(mm.group(2), set()).add(mm.group(1))
    for mm in re.finditer(
            r"require\(\s*['\"]electron['\"]\s*\)\.ipcRenderer\s*\.\s*"
            r"(invoke|send|sendSync|on|once|postMessage)"
            r"\s*\(\s*['\"`]([^'\"`]{1,120})['\"`]", text):
        ipc_renderer.setdefault(mm.group(2), set()).add(mm.group(1))
    for m in _IPC_CALL.finditer(text):
        alias, method, channel = m.group(1), m.group(2), m.group(3)
        if alias in main_aliases and method in ("handle", "on", "once"):
            ipc_main.setdefault(channel, set()).add(method + " (aliased)")
        elif alias in renderer_aliases:
            ipc_renderer.setdefault(channel, set()).add(method + " (aliased)")
_WEBPREFS = re.compile(
    r"webPreferences\s*:\s*\{([^}]{0,2000}?)\}", re.S)
_FLAG = re.compile(r"(\w+)\s*:\s*(true|false|['\"`][^'\"`]*['\"`])")
_ACCEL = re.compile(r"accelerator\s*:\s*['\"`]([^'\"`]{1,80})['\"`]")

_MAX_JS_FILES = 400
_MAX_JS_BYTES = 60_000_000
_MAX_TEXT_FOR_ENDPOINTS = 2_000_000


def _iter_js_files(root: str):
    """Yield (relpath, abspath) for .js files, skipping node_modules."""
    count, total = 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "node_modules"]
        for fn in filenames:
            if not fn.endswith(".js"):
                continue
            ap = os.path.join(dirpath, fn)
            try:
                sz = os.path.getsize(ap)
            except OSError:
                continue
            if count >= _MAX_JS_FILES or total + sz > _MAX_JS_BYTES:
                return
            count += 1
            total += sz
            yield os.path.relpath(ap, root), ap


def analyze_electron_dir(dir: str, session_id: str,
                         origin: str = "") -> dict:
    """Inventory an extracted Electron app directory. Records findings."""
    out: dict = {"dir": dir}
    src = origin or dir

    # ---- package.json ----
    pkg: dict = {}
    pkg_path = os.path.join(dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, encoding="utf-8", errors="replace") as fh:
                pkg = json.load(fh)
            if not isinstance(pkg, dict):
                pkg = {}
        except Exception:
            pkg = {}
    name = str(pkg.get("name", "") or "")[:120]
    version = str(pkg.get("version", "") or "")[:40]
    main = str(pkg.get("main", "") or "")[:200]
    deps = pkg.get("dependencies") or {}
    electron_ver = str(deps.get("electron", "") or "")[:40]
    publish = ((pkg.get("build") or {}).get("publish") if isinstance(
        pkg.get("build"), dict) else None)
    updaters: list[str] = []
    if isinstance(publish, dict):
        publish = [publish]
    if isinstance(publish, list):
        for p in publish:
            if isinstance(p, dict):
                url = str(p.get("url", "") or "")[:300]
                if url:
                    updaters.append(
                        f"{p.get('provider', '')} {url}".strip()[:320])
    out.update({"app_name": name, "app_version": version, "main": main,
                "electron_version": electron_ver, "updaters": updaters[:10],
                "has_package_json": bool(pkg)})

    js_files = list(_iter_js_files(dir))
    out["js_files_scanned"] = len(js_files)
    _record(session_id, "tech",
            f"Electron app: {name or 'unknown'}"
            + (f" v{version}" if version else ""),
            f"main={main or '?'}; electron={electron_ver or '?'}; "
            f"{len(js_files)} JS files scanned (node_modules excluded); "
            f"updaters: {', '.join(updaters[:3]) or 'none found'}.",
            "SOURCE_VERIFIED" if pkg else "INFERRED",
            0.95 if pkg else 0.5,
            "parsed from the app's own package.json" if pkg else
            "no package.json in extracted tree",
            [pkg_path if pkg else dir])
    for u in updaters[:10]:
        url = u.split(" ", 1)[-1] if " " in u else u
        _record(session_id, "endpoint", f"Auto-update feed: {url[:100]}",
                f"electron-updater publish config: {u[:200]}",
                "SOURCE_VERIFIED", 0.9,
                "package.json build.publish", [pkg_path], endpoint=url)

    # ---- regex scan over shipped JS ----
    ipc_main: dict[str, set[str]] = {}
    ipc_renderer: dict[str, set[str]] = {}
    exposed: set[str] = set()
    shortcuts: set[str] = set()
    protocols: set[str] = set()
    feed_urls: set[str] = set()
    accelerators: set[str] = set()
    webprefs: dict[str, str] = {}
    texts: list[str] = []

    for rel, ap in js_files:
        try:
            with open(ap, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if sum(len(t) for t in texts) < _MAX_TEXT_FOR_ENDPOINTS:
            texts.append(text)
        for m in _IPC_MAIN.finditer(text):
            ipc_main.setdefault(m.group(2), set()).add(m.group(1))
        for m in _IPC_RENDERER.finditer(text):
            ipc_renderer.setdefault(m.group(2), set()).add(m.group(1))
        _extract_ipc_aliased(text, ipc_main, ipc_renderer)
        exposed.update(m.group(1) for m in _EXPOSE.finditer(text))
        shortcuts.update(m.group(1) for m in _SHORTCUT.finditer(text))
        protocols.update(m.group(1) for m in _PROTOCOL.finditer(text))
        feed_urls.update(m.group(1) for m in _FEEDURL_STR.finditer(text))
        feed_urls.update(m.group(1) for m in _FEEDURL_OBJ.finditer(text))
        accelerators.update(m.group(1) for m in _ACCEL.finditer(text))
        for wm in _WEBPREFS.finditer(text):
            for fm in _FLAG.finditer(wm.group(1)):
                v = fm.group(2).strip("'\"`")
                webprefs.setdefault(fm.group(1), v[:40])

    out.update({
        "ipc_main_channels": sorted(ipc_main)[:200],
        "ipc_renderer_channels": sorted(ipc_renderer)[:200],
        "preload_apis": sorted(exposed)[:100],
        "global_shortcuts": sorted(shortcuts)[:50],
        "protocol_handlers": sorted(protocols)[:50],
        "feed_urls": sorted(feed_urls)[:20],
        "menu_accelerators": sorted(accelerators)[:100],
        "web_preferences": webprefs,
    })

    # IPC channels are the app's internal API surface → endpoint findings so
    # they flow into the graph / spec / export machinery.
    for ch in sorted(ipc_main)[:150]:
        kinds = ",".join(sorted(ipc_main[ch]))
        _record(session_id, "endpoint",
                f"IPC channel (main): '{ch[:80]}' [{kinds}]",
                "Main-process IPC endpoint. Rebuild must implement this "
                "channel in the main process.",
                "SOURCE_VERIFIED", 0.85,
                "ipcMain.handle/on string literal in shipped code",
                [src], endpoint=f"ipc://{ch}")
    for ch in sorted(ipc_renderer)[:150]:
        kinds = ",".join(sorted(ipc_renderer[ch]))
        _record(session_id, "endpoint",
                f"IPC channel (renderer): '{ch[:80]}' [{kinds}]",
                "Renderer-side IPC call site. Pairs with the main-process "
                "channel of the same name.",
                "SOURCE_VERIFIED", 0.85,
                "ipcRenderer.invoke/send/on string literal in shipped code",
                [src], endpoint=f"ipc://{ch}")
    for api in sorted(exposed)[:60]:
        _record(session_id, "note", f"Preload bridge API: '{api[:80]}'",
                "Exposed to the renderer via contextBridge.exposeInMainWorld.",
                "SOURCE_VERIFIED", 0.85,
                "exposeInMainWorld string literal in shipped code", [src])
    if webprefs:
        flags = ", ".join(f"{k}={v}" for k, v in sorted(webprefs.items())[:20])
        _record(session_id, "tech", "BrowserWindow security posture",
                f"webPreferences observed: {flags}. Rebuild should replicate "
                f"these (especially contextIsolation/sandbox).",
                "SOURCE_VERIFIED", 0.85,
                "BrowserWindow options literal in shipped code", [src])
    for sc in sorted(shortcuts)[:30]:
        _record(session_id, "note", f"Global shortcut: {sc[:60]}",
                "Registered via globalShortcut.register.",
                "SOURCE_VERIFIED", 0.85, "string literal in shipped code",
                [src])
    for proto in sorted(protocols)[:20]:
        _record(session_id, "note", f"Protocol handler: {proto[:60]}",
                "OS deep-link integration via setAsDefaultProtocolClient.",
                "SOURCE_VERIFIED", 0.85, "string literal in shipped code",
                [src])
    for fu in sorted(feed_urls)[:10]:
        _record(session_id, "endpoint", f"Auto-update feed: {fu[:100]}",
                "autoUpdater.setFeedURL target.",
                "SOURCE_VERIFIED", 0.9,
                "setFeedURL string literal in shipped code",
                [src], endpoint=fu)

    # HTTP(S) endpoints inside the shipped JS (reuse the web endpoint engine)
    blob = "\n".join(texts)[:_MAX_TEXT_FOR_ENDPOINTS]
    eps = RP.extract_endpoints_from_text(blob, "")
    api = [e for e in eps["internal"] + eps["external"] if e["kind"] == "api"]
    out["http_endpoints"] = [e["endpoint"] for e in api[:200]]
    for e in api[:60]:
        _record(session_id, "endpoint", f"Endpoint {e['endpoint']}",
                "Statically extracted from the shipped Electron JS.",
                "SOURCE_VERIFIED", 0.8,
                "string-literal extraction from app code",
                [src], endpoint=e["endpoint"])

    # ---- native modules ----
    node_files: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(dir):
        for fn in filenames:
            if fn.endswith(".node"):
                ap = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(ap)
                except OSError:
                    continue
                node_files.append({"path": os.path.relpath(ap, dir)[:200],
                                   "size": sz})
    out["native_modules"] = node_files[:50]
    for nf in node_files[:20]:
        _record(session_id, "tech",
                f"Native module: {nf['path'][:80]} ({nf['size']} bytes)",
                "Compiled native addon; internals need disassembly (REA).",
                "SOURCE_VERIFIED", 0.9, "file present in extracted app",
                [src],
                limitations="Native code behavior not analyzed; route to REA.")

    return SEC.redact(out)
