"""Tests for the Electron module: asar detection, extraction round-trip,
IPC/API-surface extraction, package.json parsing, graceful failure."""
import json
import os
import shutil
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from omnirecon import electron_intel as EI  # noqa: E402
from omnirecon import artifact_intel as AI  # noqa: E402
from omnirecon.session import _detect_target_kind, _ARTIFACT_EXTS  # noqa: E402


def build_asar(files: dict[str, bytes]) -> bytes:
    """Build a spec-correct asar archive from {path: bytes}."""
    root: dict = {"files": {}}
    for p, data in files.items():
        node = root
        parts = p.split("/")
        for part in parts[:-1]:
            node = node["files"].setdefault(part, {"files": {}})
        node["files"][parts[-1]] = {"_data": data}
    blobs: list[bytes] = []

    def assign(node: dict) -> None:
        for name, meta in node["files"].items():
            if "files" in meta:
                assign(meta)
            else:
                data = meta.pop("_data")
                meta["size"] = len(data)
                meta["offset"] = str(sum(len(b) for b in blobs))
                blobs.append(data)

    assign(root)
    js = json.dumps({"files": root["files"]}).encode("utf-8")
    h = 8 + len(js)
    p = 4 + len(js)
    header = struct.pack("<IIII", 4, h, p, len(js)) + js
    return header + b"".join(blobs)


def _write(tmp_path, name: str, data: bytes) -> str:
    p = os.path.join(str(tmp_path), name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


def _ledger(sid: str) -> list[dict]:
    lp = os.path.join(os.path.dirname(__file__), "..", "sessions", sid,
                       "evidence.jsonl")
    if not os.path.exists(lp):
        return []
    return [json.loads(l) for l in open(lp) if l.strip()]


def _clean_sid(sid: str) -> None:
    d = os.path.join(os.path.dirname(__file__), "..", "sessions", sid)
    shutil.rmtree(d, ignore_errors=True)


def test_is_asar_detects_header(tmp_path):
    p = _write(tmp_path, "app.asar",
               build_asar({"main.js": b"console.log(1)"}))
    assert EI.is_asar(p) is True


def test_is_asar_rejects_non_asar(tmp_path):
    p = _write(tmp_path, "nope.asar", b"this is not an asar file at all....")
    assert EI.is_asar(p) is False
    p2 = _write(tmp_path, "empty.asar", b"")
    assert EI.is_asar(p2) is False


def test_extract_asar_roundtrip(tmp_path):
    files = {
        "package.json": b'{"name":"x"}',
        "main.js": b"const {ipcMain} = require('electron');",
        "sub/renderer.js": b"window.api = {};",
        "empty.txt": b"",
    }
    src = _write(tmp_path, "app.asar", build_asar(files))
    dest = os.path.join(str(tmp_path), "out")
    res = EI.extract_asar(src, dest)
    assert res["files_extracted"] == 4, res
    for rel, data in files.items():
        with open(os.path.join(dest, *rel.split("/")), "rb") as fh:
            assert fh.read() == data, rel


def test_extract_asar_path_traversal_guard(tmp_path):
    # malicious entry with ../ must not escape dest_dir
    js = json.dumps({"files": {
        "../../evil.txt": {"size": 3, "offset": "0"},
        "ok.txt": {"size": 3, "offset": "3"},
    }}).encode()
    h, p = 8 + len(js), 4 + len(js)
    blob = struct.pack("<IIII", 4, h, p, len(js)) + js + b"BADOK!"
    src = _write(tmp_path, "evil.asar", blob)
    dest = os.path.join(str(tmp_path), "out")
    res = EI.extract_asar(src, dest)
    assert res["files_extracted"] == 1
    assert res["skipped_bad"] == 1
    assert not os.path.exists(os.path.join(str(tmp_path), "evil.txt"))


def test_ipc_extraction_and_findings(tmp_path):
    sid = "test-electron-ipc"
    _clean_sid(sid)
    try:
        appdir = os.path.join(str(tmp_path), "app")
        os.makedirs(appdir)
        with open(os.path.join(appdir, "main.js"), "w") as fh:
            fh.write("""
const {ipcMain, BrowserWindow, globalShortcut, app} = require('electron');
ipcMain.handle('get-settings', async () => ({}));
ipcMain.on('save-file', (e, data) => {});
app.setAsDefaultProtocolClient('myapp');
globalShortcut.register('CommandOrControl+Shift+I', () => {});
new BrowserWindow({width: 800, webPreferences: {contextIsolation: true, sandbox: true, preload: 'p.js'}});
""")
        with open(os.path.join(appdir, "renderer.js"), "w") as fh:
            fh.write("""
const {ipcRenderer, contextBridge} = require('electron');
ipcRenderer.invoke('get-settings');
ipcRenderer.send('save-file', {});
contextBridge.exposeInMainWorld('myAPI', {});
""")
        out = EI.analyze_electron_dir(appdir, sid, origin="test.asar")
        assert "get-settings" in out["ipc_main_channels"]
        assert "save-file" in out["ipc_main_channels"]
        assert "get-settings" in out["ipc_renderer_channels"]
        assert "myAPI" in out["preload_apis"]
        assert "myapp" in out["protocol_handlers"]
        assert out["web_preferences"].get("contextIsolation") == "true"
        assert out["web_preferences"].get("sandbox") == "true"
        fs = _ledger(sid)
        ipc_eps = [f for f in fs if f.get("type") == "endpoint"
                   and str(f.get("endpoint", "")).startswith("ipc://")]
        assert len(ipc_eps) >= 3, [f.get("title") for f in fs]
        assert all(f["classification"] == "SOURCE_VERIFIED" for f in ipc_eps)
    finally:
        _clean_sid(sid)


def test_package_json_parsing(tmp_path):
    sid = "test-electron-pkg"
    _clean_sid(sid)
    try:
        appdir = os.path.join(str(tmp_path), "app")
        os.makedirs(appdir)
        pkg = {"name": "demo-app", "version": "1.2.3", "main": "main.js",
               "dependencies": {"electron": "28.1.0"},
               "build": {"publish": [{"provider": "github", "owner": "acme",
                                       "repo": "demo",
                                       "url": "https://updates.example.com"}]}}
        with open(os.path.join(appdir, "package.json"), "w") as fh:
            json.dump(pkg, fh)
        out = EI.analyze_electron_dir(appdir, sid)
        assert out["app_name"] == "demo-app"
        assert out["app_version"] == "1.2.3"
        assert out["electron_version"] == "28.1.0"
        assert any("updates.example.com" in u for u in out["updaters"])
        fs = _ledger(sid)
        tech = [f for f in fs if "Electron app: demo-app" in f.get("title", "")]
        assert tech and tech[0]["classification"] == "SOURCE_VERIFIED"
    finally:
        _clean_sid(sid)


def test_corrupt_asar_graceful(tmp_path):
    sid = "test-electron-corrupt"
    _clean_sid(sid)
    try:
        p = _write(tmp_path, "bad.asar", b"\x04\x00\x00\x00garbage!!")
        out: dict = {}
        AI._analyze_asar(sid, p, out)
        assert out.get("extraction") == "failed"
        fs = _ledger(sid)
        blocked = [f for f in fs if f["classification"] == "BLOCKED"]
        assert blocked, "expected honest BLOCKED finding"
        assert "asar" in blocked[0]["title"].lower()
    finally:
        _clean_sid(sid)


def test_file_kind_asar_and_router(tmp_path):
    p = _write(tmp_path, "app.asar", build_asar({"a.js": b"x"}))
    assert AI.file_kind(p) == "asar"
    assert ".asar" in _ARTIFACT_EXTS
    kind, _ = _detect_target_kind(p)
    assert kind == "artifact"


def test_rea_flavor_param():
    # rea_analyze must accept flavor without breaking the default path
    res = AI.rea_analyze("/nonexistent-path-xyz", flavor="electron")
    assert res["ok"] is False
    assert res["reason"] in ("rea-not-installed", "rea-exec-failed",
                             "rea-provider-unavailable")
