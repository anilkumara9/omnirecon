"""Tests for the one-command setup flow (omnirecon.cli setup).

Self-contained runner (no pytest in the venv): each test_* function is run
by main(). Also pytest-collectable. Run with:
    ~/workspace/venvs/recon/bin/python ~/workspace/omnirecon/tests/test_setup.py
"""
import json
import os
import sys
import tempfile
import traceback
from types import SimpleNamespace

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

from omnirecon.cli import (  # noqa: E402
    _detect_clients,
    _ensure_codex_toml,
    _merge_mcp_json,
    _setup_client,
)

_ENTRY = {"command": "/fake/python", "args": ["/fake/server.py"]}


class _Home:
    """Temporarily point $HOME at a fresh temp dir."""

    def __enter__(self):
        self.old = os.environ.get("HOME")
        self.tmp = tempfile.mkdtemp(prefix="omnirecon_home_")
        os.environ["HOME"] = self.tmp
        return self.tmp

    def __exit__(self, *a):
        if self.old is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.old


def test_merge_json_creates_file():
    with _Home() as home:
        p = os.path.join(home, ".cursor", "mcp.json")
        res = _merge_mcp_json(p, "mcpServers", _ENTRY)
        assert res["changed"] is True, res
        cfg = json.load(open(p))
        assert cfg["mcpServers"]["omnirecon"] == _ENTRY, cfg


def test_merge_json_idempotent():
    with _Home() as home:
        p = os.path.join(home, "mcp.json")
        _merge_mcp_json(p, "mcpServers", _ENTRY)
        res = _merge_mcp_json(p, "mcpServers", _ENTRY)
        assert res["changed"] is False, res
        assert res["note"] == "already configured", res


def test_merge_json_preserves_existing_servers():
    with _Home() as home:
        p = os.path.join(home, "mcp.json")
        other = {"command": "other", "args": []}
        with open(p, "w") as fh:
            json.dump({"mcpServers": {"other": other}}, fh)
        _merge_mcp_json(p, "mcpServers", _ENTRY)
        cfg = json.load(open(p))
        assert cfg["mcpServers"]["other"] == other, cfg
        assert cfg["mcpServers"]["omnirecon"] == _ENTRY, cfg


def test_merge_json_backs_up_invalid_file():
    with _Home() as home:
        p = os.path.join(home, "mcp.json")
        with open(p, "w") as fh:
            fh.write("{not valid json!!!")
        res = _merge_mcp_json(p, "mcpServers", _ENTRY)
        assert res["changed"] is True, res
        assert os.path.isfile(p + ".omnirecon.bak"), res
        assert open(p + ".omnirecon.bak").read() == "{not valid json!!!"
        cfg = json.load(open(p))
        assert cfg["mcpServers"]["omnirecon"] == _ENTRY


def test_merge_json_dry_run_writes_nothing():
    with _Home() as home:
        p = os.path.join(home, "mcp.json")
        res = _merge_mcp_json(p, "mcpServers", _ENTRY, dry_run=True)
        assert res["changed"] is True, res
        assert not os.path.exists(p), "dry-run must not write"


def test_codex_toml_append_idempotent():
    with _Home() as home:
        p = os.path.join(home, ".codex", "config.toml")
        r1 = _ensure_codex_toml(p, "/fake/python", "/fake/server.py")
        assert r1["changed"] is True, r1
        content = open(p).read()
        assert "[mcp_servers.omnirecon]" in content, content
        r2 = _ensure_codex_toml(p, "/fake/python", "/fake/server.py")
        assert r2["changed"] is False, r2
        assert open(p).read().count("[mcp_servers.omnirecon]") == 1


def test_detect_clients_finds_codex():
    with _Home() as home:
        os.makedirs(os.path.join(home, ".codex"))
        found = _detect_clients()
        assert "codex" in found, found


def test_setup_client_cursor_writes_config():
    with _Home():
        a = SimpleNamespace(client="cursor", project="", dry_run=False)
        res = _setup_client(a)
        assert res.get("ok") is True, res
        p = os.path.expanduser("~/.cursor/mcp.json")
        assert os.path.isfile(p), res
        cfg = json.load(open(p))
        srv = cfg["mcpServers"]["omnirecon"]
        assert srv["args"][0].endswith("omnirecon/server.py"), srv
        assert os.path.isfile(srv["command"]), srv
        # idempotent
        res2 = _setup_client(a)
        assert res2["clients"][0]["changed"] is False, res2


def test_setup_client_dry_run_writes_nothing():
    with _Home():
        a = SimpleNamespace(client="cursor", project="", dry_run=True)
        res = _setup_client(a)
        assert res.get("ok") is True, res
        assert res.get("dry_run") is True, res
        assert not os.path.exists(os.path.expanduser("~/.cursor/mcp.json"))


def test_setup_client_claude_code_project_json():
    with _Home() as home:
        proj = os.path.join(home, "myproj")
        os.makedirs(proj)
        old = os.getcwd()
        os.chdir(proj)
        try:
            a = SimpleNamespace(client="claude-code", project="",
                                dry_run=False)
            res = _setup_client(a)
        finally:
            os.chdir(old)
        assert res.get("ok") is True, res
        p = os.path.join(proj, ".mcp.json")
        assert os.path.isfile(p), res
        cfg = json.load(open(p))
        assert "omnirecon" in cfg["mcpServers"], cfg


def test_setup_client_auto_no_clients_is_error():
    with _Home():
        a = SimpleNamespace(client="auto", project="", dry_run=False)
        res = _setup_client(a)
        # In this sandbox HOME is empty of clients; PATH may still have none.
        # Either a clean error or a configured client is acceptable — but
        # never a traceback-shaped dict.
        assert isinstance(res, dict), res
        assert ("error" in res) or res.get("ok") is True, res


def main():
    fns = sorted(n for n in globals()
                 if n.startswith("test_") and callable(globals()[n]))
    passed = failed = 0
    for name in fns:
        try:
            globals()[name]()
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"ok {name}")
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
