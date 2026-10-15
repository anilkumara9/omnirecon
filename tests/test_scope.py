"""Tests for the analyst-dossier wave (v2.3.0): scope ledger, feature-flag
mining, self-imposed rate limiting.

Self-contained runner (no pytest in the venv): each test_* function is run
by main(). Also pytest-collectable. Run with:
    ~/workspace/venvs/recon/bin/python ~/workspace/omnirecon/tests/test_scope.py
"""
import functools
import http.server
import os
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

from omnirecon import scope as SC  # noqa: E402
from omnirecon.recon_primitives import (  # noqa: E402
    _POLITE_LIMITER,
    _client,
    mine_feature_flags,
)
from omnirecon.security import RateLimiter  # noqa: E402


# --- scope ledger (pure logic) ---------------------------------------------

def test_build_scope_local_is_owned():
    s = SC.build_scope("http://127.0.0.1:8901/", "third-party")
    assert s["ownership"] == "owned", s
    assert "local source code" in " ".join(s["in_scope"]).lower(), s


def test_build_scope_third_party_default():
    s = SC.build_scope("https://example.com/", "third-party",
                       tos_result={"status": "not-found", "found": None,
                                   "checked": ["/terms"]},
                       robots_result={"present": True})
    assert s["ownership"] == "third-party", s
    assert s["tos"]["status"] == "not-found", s
    assert any("auth bypass" in o for o in s["out_of_scope"]), s
    assert "1 request/second" in s["rate_limit"], s


def test_build_scope_bad_ownership_falls_back():
    s = SC.build_scope("https://example.com/", "nonsense")
    assert s["ownership"] == "third-party", s


def test_scope_summary_mentions_key_facts():
    s = SC.build_scope("https://example.com/", "third-party",
                       tos_result={"status": "found", "found": "/terms",
                                   "checked": ["/terms"]},
                       robots_result={"present": False})
    txt = SC.scope_summary(s)
    assert "third-party" in txt and "/terms" not in txt, txt
    assert "ToS: found" in txt, txt


def test_check_tos_with_fake_getter():
    class R:
        status_code = 200
        content = b"x" * 600

    def fake_get(url, timeout):
        assert url.endswith("/terms"), url
        return R()

    res = SC.check_tos("https://example.com", get=fake_get)
    assert res["status"] == "found" and res["found"] == "/terms", res


def test_check_tos_not_found():
    class R:
        status_code = 404
        content = b"nope"

    res = SC.check_tos("https://example.com",
                       get=lambda url, timeout: R())
    assert res["status"] == "not-found" and res["found"] is None, res


# --- feature-flag mining ----------------------------------------------------

_FLAG_JS = """
import { useFeatureFlag } from 'launchdarkly-react-client-sdk';
const showNew = useFeatureFlag("new-checkout-flag");
const v2 = isFeatureEnabled('search-v2-experiment');
var x = window["old-toggle"];
fetch("/api/flags");
"""

def test_mine_feature_flags():
    res = mine_feature_flags(_FLAG_JS)
    assert "launchdarkly" in res["sdks"], res
    assert "new-checkout-flag" in res["flags"], res
    assert "search-v2-experiment" in res["flags"], res


def test_mine_feature_flags_clean_js():
    res = mine_feature_flags("function add(a,b){return a+b;} fetch('/api/x');")
    assert res["sdks"] == [] and res["flags"] == [], res


# --- rate limiting ----------------------------------------------------------

def test_polite_limiter_is_1rps():
    assert _POLITE_LIMITER.requests_per_second == 1.0


def test_rate_limiter_enforces_interval():
    rl = RateLimiter(requests_per_second=10.0)  # 100ms interval
    t0 = time.monotonic()
    rl.wait()
    rl.wait()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.09, f"limiter did not gate: {elapsed:.3f}s"


def test_client_has_polite_hook():
    c = _client()
    try:
        hooks = c._event_hooks.get("request", [])
        assert len(hooks) == 1, hooks
    finally:
        c.close()


# --- recon_scope tool end-to-end --------------------------------------------

def test_recon_scope_tool():
    root = tempfile.mkdtemp(prefix="omnirecon_scope_srv_")
    with open(os.path.join(root, "index.html"), "w") as fh:
        fh.write("<html><body>hi</body></html>")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=root)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        from omnirecon import server as S
        st = S.recon_start(base, "fast")
        assert "session_id" in st, st
        out = S.recon_scope(st["session_id"])
        assert "scope" in out, out
        assert out["scope"]["ownership"] == "owned", out["scope"]
        assert out["scope"]["tos"]["status"] in ("found", "not-found"), out
        assert out.get("unknowns") is not None, out
        assert out.get("limitations"), out
        ev = S.recon_get_evidence(st["session_id"], type="scope")
        assert len(ev.get("findings", [])) == 1, ev
        assert ev["findings"][0]["classification"] == "OBSERVED", ev
    finally:
        srv.shutdown()


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
