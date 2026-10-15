"""Tests for omnirecon.js_hook (Wave 2: JS signature tracing).

Self-contained runner (no pytest in the venv): each test_* function is run
by main() against one shared OwnedBrowser for the browser test. Run with:
    ~/workspace/venvs/recon/bin/python ~/workspace/omnirecon/tests/test_js_hook.py
"""
import functools
import http.server
import os
import sys
import tempfile
import threading
import traceback

# Sandbox quirk: the default no_proxy (bracketed IPv6) breaks httpx URL parsing.
os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

from omnirecon import js_hook as JH  # noqa: E402
from omnirecon.browser_engine import OwnedBrowser  # noqa: E402

_HEX64 = "a1b2c3d4" * 8

_BROWSER = None


def _browser():
    """Shared OwnedBrowser, launched lazily.

    Works both under pytest (which never calls main()) and in the
    self-contained runner below.
    """
    global _BROWSER
    if _BROWSER is None:
        import atexit
        use_relay = os.environ.get("HTTPS_PROXY", "").startswith(
            "http://127.0.0.1:8899")
        b = OwnedBrowser()
        b.launch(headless=True, ignore_https_errors=use_relay)
        _BROWSER = b
        atexit.register(_BROWSER.shutdown)
    return _BROWSER


def _synthetic_data():
    return {
        "crypto": [{
            "op": "sign", "alg": "HMAC/SHA-256",
            "input_preview": "amount=100&currency=USD&ts=1699999999",
            "input_len": 38,
            "stack": ("at computeSig (http://127.0.0.1:9/app.js:42:10) <- "
                      "at HTMLButtonElement.onclick (http://127.0.0.1:9/app.js:10:3)"),
            "t": 1000,
        }],
        "reqs": [{
            "kind": "fetch", "method": "POST",
            "url": f"http://127.0.0.1:9/api/pay?amount=100&currency=USD&sign={_HEX64}",
            "body_preview": "",
            "stack": "at pay (http://127.0.0.1:9/app.js:50:5)",
            "t": 1200,
        }],
    }


def test_analyze_correlates_hmac():
    out = JH.analyze(_synthetic_data(), page_url="http://127.0.0.1:9/")
    sigs = out["signatures"]
    assert len(sigs) == 1, out
    s = sigs[0]
    assert s["param"] == "sign", s
    assert s["algorithm"] == "HMAC-SHA-256", s
    assert "amount" in s["input_fields"], s
    assert "currency" in s["input_fields"], s
    assert s["computed_in"] == "http://127.0.0.1:9/app.js:42", s
    assert s["classification"] == "SOURCE_VERIFIED", s
    assert s["confidence"] >= 0.75, s
    assert s["endpoint"] == "/api/pay", s


def test_analyze_no_crypto_is_unknown():
    data = {"crypto": [], "reqs": [{
        "kind": "xhr", "method": "GET",
        "url": f"http://127.0.0.1:9/api/data?sig={_HEX64}",
        "body_preview": "", "stack": "", "t": 500,
    }]}
    out = JH.analyze(data)
    assert out["signatures"] == [], out
    assert out["unknowns"], "missing-crypto case must be an unknown"
    assert "sig" in out["unknowns"][0], out["unknowns"]


def test_analyze_redacts_signature_values():
    out = JH.analyze(_synthetic_data())
    s = out["signatures"][0]
    assert s["value_preview"] == _HEX64[:8] + "..." + _HEX64[-4:], s
    assert _HEX64 not in s["value_preview"], "full signature value leaked"


def test_analyze_cryptojs_label():
    data = {"crypto": [{
        "op": "cryptojs:HmacSHA256", "alg": "HmacSHA256",
        "input_preview": "order=7&total=42", "input_len": 15,
        "stack": "at sign (https://shop.test/checkout.js:5:1)", "t": 100,
    }], "reqs": [{
        "kind": "fetch", "method": "GET",
        "url": f"https://shop.test/api/order?order=7&checksum={_HEX64}",
        "body_preview": "", "stack": "", "t": 300,
    }]}
    out = JH.analyze(data)
    assert len(out["signatures"]) == 1, out
    assert out["signatures"][0]["algorithm"] == "HMAC-SHA-256 (CryptoJS)"


def test_analyze_no_data():
    out = JH.analyze(None)
    assert out["signatures"] == [] and out["unknowns"]


def test_analyze_hmac_unknown_hash_fallback():
    # String-form subtle.sign("HMAC", ...) with no key label: no "HMAC-?".
    assert JH._algorithm_label("sign", "HMAC") == "HMAC (hash unknown)"
    assert JH._algorithm_label("sign", "HMAC/SHA-256") == "HMAC-SHA-256"


PAGE = """<html><head><title>Sig Test</title></head><body>
<script>
async function checkout(){
  var msg = "amount=100&currency=USD&ts=1699999999";
  var key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode("k3y-secret"),
    {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  var buf = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(msg));
  var hex = Array.from(new Uint8Array(buf)).map(function(b){
    return b.toString(16).padStart(2, "0");
  }).join("");
  await fetch("/api/checkout?amount=100&currency=USD&ts=1699999999&sign=" + hex,
              {method: "POST"}).catch(function(){});
}
window.addEventListener("load", function(){ setTimeout(checkout, 400); });
</script></body></html>"""


def test_browser_end_to_end():
    # The real proof: hooks arm before page JS, capture the WebCrypto HMAC
    # call, and correlate it with the fetch carrying ?sign=.
    root = tempfile.mkdtemp(prefix="omnirecon_sig_srv_")
    with open(os.path.join(root, "index.html"), "w") as fh:
        fh.write(PAGE)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=root)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = JH.trace_signatures(_browser(), base + "/", wait_ms=6000)
    finally:
        srv.shutdown()
    sigs = out["signatures"]
    assert sigs, f"no signatures traced: {out}"
    s = next((x for x in sigs if x["param"] == "sign"), None)
    assert s is not None, sigs
    assert "HMAC" in s["algorithm"], s
    assert "amount" in s["input_fields"], s
    assert "currency" in s["input_fields"], s
    assert s["computed_in"].startswith(base), s
    assert s["classification"] == "SOURCE_VERIFIED", s
    assert out["stats"]["crypto_calls_captured"] >= 1, out["stats"]


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
