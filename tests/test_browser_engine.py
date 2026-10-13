"""Real tests for omnirecon.browser_engine (Lane A).

Self-contained runner (no pytest in the venv): each test_* function runs
against one shared OwnedBrowser; failures raise AssertionError and are
reported. Run with:
    ~/workspace/venvs/recon/bin/python ~/workspace/omnirecon/tests/test_browser_engine.py
"""
import json
import os
import sys
import tempfile
import traceback
import urllib.parse

# Sandbox quirk: the default no_proxy (bracketed IPv6) breaks httpx URL parsing.
os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

from omnirecon.browser_engine import (  # noqa: E402
    AsyncOwnedBrowser,
    OwnedBrowser,
    ReconError,
    _redact,
)

HTML = """<html><head><title>Recon Test</title></head><body>
<h1>Hello World</h1>
<a href="/about">About us</a>
<button id="changer" onclick="document.getElementById('out').textContent='changed'">Click me</button>
<div id="out">before</div>
<button id="dead">Does nothing</button>
<button id="buy">Buy now</button>
<form action="/search" method="get" name="sform">
  <input name="q" placeholder="Search terms" required>
  <input type="password" name="pw">
  <select name="s"><option value="a">A</option><option value="b">B</option></select>
  <button type="submit">Search</button>
</form>
<script>throw new Error("boom-console-test");</script>
</body></html>"""
DATA_URL = "data:text/html," + urllib.parse.quote(HTML)

NET_HTML = ("<html><body><script>"
            "fetch('https://example.com/?api_key=TOPSECRET123&foo=1')"
            ".catch(()=>{});</script></body></html>")
NET_URL = "data:text/html," + urllib.parse.quote(NET_HTML)

B = OwnedBrowser()
ART = tempfile.mkdtemp(prefix="omnirecon_test_artifacts_")
RESULTS = []


def check(name, fn):
    try:
        fn()
    except Exception:
        RESULTS.append((name, False, traceback.format_exc(limit=3)))
        print(f"FAIL {name}")
    else:
        RESULTS.append((name, True, ""))
        print(f"PASS {name}")


def page_id_for(url):
    return B.goto(url)["page_id"]


def test_snapshot_controls():
    pid = page_id_for(DATA_URL)
    snap = B.snapshot(pid)
    assert snap["title"] == "Recon Test", snap["title"]
    ctrls = snap["controls"]
    assert len(ctrls) >= 8, f"only {len(ctrls)} controls"
    by_name = {c["name"]: c for c in ctrls}
    assert "Click me" in by_name and by_name["Click me"]["role"] == "button"
    assert "About us" in by_name and by_name["About us"]["role"] == "link"
    assert any(c["tag"] == "select" for c in ctrls), "select missing"
    assert snap["link_count"] >= 1
    assert any(h["text"] == "Hello World" for h in snap["headings"])
    # refs usable by interact
    assert by_name["Click me"]["ref"].startswith("e")
    assert snap["forms"], "no forms extracted"
    form = snap["forms"][0]
    assert form["action"] == "/search" and form["method"] == "GET"
    names = {i["name"] for i in form["inputs"]}
    assert {"q", "pw", "s"} <= names, names
    assert "Hello World" in snap["text_sample"]


def test_screenshot_artifact():
    pid = page_id_for(DATA_URL)
    path = B.screenshot(pid, "desktop", ART)
    assert os.path.isfile(path), path
    base = os.path.basename(path)
    assert base.endswith(".png") and len(base) == 68, base  # sha256 hex + .png
    with open(path, "rb") as fh:
        assert fh.read(8) == b"\x89PNG\r\n\x1a\n", "not a PNG"
    # content-addressed: same page -> same filename
    assert B.screenshot(pid, "desktop", ART) == path
    # mobile viewport works too
    m = B.screenshot(pid, "mobile", ART)
    assert os.path.isfile(m) and m != path
    try:
        B.screenshot(pid, "widescreen", ART)
    except ReconError as e:
        assert e.code == "bad_viewport"
    else:
        raise AssertionError("bad viewport accepted")


def test_redact_unit():
    dirty = {
        "headers": {"Authorization": "Bearer abc123", "Cookie": "sess=xyz",
                    "Content-Type": "application/json"},
        "url": "https://x.test/api?api_key=SUPERSECRET&foo=1",
        "nested": [{"password": "hunter2", "user": "bob"}],
    }
    clean = _redact(dirty)
    blob = json.dumps(clean)
    for secret in ("abc123", "sess=xyz", "SUPERSECRET", "hunter2"):
        assert secret not in blob, f"leaked: {secret}"
    assert "foo=1" in blob, "non-sensitive param was clobbered"
    assert "application/json" in blob
    assert "[REDACTED]" in blob


def test_network_capture_redacted():
    pid = page_id_for(NET_URL)
    cap = B.network_capture(pid, duration_ms=5000)
    assert isinstance(cap, dict) and cap.get("requests"), "no requests captured"
    entries = cap["requests"]
    blob = json.dumps(entries)
    assert "TOPSECRET123" not in blob, f"api_key leaked: {blob[:400]}"
    assert "foo=1" in blob, "benign param lost"
    ex = [e for e in entries if "example.com" in e["url"]]
    assert ex, "fetch to example.com not captured"
    assert ex[0]["method"] == "GET"
    assert {"method", "url", "status", "type", "ms",
            "initiator"} <= set(ex[0]), set(ex[0])


def test_network_initiator_stack():
    # Proves the CDP "magic": each API call links to the exact script URL,
    # line and function that fired it. Served over loopback (proxy bypass).
    import functools
    import http.server
    import threading
    root = tempfile.mkdtemp(prefix="omnirecon_init_srv_")
    with open(os.path.join(root, "index.html"), "w") as fh:
        fh.write("<html><body><script>\nfunction loadData() {\n"
                 "  fetch('/api/widgets?page=2').then(r=>r.text()).catch(()=>{});\n"
                 "}\nloadData();\n</script></body></html>")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=root)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        pid = page_id_for(f"http://127.0.0.1:{port}/")
        cap = B.network_capture(pid, duration_ms=5000)
    finally:
        srv.shutdown()
    entries = cap["requests"]
    api = [e for e in entries if "/api/widgets" in e["url"]]
    assert api, "fetch to /api/widgets not captured"
    init = api[0]["initiator"]
    assert init is not None, "no initiator stack captured for the fetch"
    assert init["script_url"] == f"http://127.0.0.1:{port}/", init
    assert init["function"] == "loadData", init
    assert isinstance(init["line"], int) and init["line"] >= 0, init
    assert init["initiator_type"] == "script", init


def test_interact_refusals():
    pid = page_id_for(DATA_URL)
    B.snapshot(pid)
    # 1. unsafe kind refused
    try:
        B.interact(pid, {"kind": "extract_value", "selector": "input"})
    except ReconError as e:
        assert e.code == "invalid_action", e.code
    else:
        raise AssertionError("extract_value not refused")
    # 2. password exfiltration attempt refused (no value-extraction kinds exist)
    try:
        B.interact(pid, {"kind": "get_text", "selector": "input[type=password]"})
    except ReconError as e:
        assert e.code == "invalid_action", e.code
    else:
        raise AssertionError("password read not refused")
    # 3. destructive click refused
    snap = B.snapshot(pid)
    buy_ref = next(c["ref"] for c in snap["controls"] if c["name"] == "Buy now")
    try:
        B.interact(pid, {"kind": "click", "ref": buy_ref})
    except ReconError as e:
        assert e.code == "refused", e.code
    else:
        raise AssertionError("destructive click not refused")
    # 4. unknown ref rejected
    try:
        B.interact(pid, {"kind": "click", "ref": "e9999"})
    except ReconError as e:
        assert e.code == "bad_ref", e.code
    else:
        raise AssertionError("bad ref accepted")


def test_interact_observed_true():
    pid = page_id_for(DATA_URL)
    snap = B.snapshot(pid)
    ref = next(c["ref"] for c in snap["controls"] if c["name"] == "Click me")
    res = B.interact(pid, {"kind": "click", "ref": ref})
    assert res["observed"] is True, res
    assert res["dom_changed"] is True, res
    assert res["url_before"] == res["url_after"]
    assert "no observable change" not in res["note"]


def test_interact_observed_false():
    pid = page_id_for(DATA_URL)
    snap = B.snapshot(pid)
    ref = next(c["ref"] for c in snap["controls"] if c["name"] == "Does nothing")
    res = B.interact(pid, {"kind": "click", "ref": ref})
    assert res["observed"] is False, res
    assert "visible but did not" in res["note"], res["note"]


def test_interact_fill_password_no_leak():
    pid = page_id_for(DATA_URL)
    B.snapshot(pid)
    res = B.interact(pid, {"kind": "fill", "selector": "input[name=pw]",
                           "value": "hunter2-hunter2"})
    assert "hunter2" not in json.dumps(res), "password value leaked in result"
    assert "never captured" in res["note"], res["note"]


def test_console_errors():
    pid = page_id_for(DATA_URL)
    errs = B.console_errors(pid)
    assert any("boom-console-test" in e for e in errs), errs


def _local_http_server():
    """Hermetic crawl target: 3 local pages, no external network needed."""
    import http.server
    import threading

    pages = {
        "/": ('<html><head><title>Home</title></head><body><h1>Home</h1>'
              '<a href="/about">About</a><a href="/contact">Contact</a>'
              '<button>Click</button></body></html>'),
        "/about": ('<html><head><title>About</title></head><body><h1>About</h1>'
                   '<a href="/">Home</a></body></html>'),
        "/contact": ('<html><head><title>Contact</title></head><body><h1>Contact</h1>'
                     '<form action="/send"><input name="email">'
                     '<button type="submit">Send</button></form></body></html>'),
    }

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path.split("?")[0], "<html><body>404</body></html>")
            code = 200 if self.path.split("?")[0] in pages else 404
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_crawl_example_bounded():
    srv = _local_http_server()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        sess = tempfile.mkdtemp(prefix="omnirecon_test_session_")
        res = B.crawl(base, max_pages=5, max_depth=1, session_dir=sess)
        assert res["pages_crawled"] >= 1, res
        assert res["pages_crawled"] <= 5, res
        assert isinstance(res["routes"], list) and res["routes"]
        assert res["routes"][0]["control_count"] >= 0
        assert "api_endpoints" in res
        assert res["start_page_screenshot"] and os.path.isfile(
            res["start_page_screenshot"])
    finally:
        srv.shutdown()


def test_async_engine_in_running_loop():
    # Simulates FastMCP: the tool handler runs INSIDE a running asyncio loop,
    # where Playwright's sync API raises. The async engine must work there.
    import asyncio

    use_relay = os.environ.get("HTTPS_PROXY", "").startswith(
        "http://127.0.0.1:8899")

    async def main():
        b = AsyncOwnedBrowser()
        await b.launch(headless=True, ignore_https_errors=use_relay)
        try:
            r = await b.goto(DATA_URL)
            assert r["title"] == "Recon Test", r
            snap = await b.snapshot(r["page_id"])
            assert snap["control_count"] >= 8, snap["control_count"]
            ref = next(c["ref"] for c in snap["controls"]
                       if c["name"] == "Click me")
            res = await b.interact(r["page_id"], {"kind": "click", "ref": ref})
            assert res["observed"] is True, res
            errs = b.console_errors(r["page_id"])
            assert any("boom-console-test" in e for e in errs), errs
        finally:
            await b.close()

    asyncio.run(main())


def test_sync_wrapper_from_async_context():
    # The sync facade must also be usable when the *caller* sits inside a
    # running loop (e.g. a sync tool invoked from async code): the blocking
    # call goes through an executor, the engine runs on its own loop thread.
    import asyncio

    use_relay = os.environ.get("HTTPS_PROXY", "").startswith(
        "http://127.0.0.1:8899")

    async def main():
        loop = asyncio.get_running_loop()
        b2 = OwnedBrowser()
        try:
            await loop.run_in_executor(
                None,
                lambda: b2.launch(headless=True, ignore_https_errors=use_relay))
            r = await loop.run_in_executor(None, lambda: b2.goto(DATA_URL))
            assert r["title"] == "Recon Test", r
            snap = await loop.run_in_executor(
                None, lambda: b2.snapshot(r["page_id"]))
            assert snap["control_count"] >= 8, snap["control_count"]
        finally:
            await loop.run_in_executor(None, b2.shutdown)

    asyncio.run(main())


def setup_module(module):
    """pytest entry point: launch the shared browser (mirrors main())."""
    use_relay = os.environ.get("HTTPS_PROXY", "").startswith("http://127.0.0.1:8899")
    B.launch(headless=True, ignore_https_errors=use_relay)


def teardown_module(module):
    B.shutdown()


def main():
    global B
    # Sandbox runs a TLS-intercepting egress proxy: the relay on 127.0.0.1:8899
    # (started separately) forwards with preemptive auth; cert validation is
    # disabled for the test browser only when the relay is in use.
    use_relay = os.environ.get("HTTPS_PROXY", "").startswith("http://127.0.0.1:8899")
    B.launch(headless=True, ignore_https_errors=use_relay)
    try:
        for name, fn in sorted(
                [(k, v) for k, v in globals().items() if k.startswith("test_")]):
            check(name, fn)
    finally:
        B.shutdown()
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} tests passed")
    for n, ok, tb in RESULTS:
        if not ok:
            print(f"\n--- {n} ---\n{tb}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
