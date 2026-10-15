"""Tests for omnirecon.ui_intel (designer-grade UI reverse engineering).

Uses a data: URL so no network is needed; requires a local Chromium
(headless shell). Follows the test_browser_engine.py self-contained style.
"""
import json
import os
import sys
import traceback
import urllib.parse

os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

sys.path.insert(0, os.path.expanduser("~/workspace/omnirecon"))

from omnirecon.browser_engine import AsyncOwnedBrowser  # noqa: E402
from omnirecon import ui_intel  # noqa: E402

HTML = """<html><head><style>
body { font-family: Inter, sans-serif; background: #0f172a; color: #e2e8f0; }
.btn-p { background: #3b82f6; color: white; border-radius: 8px; padding: 12px 24px; font-weight: 600; }
.btn-s { background: transparent; color: #3b82f6; border-radius: 8px; padding: 12px 24px; }
</style></head><body>
<header><nav><a href="/">Home</a></nav></header>
<main><section><h1>Hi</h1>
<button class="btn-p">One</button><button class="btn-p">Two</button>
<button class="btn-s">Three</button>
</section></main><footer><p>Foot</p></footer>
</body></html>"""

DATA_URL = "data:text/html," + urllib.parse.quote(HTML)

BROWSER = None
_LOOP = None


def _loop():
    """Module-owned event loop (isolated from other test modules)."""
    global _LOOP
    import asyncio
    if _LOOP is None:
        _LOOP = asyncio.new_event_loop()
        asyncio.set_event_loop(_LOOP)
    return _LOOP


def setup_module(module):
    global BROWSER
    BROWSER = AsyncOwnedBrowser()
    _loop().run_until_complete(BROWSER.launch(headless=True))


def teardown_module(module):
    global _LOOP
    if BROWSER:
        _loop().run_until_complete(BROWSER.close())
    if _LOOP is not None:
        _LOOP.close()
        _LOOP = None


def _run(coro):
    return _loop().run_until_complete(coro)


def test_ui_tokens_extracted():
    page = _run(BROWSER.goto(DATA_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-pytest", DATA_URL))
    assert result["elements_sampled"] > 5, result
    toks = result["tokens"]
    assert "Inter" in toks["fonts"], toks["fonts"]
    assert "8px" in toks["radii"], toks["radii"]
    # no bootstrap false positive on plain classes
    assert result["frameworks"] == [], result["frameworks"]


def test_component_variants_distinguished():
    page = _run(BROWSER.goto(DATA_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-pytest", DATA_URL))
    sigs = {(c["tag"], c["bg"], c["count"]) for c in result["components"]}
    # two primary buttons share one signature; secondary is separate
    primaries = [c for c in result["components"]
                 if c["tag"] == "button" and "59, 130, 246" in c["bg"]]
    assert primaries and primaries[0]["count"] == 2, result["components"]
    secondaries = [c for c in result["components"]
                   if c["tag"] == "button" and c["bg"] == "rgba(0, 0, 0, 0)"]
    assert secondaries and secondaries[0]["count"] == 1, result["components"]


MOTION_HTML = """<html><head><style>
@keyframes pulse { from { opacity: 1; } to { opacity: 0.5; } }
.box { width: 100px; height: 100px; background: red;
       transition: opacity 0.3s ease-in-out;
       animation: pulse 2s ease-in-out infinite; }
</style></head><body><div class="box">x</div></body></html>"""

MOTION_URL = "data:text/html," + urllib.parse.quote(MOTION_HTML)


def test_motion_catalog_captures_transitions_and_animations():
    page = _run(BROWSER.goto(MOTION_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-motion", MOTION_URL))
    motion = result.get("motion")
    assert motion, result.keys()
    trans = motion["transitions"]
    assert any(t["property"] == "opacity" and "0.3s" in t["duration"]
               for t in trans), trans
    anims = motion["animations"]
    assert any(a["name"] == "pulse" and "2s" in a["duration"]
               for a in anims), anims
    assert any("ease-in-out" in (t.get("easing") or "")
               for t in trans), trans


def test_dark_mode_probe_reports():
    page = _run(BROWSER.goto(DATA_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-dark", DATA_URL))
    dm = result.get("dark_mode")
    assert dm is not None, result.keys()
    assert isinstance(dm["supported"], bool), dm


def test_vitals_snapshot_reports():
    page = _run(BROWSER.goto(DATA_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-vitals", DATA_URL))
    vitals = result.get("vitals")
    assert vitals, result.keys()
    assert vitals["resources"] >= 0, vitals
    assert vitals["js_kb"] >= 0, vitals


def test_sections_and_ledger():
    page = _run(BROWSER.goto(DATA_URL))
    result = _run(ui_intel.analyze_ui(
        BROWSER, page["page_id"], "test-ui-pytest2", DATA_URL))
    landmarks = {s["landmark"] for s in result["sections"]}
    assert {"header", "nav", "main", "footer"} <= landmarks, landmarks
    lp = os.path.expanduser(
        "~/workspace/omnirecon/sessions/test-ui-pytest2/evidence.jsonl")
    findings = [json.loads(l) for l in open(lp)]
    types = {f["type"] for f in findings}
    assert "tech" in types and "component" in types, types
    token_f = [f for f in findings if f["type"] == "tech"
               and f["title"].startswith("Design tokens")][0]
    assert token_f["classification"] == "OBSERVED", token_f
    assert token_f["confidence"] >= 0.85, token_f


if __name__ == "__main__":
    setup()
    passed, failed = 0, 0
    for name, fn in sorted(
            [(k, v) for k, v in globals().items() if k.startswith("test_")]):
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
            failed += 1
    teardown()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
