"""Owned-browser intelligence engine (Lane A).

Drives a real Chromium via Playwright's **async** API: navigation, compact
DOM/accessibility snapshots, content-addressed screenshots, redacted network
capture with CDP initiator stacks, console errors, safe interaction probing,
and route-discovery crawls.

Two interfaces are exposed:

- ``AsyncOwnedBrowser`` — native async/await. Use this from async contexts
  such as FastMCP tool handlers (which run inside a running event loop, where
  Playwright's sync API raises).
- ``OwnedBrowser`` — sync facade. Every call is dispatched to a dedicated
  worker thread running its own event loop, so it works from plain scripts
  and from threads spawned inside a running loop. Never call its blocking
  methods directly on a running loop thread (use an executor instead).

Every public method returns plain JSON-serializable data or raises
``ReconError`` (``.code``/``.hint``, never tracebacks). All captured network
data passes through ``omnirecon.security.redact`` (with a contract-compatible
local fallback until Lane B's module lands). Page content is untrusted data:
nothing is ever eval'd or exec'd.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from typing import Any

VIEWPORTS = {
    "desktop": {"width": 1440, "height": 900},
    "tablet": {"width": 834, "height": 1112},
    "mobile": {"width": 390, "height": 844},
}

SAFE_ACTION_KINDS = {"click", "fill", "select", "press", "scroll"}

# Clicking anything matching these is refused: purchases, payments, deletions.
_DESTRUCTIVE_RE = re.compile(
    r"buy\s*now|place\s*order|complete\s*(purchase|order)|check\s*out|"
    r"pay\s*(now|ment)?|make\s*payment|subscribe|unsubscribe|"
    r"\bdelete\b|destroy|remove\s*account|cancel\s*(account|subscription)|"
    r"withdraw|transfer\s*(funds|money)",
    re.IGNORECASE,
)

# Keys treated as secrets by the local redact fallback (mirrors security.py §6).
_SENSITIVE_KEY_RE = re.compile(
    r"authorization|cookie|set-cookie|x-api-key|apikey|api_key|secret|"
    r"password|passwd|pwd|auth|sessionid|session_id|bearer|token|"
    r"access_key|client_secret",
    re.IGNORECASE,
)


# Unified with omnirecon.security.ReconError (message, code, hint).
# All raise sites below were mechanically converted from the old
# (code, message) ordering on 2026-10-13.
from omnirecon.security import ReconError


# ---------------------------------------------------------------------------
# chromium executable verification + self-reinstall (curl, not node downloader)
# ---------------------------------------------------------------------------

_CFT_BASE = "https://cdn.playwright.dev/builds/cft/153.0.8010.12/linux64"
# (cache dirname, zip name, inner dir after unzip, executable relative path)
_BROWSER_WANTS = [
    ("chromium_headless_shell-1243",
     "chrome-headless-shell-linux64.zip",
     "chrome-headless-shell-linux64",
     "chrome-headless-shell-linux64/chrome-headless-shell"),
    ("chromium-1243",
     "chrome-linux64.zip",
     "chrome-linux64",
     "chrome-linux64/chrome"),
]


def _playwright_dir() -> str:
    return os.path.expanduser("~/.cache/ms-playwright")


_BODY_CAP_BYTES = 200 * 1024
_JSON_CT = ("application/json", "application/hal+json", "application/vnd.api+json")


def infer_shape(obj: object, _depth: int = 0, _max_depth: int = 4) -> dict:
    """Infer a values-free JSON Schema-ish shape: key names + types only.

    Never retains example values — safe for the evidence ledger.
    """
    if _depth > _max_depth:
        return {"type": "any"}
    if obj is None:
        return {"type": "null"}
    if isinstance(obj, bool):
        return {"type": "boolean"}
    if isinstance(obj, int):
        return {"type": "integer"}
    if isinstance(obj, float):
        return {"type": "number"}
    if isinstance(obj, str):
        return {"type": "string"}
    if isinstance(obj, list):
        item_shapes: list[dict] = []
        seen: set[str] = set()
        for item in obj[:5]:
            s = infer_shape(item, _depth + 1, _max_depth)
            key = json.dumps(s, sort_keys=True)
            if key not in seen:
                seen.add(key)
                item_shapes.append(s)
        return {"type": "array", "items": item_shapes[:3],
                "count": len(obj)}
    if isinstance(obj, dict):
        props = {}
        for k in list(obj.keys())[:60]:
            props[str(k)[:80]] = infer_shape(obj[k], _depth + 1, _max_depth)
        return {"type": "object", "properties": props,
                "keys": len(obj)}
    return {"type": type(obj).__name__}


def _looks_json(headers: dict) -> bool:
    ct = ""
    try:
        for k, v in (headers or {}).items():
            if str(k).lower() == "content-type":
                ct = str(v).lower()
                break
    except Exception:
        pass
    return any(t in ct for t in _JSON_CT)


def _chromium_executables() -> list[str]:
    base = _playwright_dir()
    return [os.path.join(base, d, exe) for d, _, _, exe in _BROWSER_WANTS]


def _ensure_chromium() -> None:
    """Verify a Chromium executable exists; if not, download + extract it.

    Uses curl (honors proxy env vars) because the node-based
    `playwright install` downloader stalls in proxied sandboxes. The headless
    shell alone is sufficient; the full build is fetched as backup.
    """
    if any(os.path.isfile(p) for p in _chromium_executables()):
        return
    tmp = tempfile.mkdtemp(prefix="pw_browser_dl_")
    try:
        for dirname, zipname, inner, exe_rel in _BROWSER_WANTS:
            dest = os.path.join(_playwright_dir(), dirname)
            if os.path.isfile(os.path.join(dest, exe_rel)):
                continue
            zpath = os.path.join(tmp, zipname)
            r = subprocess.run(
                ["curl", "-sSL", "--max-time", "1500", "-o", zpath,
                 f"{_CFT_BASE}/{zipname}"],
                capture_output=True, timeout=1560)
            if r.returncode != 0 or not os.path.isfile(zpath):
                raise ReconError(f"could not download {zipname} (curl exit {r.returncode})", "browser_download_failed", "check network/proxy, or run "
                    "`playwright install chromium` manually")
            os.makedirs(dest, exist_ok=True)
            shutil.unpack_archive(zpath, dest)
            # tolerate both inner-dir namings across Playwright versions
            have = os.path.join(dest, inner)
            alt = os.path.join(
                dest, "chrome-linux" if inner == "chrome-linux64"
                else "chrome-linux64")
            if os.path.isdir(have) and not os.path.exists(alt):
                try:
                    os.symlink(have, alt)
                except Exception:
                    pass
            exe = os.path.join(dest, exe_rel)
            if os.path.isfile(exe):
                os.chmod(exe, 0o755)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not any(os.path.isfile(p) for p in _chromium_executables()):
        raise ReconError("Chromium executable still missing after download attempt", "browser_missing", "run `playwright install chromium` manually")


# ---------------------------------------------------------------------------
# redaction — prefers omnirecon.security.redact (Lane B), falls back locally
# ---------------------------------------------------------------------------

def _fallback_redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _SENSITIVE_KEY_RE.search(str(k)):
                out[k] = "[REDACTED]"
            else:
                out[k] = _fallback_redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_fallback_redact(x) for x in obj]
    if isinstance(obj, str):
        def _q(m):
            return m.group(1) + "[REDACTED]"

        s = re.sub(
            r"([?&](?:[^=&]*?(?:"
            r"authorization|cookie|token|api_?key|secret|password|passwd|auth|"
            r"sessionid|session_id|access_key|client_secret"
            r")[^=&]*)=)[^&]*",
            _q,
            obj,
            flags=re.IGNORECASE,
        )
        return s[:4096]
    return obj


def _redact(obj: Any) -> Any:
    """Redact via omnirecon.security.redact when available (Lane B)."""
    try:
        from omnirecon.security import redact  # type: ignore

        return redact(obj)
    except Exception:
        return _fallback_redact(obj)


# ---------------------------------------------------------------------------
# snapshot JavaScript (runs inside the page; untrusted output, never eval'd)
# ---------------------------------------------------------------------------

_SNAPSHOT_JS = r"""
() => {
  const MAX_TEXT = 120;
  const secretInput = (el) => {
    const t = (el.getAttribute('type') || '').toLowerCase();
    return t === 'password' || el.getAttribute('data-secret') !== null
        || /passw|secret|token/i.test(el.getAttribute('name') || '');
  };
  const text = (el) => {
    // NEVER capture typed values from secret-bearing inputs (H1 fix):
    // passwords/secrets must not reach snapshots, findings, or the ledger.
    const val = secretInput(el) ? '' : (el.value || '');
    return ((el.getAttribute('aria-label') || el.alt || val
      || el.placeholder || el.title || (el.innerText || '').trim()
      ).replace(/\s+/g, ' ').slice(0, MAX_TEXT));
  };
  const cssPath = (el) => {
    const parts = [];
    let e = el;
    while (e && e.nodeType === 1 && parts.length < 6) {
      let s = e.tagName.toLowerCase();
      if (e.id) { s += '#' + CSS.escape(e.id); parts.unshift(s); break; }
      const cls = (e.className && typeof e.className === 'string')
        ? e.className.trim().split(/\s+/).slice(0, 2).map(c => '.' + CSS.escape(c)).join('') : '';
      const sib = Array.from(e.parentNode ? e.parentNode.children : [])
        .filter(c => c.tagName === e.tagName);
      const idx = sib.length > 1 ? `:nth-of-type(${sib.indexOf(e) + 1})` : '';
      parts.unshift(s + cls + idx);
      e = e.parentElement;
    }
    return parts.join(' > ');
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden'
        && cs.display !== 'none' && cs.opacity !== '0';
  };
  const ROLE_OF = {A:'link',BUTTON:'button',INPUT:'textbox',SELECT:'combobox',
    TEXTAREA:'textbox',H1:'heading',H2:'heading',H3:'heading',H4:'heading',
    IMG:'img',FORM:'form',NAV:'navigation',TABLE:'table',UL:'list',OL:'list'};
  const controls = [];
  const seen = new Set();
  document.querySelectorAll(
    'a,button,input,select,textarea,[role=button],[role=link],[role=checkbox],'
    + '[role=radio],[role=tab],[role=menuitem],[role=switch],[onclick],summary'
  ).forEach((el, i) => {
    if (seen.has(el) || controls.length >= 400) return;
    seen.add(el);
    const tag = el.tagName;
    let type = (el.getAttribute('type') || '').toLowerCase();
    controls.push({
      ref: 'e' + controls.length,
      role: el.getAttribute('role') || ROLE_OF[tag] || tag.toLowerCase(),
      name: text(el),
      type: type || null,
      tag: tag.toLowerCase(),
      visible: visible(el),
      selector: cssPath(el),
      required: !!el.required,
      disabled: !!el.disabled,
    });
  });
  const forms = [];
  document.querySelectorAll('form').forEach((f) => {
    if (forms.length >= 25) return;
    const inputs = [];
    f.querySelectorAll('input,select,textarea').forEach((el) => {
      if (inputs.length >= 30) return;
      inputs.push({name: el.getAttribute('name'),
                   type: (el.getAttribute('type') || 'text').toLowerCase(),
                   required: !!el.required, placeholder: el.getAttribute('placeholder')});
    });
    forms.push({action: f.getAttribute('action'), method: (f.getAttribute('method') || 'GET').toUpperCase(),
                name: f.getAttribute('name'), inputs});
  });
  const headings = [];
  document.querySelectorAll('h1,h2,h3').forEach((h) => {
    if (headings.length < 20) headings.push({level: h.tagName, text: (h.innerText || '').trim().slice(0, 120)});
  });
  return {
    controls, forms, headings,
    link_count: document.querySelectorAll('a[href]').length,
    image_count: document.querySelectorAll('img').length,
    button_count: document.querySelectorAll('button,[role=button]').length,
    text_sample: (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').slice(0, 600),
  };
}
"""

_DOM_SIG_JS = "() => JSON.stringify({u: location.href, l: (document.body ? document.body.innerHTML.length : 0), c: document.querySelectorAll('a,button,input,select,textarea').length})"


# ---------------------------------------------------------------------------
# AsyncOwnedBrowser — native async engine (use from FastMCP / async contexts)
# ---------------------------------------------------------------------------

class AsyncOwnedBrowser:
    """One owned Chromium instance; pages tracked by integer page_id.

    All methods are coroutines and must run on the same event loop.
    """

    def __init__(self):
        self._pw = None
        self._browser = None
        self._pages: dict[int, dict] = {}
        self._next_id = 1
        self._ignore_https_errors = False
        self._tmp_artifacts = tempfile.mkdtemp(prefix="omnirecon_artifacts_")

    # -- lifecycle ------------------------------------------------------

    async def launch(self, headless: bool = True,
                     ignore_https_errors: bool = False) -> dict:
        """Launch the owned Chromium.

        ignore_https_errors: accept invalid/self-signed certs — needed behind
        TLS-intercepting corporate/sandbox proxies and for authorized test
        environments with self-signed certificates. Default False.
        """
        if self._browser:
            return {"ok": True, "note": "browser already running"}
        self._ignore_https_errors = ignore_https_errors
        _ensure_chromium()  # no-op when present; curl-reinstalls when missing
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise ReconError("playwright is not installed in the venv", "no_playwright", "run: ~/workspace/venvs/recon/bin/pip install playwright") from e
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._try_launch(headless)
        except Exception as e:
            raise ReconError(f"could not launch Chromium: {e}"[:300], "launch_failed", "run: ~/workspace/venvs/recon/bin/playwright install chromium") from e
        return {"ok": True, "headless": headless}

    async def _try_launch(self, headless: bool):
        """Launch with fallbacks: default -> +no-sandbox -> full-chromium headless=new.

        The fallbacks cover containers running as root and installs where only
        the full Chromium build (no headless shell) is present. The proxy (when
        the environment requires one, e.g. this sandbox) is passed at launch
        level so every context inherits it.
        """
        proxy = self._proxy_config()
        attempts = [
            {"headless": headless},
            {"headless": headless, "args": ["--no-sandbox"]},
            {"headless": False,
             "args": ["--headless=new", "--no-sandbox", "--disable-gpu",
                      "--disable-dev-shm-usage"]},
        ]
        last = None
        for kw in attempts:
            try:
                if proxy:
                    kw = {**kw, "proxy": proxy}
                return await self._pw.chromium.launch(**kw)
            except Exception as e:
                last = e
        raise last

    async def close(self) -> dict:
        for pid in list(self._pages):
            try:
                await self._pages[pid]["page"].close()
            except Exception:
                pass
            try:
                ctx = self._pages[pid].get("context")
                if ctx:
                    await ctx.close()
            except Exception:
                pass
        self._pages.clear()
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._pw:
            try:
                await self._pw.stop()
            except Exception:
                pass
            self._pw = None
        return {"ok": True}

    def _require_browser(self):
        if not self._browser:
            raise ReconError("browser not launched", "not_launched", "call launch() first")

    def _get_page_entry(self, page_id: int) -> dict:
        try:
            pid = int(page_id)
        except Exception:
            raise ReconError(f"invalid page_id: {page_id!r}", "bad_page_id")
        entry = self._pages.get(pid)
        if not entry:
            raise ReconError(f"unknown page_id: {pid}", "bad_page_id", "page ids come from goto()")
        return entry

    def _proxy_config(self) -> dict | None:
        """Honor standard proxy env vars (corporate proxies, sandboxes).

        Returns a Playwright proxy dict or None. Credentials are taken from
        the URL userinfo and never logged.
        """
        from urllib.parse import urlparse

        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            val = os.environ.get(var)
            if not val:
                continue
            try:
                u = urlparse(val)
                if not u.hostname:
                    continue
                cfg: dict = {"server": f"{u.scheme or 'http'}://{u.hostname}"
                                       f":{u.port or 8080}"}
                if u.username:
                    cfg["username"] = u.username
                if u.password:
                    cfg["password"] = u.password
                # honor no_proxy-style bypass for loopback
                cfg["bypass"] = "localhost,127.0.0.1"
                return cfg
            except Exception:
                continue
        return None

    async def _new_page(self):
        ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) OmniRecon/1.0 Chrome/126.0 Safari/537.36")
        ctx = await self._browser.new_context(
            user_agent=ua, ignore_https_errors=self._ignore_https_errors)
        return await ctx.new_page(), ctx

    # -- navigation ------------------------------------------------------

    async def goto(self, url: str, page_id: int | None = None,
                 session_id: str | None = None) -> dict:
        """Navigate (new page unless page_id given). Returns page_id/url/title/status.

        When session_id is given and that session has saved auth cookies
        (via recon_authenticate), they are injected into the new browser
        context before navigation.
        """
        self._require_browser()
        if not re.match(r"^(https?|data):", url or "", re.IGNORECASE):
            raise ReconError(f"only http(s) and data: URLs are navigated: "
                             f"{str(url)[:80]!r}", "bad_url")
        try:
            if page_id is None:
                page, ctx = await self._new_page()
                if session_id:
                    try:
                        from omnirecon import auth as _auth
                        await _auth.inject_cookies(ctx, session_id)
                    except Exception:
                        pass
                pid = self._next_id
                self._next_id += 1
                entry = {"page": page, "context": ctx, "net": [], "ws": [],
                         "console": [],
                         "refs": {}, "url": url, "initiators": {}}
                self._pages[pid] = entry
                self._attach_listeners(pid, entry)
                await self._attach_cdp_initiators(entry)
            else:
                entry = self._get_page_entry(page_id)
                page = entry["page"]
                pid = int(page_id)
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass  # pages with polling/streaming never idle; not fatal
            entry["url"] = page.url
            return {"page_id": pid, "url": page.url, "title": await page.title(),
                    "status": resp.status if resp else None}
        except ReconError:
            raise
        except Exception as e:
            raise ReconError(f"goto {url} failed: {e}"[:300], "navigation_failed") from e

    def _attach_listeners(self, pid: int, entry: dict):
        page = entry["page"]

        def on_request(req):
            req_shape = None
            try:
                pd = req.post_data
                if pd and len(pd) < _BODY_CAP_BYTES:
                    try:
                        req_shape = infer_shape(json.loads(pd))
                    except Exception:
                        req_shape = {"type": "string",
                                     "bytes": len(pd)}
            except Exception:
                pass
            entry["net"].append({
                "t0": time.monotonic(),
                "method": req.method,
                "url": req.url,
                "type": req.resource_type,
                "status": None,
                "ms": None,
                "initiator": None,  # backfilled from CDP at read time
                "request_shape": req_shape,
                "response_shape": None,
            })

        async def on_response(resp):
            # match the most recent pending request for this URL
            target = None
            for r in reversed(entry["net"]):
                if r["url"] == resp.url and r["status"] is None:
                    target = r
                    break
            if target is None:
                return
            target["status"] = resp.status
            target["ms"] = int((time.monotonic() - target["t0"]) * 1000)
            # Capture values-free response shapes for XHR/fetch JSON.
            try:
                if resp.request.resource_type not in ("xhr", "fetch"):
                    return
                headers = {}
                try:
                    headers = await resp.all_headers()
                except Exception:
                    pass
                if not _looks_json(headers):
                    return
                body = await resp.body()
                if not body or len(body) > _BODY_CAP_BYTES:
                    return
                try:
                    target["response_shape"] = infer_shape(
                        json.loads(body.decode("utf-8", "replace")))
                except Exception:
                    pass
            except Exception:
                pass

        def on_websocket(ws):
            def _frame(payload, is_received: bool):
                try:
                    if len(entry["ws"]) >= 200:
                        return
                    shape = None
                    text = payload if isinstance(payload, str) \
                        else payload.decode("utf-8", "replace")[:4000]
                    try:
                        shape = infer_shape(json.loads(text))
                    except Exception:
                        shape = {"type": "text",
                                 "bytes": len(text)}
                    entry["ws"].append({
                        "url": ws.url,
                        "direction": "received" if is_received else "sent",
                        "shape": shape,
                    })
                except Exception:
                    pass

            try:
                ws.on("framesent", lambda p: _frame(p, False))
                ws.on("framereceived", lambda p: _frame(p, True))
            except Exception:
                pass

        def on_console(msg):
            if msg.type in ("error", "warning") and len(entry["console"]) < 50:
                entry["console"].append(f"[{msg.type}] {msg.text[:400]}")

        def on_page_error(exc):
            if len(entry["console"]) < 50:
                entry["console"].append(f"[pageerror] {str(exc)[:400]}")

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("websocket", on_websocket)
        page.on("console", on_console)
        page.on("pageerror", on_page_error)

    async def _attach_cdp_initiators(self, entry: dict):
        """Capture NETWORK INITIATOR STACKS via a CDP session.

        For every request the browser makes, CDP's Network.requestWillBeSent
        carries the initiator stack — the exact script URL, line number and
        function that fired the XHR/fetch/WebSocket. Stored per-URL and
        backfilled into the network log at read time, so each discovered API
        call links to the code that made it.
        """
        page = entry["page"]
        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("Network.enable")

            def on_will_be_sent(params):
                try:
                    init = params.get("initiator") or {}
                    stack = (init.get("stack") or {}).get("callFrames") or []
                    info = None
                    if stack:
                        f = stack[0]
                        info = {
                            "script_url": f.get("url"),
                            "line": f.get("lineNumber"),
                            "column": f.get("columnNumber"),
                            "function": f.get("functionName") or None,
                            "initiator_type": init.get("type"),
                        }
                    url = (params.get("request") or {}).get("url")
                    if url:
                        dq = entry["initiators"].setdefault(url, deque(maxlen=50))
                        dq.append(info)
                except Exception:
                    pass

            cdp.on("Network.requestWillBeSent", on_will_be_sent)
            entry["cdp"] = cdp
        except Exception:
            # CDP unavailable (older browsers, restricted contexts):
            # initiator stays None, everything else keeps working.
            entry["cdp"] = None

    def _backfill_initiators(self, entry: dict):
        """Attach captured initiator stacks to net-log entries, in order."""
        initiators = entry.get("initiators") or {}
        for r in entry["net"]:
            if r.get("initiator") is not None:
                continue
            dq = initiators.get(r["url"])
            if dq:
                try:
                    r["initiator"] = dq.popleft()
                except IndexError:
                    pass

    # -- snapshot --------------------------------------------------------

    async def snapshot(self, page_id: int) -> dict:
        """Compact accessibility/controls/forms extraction for a page."""
        entry = self._get_page_entry(page_id)
        page = entry["page"]
        try:
            data = await page.evaluate(_SNAPSHOT_JS)
        except Exception as e:
            raise ReconError(f"DOM snapshot failed: {e}"[:250], "snapshot_failed") from e
        refs = {c["ref"]: c["selector"] for c in data["controls"]}
        entry["refs"] = refs
        data["url"] = page.url
        data["title"] = await page.title()
        data["control_count"] = len(data["controls"])
        return data

    # -- screenshots ------------------------------------------------------

    async def screenshot(self, page_id: int, viewport: str = "desktop",
                         artifacts_dir: str | None = None) -> str:
        """Viewport screenshot -> content-addressed PNG path (sha256.png)."""
        entry = self._get_page_entry(page_id)
        if viewport not in VIEWPORTS:
            raise ReconError(f"viewport must be one of {sorted(VIEWPORTS)}", "bad_viewport")
        artifacts = artifacts_dir or self._tmp_artifacts
        os.makedirs(artifacts, exist_ok=True)
        page = entry["page"]
        prev = page.viewport_size
        try:
            await page.set_viewport_size(VIEWPORTS[viewport])
            png = await page.screenshot(full_page=False, timeout=15000)
        except Exception as e:
            raise ReconError(f"screenshot failed: {e}"[:250], "screenshot_failed") from e
        finally:
            try:
                if prev:
                    await page.set_viewport_size(prev)
            except Exception:
                pass
        digest = hashlib.sha256(png).hexdigest()
        path = os.path.join(artifacts, f"{digest}.png")
        with open(path, "wb") as fh:
            fh.write(png)
        return path

    # -- network -----------------------------------------------------------

    # -- request interception + mocking ------------------------------------
    # Time-travel the app into edge states: mock API failures, slow networks,
    # empty responses. This is how you see the 2-3x more UI that only exists
    # in error/empty/loading states — invisible to passive crawling.

    async def intercept(self, page_id: int, pattern: str, action: str,
                        status: int = 500, body: str = "",
                        delay_ms: int = 0) -> dict:
        """Intercept requests matching pattern.

        Actions: 'abort' (network failure), 'mock' (return status+body),
        'delay' (slow the response by delay_ms).
        Pattern is a glob like '**/api/*'.
        """
        entry = self._get_page_entry(page_id)
        page = entry["page"]

        async def _handler(route):
            if action == "abort":
                await route.abort()
            elif action == "mock":
                await route.fulfill(status=status, body=body,
                                    content_type="application/json")
            elif action == "delay":
                await page.wait_for_timeout(delay_ms)
                await route.continue_()
            else:
                await route.continue_()

        await page.route(pattern, _handler)
        # Track for cleanup
        entry.setdefault("routes", []).append(pattern)
        return {"intercepted": pattern, "action": action}

    async def clear_intercepts(self, page_id: int) -> dict:
        """Remove all registered route interceptions."""
        entry = self._get_page_entry(page_id)
        page = entry["page"]
        for pattern in entry.get("routes", []):
            try:
                await page.unroute(pattern)
            except Exception:
                pass
        entry["routes"] = []
        return {"cleared": True}

    async def mock_scenario(self, page_id: int, scenario: str,
                            url_pattern: str = "**/api/*") -> dict:
        """Run a predefined edge-state scenario.

        Scenarios:
        - 'api_down': all API calls return 500
        - 'slow': API calls delayed 3s (loading states)
        - 'empty': API calls return empty list {}
        - 'unauthorized': API calls return 401 (expired session)
        """
        scenarios = {
            "api_down": ("mock", 500, '{"error":"mocked outage"}', 0),
            "slow": ("delay", 200, "", 3000),
            "empty": ("mock", 200, '{"data":[]}', 0),
            "unauthorized": ("mock", 401, '{"error":"mocked expired session"}', 0),
        }
        if scenario not in scenarios:
            raise ReconError(
                f"unknown scenario '{scenario}'; choose from "
                f"{sorted(scenarios)}", "bad_scenario")
        action, status, body, delay = scenarios[scenario]
        return await self.intercept(page_id, url_pattern, action,
                                    status=status, body=body,
                                    delay_ms=delay)

    async def network_capture(self, page_id: int, duration_ms: int = 8000) -> list[dict]:
        """Reload the page and record redacted network traffic for duration_ms.

        Each entry carries the CDP initiator stack ({script_url, line, column,
        function, initiator_type}) linking the request to the code that fired it.
        """
        entry = self._get_page_entry(page_id)
        page = entry["page"]
        entry["net"] = []
        entry["ws"] = []
        try:
            await page.reload(wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            raise ReconError(f"reload for capture failed: {e}"[:250], "capture_failed") from e
        await page.wait_for_timeout(max(500, min(int(duration_ms), 30000)))
        # let async body captures settle
        await page.wait_for_timeout(1500)
        self._backfill_initiators(entry)
        out = []
        for r in entry["net"]:
            out.append({
                "method": r["method"],
                "url": r["url"],
                "status": r["status"],
                "type": r["type"],
                "ms": r["ms"],
                "initiator": r.get("initiator"),
                "request_shape": r.get("request_shape"),
                "response_shape": r.get("response_shape"),
            })
        ws_frames = []
        for f in entry.get("ws", []):
            ws_frames.append({
                "url": f["url"],
                "direction": f["direction"],
                "shape": f["shape"],
            })
        return {"requests": _redact(out), "websocket_frames": _redact(ws_frames)}

    def console_errors(self, page_id: int) -> list[str]:
        entry = self._get_page_entry(page_id)
        return [m for m in entry["console"] if m.startswith("[error]")
                or m.startswith("[pageerror]")]

    async def storage_snapshot(self, page_id: int) -> dict:
        """Dump client-side storage: localStorage, sessionStorage, cookies,
        IndexedDB database names. Secrets are redacted by the caller."""
        entry = self._get_page_entry(page_id)
        page = entry["page"]
        js = """() => {
          const out = {localStorage: {}, sessionStorage: {}, cookies: [],
                       indexedDB: []};
          try { for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i); out.localStorage[k] = localStorage.getItem(k); } } catch (e) {}
          try { for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i); out.sessionStorage[k] = sessionStorage.getItem(k); } } catch (e) {}
          try { out.cookies = document.cookie.split(';').map(c => c.trim().split('=')[0]).filter(Boolean); } catch (e) {}
          try { out.indexedDB = []; } catch (e) {}
          return out;
        }"""
        try:
            data = await page.evaluate(js)
        except Exception:
            data = {}
        # IndexedDB needs an async check
        try:
            dbs = await page.evaluate(
                "async () => (indexedDB.databases ? "
                "(await indexedDB.databases()).map(d => d.name) : [])")
            data["indexedDB"] = dbs or []
        except Exception:
            pass
        return data if isinstance(data, dict) else {}

    # -- interaction -------------------------------------------------------

    async def _resolve_target(self, entry: dict, action: dict) -> tuple[str, str, str]:
        """Returns (selector, accessible_name, tag). Raises ReconError."""
        page = entry["page"]
        ref = action.get("ref")
        selector = action.get("selector")
        if ref:
            selector = entry["refs"].get(ref)
            if not selector:
                raise ReconError(f"unknown control ref {ref!r}", "bad_ref", "refs come from snapshot(); call snapshot() first")
        if not selector:
            raise ReconError("action needs 'ref' (from snapshot) or 'selector'", "no_target")
        try:
            name = await page.eval_on_selector(
                selector,
                "(el) => {"
                " const t=(el.getAttribute('type')||'').toLowerCase();"
                " const secret=t==='password'||el.getAttribute('data-secret')!==null"
                "   ||/passw|secret|token/i.test(el.getAttribute('name')||'');"
                " const val=secret?'':(el.value||'');"
                " return (el.getAttribute('aria-label')||(el.innerText||'').trim()"
                "   ||val||el.placeholder||'').slice(0,120); }")
            tag = await page.eval_on_selector(
                selector, "(el) => el.tagName.toLowerCase()")
        except Exception:
            name, tag = "", ""
        return selector, name or "", tag or ""

    async def interact(self, page_id: int, action: dict) -> dict:
        """Perform ONE safe action; report what was actually observed.

        Never claims a control works from visibility alone: ``observed`` is True
        only when the URL changed, the DOM changed, or new XHR/fetch traffic
        appeared. Refuses destructive actions (purchases/payments/deletions)
        and any password-exfiltration attempt.
        """
        entry = self._get_page_entry(page_id)
        if not isinstance(action, dict):
            raise ReconError("action must be a dict", "bad_action")
        kind = action.get("kind")
        if kind not in SAFE_ACTION_KINDS:
            raise ReconError(f"refused: action kind {kind!r} is not in the safe set "
                f"{sorted(SAFE_ACTION_KINDS)} (no value extraction, no scripts)", "invalid_action", "password exfiltration and arbitrary JS are never allowed")
        page = entry["page"]

        if kind == "scroll":
            return await self._do_scroll(entry, action)

        selector, name, tag = await self._resolve_target(entry, action)

        # destructive-action refusal (checked against accessible name + selector)
        if kind == "click" and _DESTRUCTIVE_RE.search(f"{name} {selector}"):
            raise ReconError(f"refused: click target {name!r} looks destructive "
                "(purchase/payment/deletion); consequential actions need "
                "explicit user approval", "refused", "use click only for navigation/UI exploration")

        # password fields: filling is legitimate (authorized test accounts),
        # but values are NEVER returned or stored
        is_password = False
        try:
            is_password = await page.eval_on_selector(
                selector,
                "(el) => (el.getAttribute('type')||'').toLowerCase() === 'password'")
        except Exception:
            pass

        url_before = page.url
        try:
            sig_before = await page.evaluate(_DOM_SIG_JS)
        except Exception:
            sig_before = ""
        net_before = len([r for r in entry["net"]
                          if r["type"] in ("xhr", "fetch", "websocket")])

        try:
            if kind == "click":
                await page.click(selector, timeout=8000)
            elif kind == "fill":
                value = action.get("value", "")
                if not isinstance(value, str):
                    raise ReconError("fill needs a string 'value'", "bad_action")
                await page.fill(selector, value, timeout=8000)
            elif kind == "select":
                value = action.get("value", "")
                await page.select_option(selector, value, timeout=8000)
            elif kind == "press":
                key = action.get("key", "Enter")
                await page.press(selector, key, timeout=8000)
        except ReconError:
            raise
        except Exception as e:
            raise ReconError(f"{kind} on {selector!r} failed: {e}"[:300], "action_failed") from e

        await page.wait_for_timeout(900)
        url_after = page.url
        try:
            sig_after = await page.evaluate(_DOM_SIG_JS)
        except Exception:
            sig_after = sig_before
        self._backfill_initiators(entry)
        net_after = len([r for r in entry["net"]
                         if r["type"] in ("xhr", "fetch", "websocket")])
        new_reqs = [
            {"method": r["method"], "url": r["url"], "status": r["status"],
             "type": r["type"], "initiator": r.get("initiator")}
            for r in entry["net"]
            if r["type"] in ("xhr", "fetch", "websocket")
        ][-(net_after - net_before):] if net_after > net_before else []

        dom_changed = sig_after != sig_before
        url_changed = url_after != url_before
        observed = dom_changed or url_changed or bool(new_reqs)
        note = ("state change observed" if observed
                else "no observable change: control is visible but did not "
                     "change URL, DOM, or network traffic")
        if is_password:
            note += " (password field value never captured)"
        return {
            "observed": observed,
            "kind": kind,
            "target": {"selector": selector, "name": name, "tag": tag},
            "url_before": url_before,
            "url_after": url_after,
            "dom_changed": dom_changed,
            "new_requests": _redact(new_reqs),
            "note": note,
        }

    async def _do_scroll(self, entry: dict, action: dict) -> dict:
        page = entry["page"]
        direction = (action.get("direction") or "down").lower()
        pixels = int(action.get("pixels", 800))
        url_before = page.url
        try:
            if direction == "up":
                pixels = -abs(pixels)
            else:
                pixels = abs(pixels)
            await page.mouse.wheel(0, pixels)
        except Exception as e:
            raise ReconError(f"scroll failed: {e}"[:250], "action_failed") from e
        await page.wait_for_timeout(900)
        return {
            "observed": True,  # scroll itself executed; content change unknown
            "kind": "scroll",
            "target": {"selector": None, "name": f"scroll {direction}",
                       "tag": "viewport"},
            "url_before": url_before,
            "url_after": page.url,
            "dom_changed": None,  # scroll rarely changes DOM signature; not claimed
            "new_requests": [],
            "note": ("scroll executed; lazy-loaded content may have appeared — "
                     "re-run snapshot() to verify"),
        }

    # -- crawl --------------------------------------------------------------

    async def crawl(self, start_url: str, max_pages: int = 30, max_depth: int = 2,
                    session_dir: str | None = None) -> dict:
        """Route discovery: static link graph (recon_primitives) + rendered
        snapshots of each discovered route in the owned browser."""
        self._require_browser()
        max_pages = max(1, min(int(max_pages), 100))
        max_depth = max(0, min(int(max_depth), 4))
        try:
            from omnirecon import recon_primitives as RP
        except Exception as e:
            raise ReconError(f"recon_primitives unavailable: {e}", "no_primitives") from e

        static = RP.crawl_site(start_url, max_pages=max_pages,
                               max_depth=max_depth)
        artifacts = os.path.join(session_dir or self._tmp_artifacts, "artifacts")
        os.makedirs(artifacts, exist_ok=True)

        routes = []
        shot = None
        for i, p in enumerate(static.get("pages", [])):
            url = p.get("url")
            if not url:
                continue
            try:
                nav = await self.goto(url)
                snap = await self.snapshot(nav["page_id"])
                if i == 0:
                    try:
                        shot = await self.screenshot(nav["page_id"], "desktop",
                                                     artifacts)
                    except ReconError:
                        shot = None
                routes.append({
                    "url": url,
                    "title": snap.get("title"),
                    "control_count": snap.get("control_count", 0),
                    "form_count": len(snap.get("forms", [])),
                    "link_count": snap.get("link_count", 0),
                    "headings": [h["text"] for h in snap.get("headings", [])[:5]],
                    "route_kind": _classify_route(url),
                })
            except ReconError:
                routes.append({"url": url, "title": p.get("title"),
                               "control_count": 0, "form_count": 0,
                               "link_count": 0, "headings": [],
                               "error": "browser visit failed",
                               "route_kind": _classify_route(url)})
            await asyncio.sleep(0.3)  # polite delay between page visits
        return {
            "start_url": start_url,
            "pages_crawled": static.get("pages_crawled", 0),
            "routes_visited": len(routes),
            "routes": routes,
            "api_endpoints": static.get("api_endpoints", []),
            "start_page_screenshot": shot,
        }


def _classify_route(url: str) -> str:
    u = url.lower()
    for pat, kind in (
        (r"/login|/signin|/auth|/sso", "auth"),
        (r"/signup|/register|/onboard", "signup"),
        (r"/pricing|/plans|/billing|/checkout|/cart", "commerce"),
        (r"/docs|/guide|/tutorial|/blog|/changelog", "docs"),
        (r"/api/|/graphql", "api"),
        (r"/settings|/account|/profile|/admin|/dashboard", "app"),
        (r"/search", "search"),
    ):
        if re.search(pat, u):
            return kind
    return "content"


# ---------------------------------------------------------------------------
# Sync facade — runs the async engine on a dedicated worker thread/loop
# ---------------------------------------------------------------------------

class _LoopThread:
    """A daemon thread running its own private asyncio event loop.

    Lets sync callers drive the async engine without touching the caller's
    loop (or lack of one). Never use from the worker thread itself.
    """

    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._failed: Exception | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="omnirecon-browser-loop")
        self._thread.start()
        if not self._ready.wait(30):
            raise ReconError("browser event-loop thread did not start", "loop_failed")
        if self._failed is not None:
            raise ReconError(f"browser event-loop thread failed: {self._failed}", "loop_failed")

    def _run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
        except Exception as e:  # pragma: no cover - defensive
            self._failed = e
        finally:
            self._ready.set()
        if self._loop is not None:
            self._loop.run_forever()

    def run(self, coro, timeout: float = 1800):
        """Block the calling thread until coro completes on the worker loop."""
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError as e:
            raise ReconError(f"browser operation timed out after {timeout}s", "timeout", "the page may be hanging; try a smaller scope") from e

    def stop(self):
        loop, self._loop = self._loop, None
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        self._thread.join(timeout=10)


class OwnedBrowser:
    """Sync facade over AsyncOwnedBrowser (Lane A public API).

    Every method dispatches to a dedicated worker thread with its own event
    loop, so this is safe to use from plain scripts, threads, and test code —
    including code running *inside* another asyncio loop, as long as the call
    itself doesn't block that loop's thread (use an executor there, or use
    AsyncOwnedBrowser directly, as FastMCP tool handlers should).
    """

    def __init__(self):
        self._impl = AsyncOwnedBrowser()
        self._thread = _LoopThread()

    def _run(self, coro):
        return self._thread.run(coro)

    def launch(self, headless: bool = True,
               ignore_https_errors: bool = False) -> dict:
        return self._run(self._impl.launch(
            headless=headless, ignore_https_errors=ignore_https_errors))

    def close(self) -> dict:
        return self._run(self._impl.close())

    def shutdown(self) -> dict:
        """Close the browser and stop the worker thread. Idempotent."""
        try:
            self._run(self._impl.close())
        except Exception:
            pass
        try:
            self._thread.stop()
        except Exception:
            pass
        return {"ok": True}

    def goto(self, url: str, page_id: int | None = None,
             session_id: str | None = None) -> dict:
        return self._run(self._impl.goto(url, page_id=page_id,
                                         session_id=session_id))

    def snapshot(self, page_id: int) -> dict:
        return self._run(self._impl.snapshot(page_id))

    def screenshot(self, page_id: int, viewport: str = "desktop",
                   artifacts_dir: str | None = None) -> str:
        return self._run(self._impl.screenshot(
            page_id, viewport=viewport, artifacts_dir=artifacts_dir))

    def network_capture(self, page_id: int, duration_ms: int = 8000) -> list[dict]:
        return self._run(self._impl.network_capture(page_id, duration_ms))

    def intercept(self, page_id: int, pattern: str, action: str,
                  status: int = 500, body: str = "",
                  delay_ms: int = 0) -> dict:
        return self._run(self._impl.intercept(
            page_id, pattern, action, status=status, body=body,
            delay_ms=delay_ms))

    def clear_intercepts(self, page_id: int) -> dict:
        return self._run(self._impl.clear_intercepts(page_id))

    def mock_scenario(self, page_id: int, scenario: str,
                      url_pattern: str = "**/api/*") -> dict:
        return self._run(self._impl.mock_scenario(
            page_id, scenario, url_pattern))

    def console_errors(self, page_id: int) -> list[str]:
        # pure local read; no loop needed
        return self._impl.console_errors(page_id)

    def storage_snapshot(self, page_id: int) -> dict:
        return self._run(self._impl.storage_snapshot(page_id))

    def interact(self, page_id: int, action: dict) -> dict:
        return self._run(self._impl.interact(page_id, action))

    def crawl(self, start_url: str, max_pages: int = 30, max_depth: int = 2,
              session_dir: str | None = None) -> dict:
        return self._run(self._impl.crawl(
            start_url, max_pages=max_pages, max_depth=max_depth,
            session_dir=session_dir))
