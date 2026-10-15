"""JS signature tracing (Beat-REA Wave 2).

Answers the #1 real-world web reverse-engineering question: "how is this
``sign=`` parameter computed?"

A Playwright init script (installed before any page JavaScript runs) hooks
the page's own crypto and network primitives and records what the page
computes itself:

  - ``crypto.subtle.digest`` / ``crypto.subtle.sign`` (WebCrypto)
  - CryptoJS HMAC/SHA/MD5 family (lazy hook, in case the lib loads later)
  - ``window.fetch`` and ``XMLHttpRequest`` (outgoing requests + stacks)

``analyze()`` then correlates outgoing requests that carry signature-looking
parameters (``sign=``, ``sig=``, ``checksum=``, ``token=``, ``nonce=``, ...)
with the crypto calls that ran just before them, and reports WHICH request
fields fed into the signature input, e.g.::

    sign = HMAC-SHA-256(key, "amount=100&currency=USD&ts=1699999999")

Security note: this only observes computation the page performs itself inside
our own owned browser — no bypass of any protection, no credential theft.
Signature values are redacted to prefix/suffix in all output.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, urlsplit

# ---------------------------------------------------------------------------
# The hook script: runs in the page before any of its own JS.
# ---------------------------------------------------------------------------

HOOK_SCRIPT = r"""
(function(){
  if (window.__omni) return;
  window.__omni = { crypto: [], reqs: [] };
  var omni = window.__omni;
  function now(){ return Date.now(); }
  function frame(){
    try {
      var s = new Error().stack || "";
      return s.split("\n").slice(2, 6).join(" <- ").slice(0, 800);
    } catch (e) { return ""; }
  }
  function logCrypto(op, alg, inputPreview, inputLen){
    if (omni.crypto.length >= 400) return;
    try {
      omni.crypto.push({op: op, alg: String(alg || "?").slice(0, 120),
                        input_preview: String(inputPreview || "").slice(0, 400),
                        input_len: inputLen || 0,
                        stack: frame(), t: now()});
    } catch (e) {}
  }
  function logReq(kind, method, url, body){
    if (omni.reqs.length >= 400) return;
    try {
      omni.reqs.push({kind: kind, method: method || "",
                      url: String(url || "").slice(0, 2000),
                      body_preview: String(body == null ? "" : body).slice(0, 600),
                      stack: frame(), t: now()});
    } catch (e) {}
  }
  function bytesToPreview(buf, maxBytes){
    try {
      var b = new Uint8Array(buf);
      var n = Math.min(b.length, maxBytes || 160);
      var ascii = "", ok = true, i;
      for (i = 0; i < n; i++) {
        var c = b[i];
        if (c === 9 || c === 10 || c === 13) { ascii += " "; continue; }
        if (c < 32 || c > 126) { ok = false; break; }
        ascii += String.fromCharCode(c);
      }
      if (ok) return ascii;
      var hex = "";
      for (i = 0; i < n; i++) hex += b[i].toString(16).padStart(2, "0");
      return "hex:" + hex;
    } catch (e) { return ""; }
  }
  function algLabel(alg){
    try {
      if (!alg) return "?";
      if (typeof alg === "string") return alg;
      var name = alg.name || "?";
      var h = alg.hash;
      var hs = (h && (h.name || h)) || "";
      return hs ? (name + "/" + hs) : name;
    } catch (e) { return "?"; }
  }

  function keyLabel(key){
    try {
      var a = key && key.algorithm;
      if (!a) return "";
      var h = a.hash;
      var hs = (h && (h.name || h)) || "";
      return hs ? ("/" + hs) : "";
    } catch (e) { return ""; }
  }

  // --- WebCrypto ---
  try {
    var subtle = window.crypto && window.crypto.subtle;
    if (subtle) {
      var _digest = subtle.digest.bind(subtle);
      subtle.digest = function(alg, data){
        try { logCrypto("digest", algLabel(alg), bytesToPreview(data),
                        data && data.byteLength); } catch (e) {}
        return _digest(alg, data);
      };
      var _sign = subtle.sign.bind(subtle);
      subtle.sign = function(alg, key, data){
        try { logCrypto("sign", algLabel(alg) + keyLabel(key),
                        bytesToPreview(data),
                        data && data.byteLength); } catch (e) {}
        return _sign(alg, key, data);
      };
    }
  } catch (e) {}

  // --- CryptoJS (lazy: the library often loads after this script) ---
  function hookCryptoJS(){
    try {
      var C = window.CryptoJS;
      if (!C || C.__omni_hooked) return;
      C.__omni_hooked = true;
      ["HmacSHA256", "HmacSHA512", "HmacSHA1", "HmacMD5",
       "SHA256", "SHA512", "SHA1", "MD5"].forEach(function(fname){
        if (typeof C[fname] === "function") {
          (function(orig, name){
            C[fname] = function(msg, key){
              try { logCrypto("cryptojs:" + name, name,
                              String(msg).slice(0, 400),
                              String(msg).length); } catch (e) {}
              return orig.call(C, msg, key);
            };
          })(C[fname], fname);
        }
      });
    } catch (e) {}
  }
  hookCryptoJS();
  setInterval(hookCryptoJS, 800);

  // --- fetch ---
  try {
    var _fetch = window.fetch.bind(window);
    window.fetch = function(input, init){
      try {
        var url = (typeof input === "string") ? input : (input && input.url) || "";
        var method = (init && init.method) || (input && input.method) || "GET";
        var body = init && init.body;
        logReq("fetch", method, url, (typeof body === "string") ? body : "");
      } catch (e) {}
      return _fetch(input, init);
    };
  } catch (e) {}

  // --- XHR ---
  try {
    var XHR = XMLHttpRequest.prototype;
    var _open = XHR.open, _send = XHR.send;
    XHR.open = function(method, url){
      this.__omni_method = method; this.__omni_url = url;
      return _open.apply(this, arguments);
    };
    XHR.send = function(body){
      try { logReq("xhr", this.__omni_method, this.__omni_url, body); }
      catch (e) {}
      return _send.apply(this, arguments);
    };
  } catch (e) {}
})();
"""

# ---------------------------------------------------------------------------
# Analysis: correlate signed requests with the crypto that computed them.
# ---------------------------------------------------------------------------

#: Substrings that mark a query/body parameter as signature-like.
SIGNATURE_PARAM_HINTS = (
    "sign", "sig", "checksum", "hmac", "nonce", "token",
    "auth", "digest", "secret",
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_STACK_TOKEN_RE = re.compile(r"\(?(https?://[^)\s\"']+)\)?")


def _is_sig_name(name: str) -> bool:
    n = (name or "").lower()
    return any(h in n for h in SIGNATURE_PARAM_HINTS)


def _looks_like_sig_value(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 16 or len(v) > 512:
        return False
    return bool(_HEX_RE.match(v) or _B64_RE.match(v))


def _redact_sig(value: str) -> str:
    """Signature values are redacted to prefix...suffix in all output."""
    v = str(value or "")
    if len(v) <= 16:
        return v[:8] + "..." if len(v) > 8 else v
    return v[:8] + "..." + v[-4:]


def _source_from_stack(stack: str) -> str:
    """Extract 'url:line' of the page-JS frame from a Chrome stack string.

    Chrome frames look like ``at fn (https://host:port/app.js:42:10)``.
    We take the first token and strip the trailing :column, keeping any
    :port — ports are not digit-only line numbers after the path split.
    """
    for m in _STACK_TOKEN_RE.finditer(stack or ""):
        token = m.group(1).rstrip(".,;")
        parts = token.rsplit(":", 2)
        if (len(parts) == 3 and parts[1].isdigit()
                and parts[2].isdigit()):
            return f"{parts[0]}:{parts[1]}"
        parts = token.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return f"{parts[0]}:{parts[1]}"
    return ""


def _algorithm_label(op: str, alg: str) -> str:
    op = (op or "").lower()
    alg = (alg or "").strip()
    if op.startswith("cryptojs:"):
        base = op.split(":", 1)[1]
        fam = {"hmacsha256": "HMAC-SHA-256", "hmacsha512": "HMAC-SHA-512",
               "hmacsha1": "HMAC-SHA-1", "hmacmd5": "HMAC-MD5",
               "sha256": "SHA-256", "sha512": "SHA-512",
               "sha1": "SHA-1", "md5": "MD5"}.get(base.lower(), base)
        return f"{fam} (CryptoJS)"
    if op == "sign":
        # WebCrypto: alg like "HMAC/SHA-256"
        parts = alg.upper().split("/")
        if parts[0] == "HMAC":
            h = parts[1] if len(parts) > 1 else ""
            return f"HMAC-{h}" if h else "HMAC (hash unknown)"
        return f"{alg} signature"
    if op == "digest":
        return alg.upper().replace("-", "-") if alg != "?" else "hash (unknown)"
    return f"{op}:{alg}"


def _request_params(req: dict) -> list[tuple[str, str]]:
    """Query params + urlencoded body params for a logged request."""
    out: list[tuple[str, str]] = []
    try:
        out.extend(parse_qsl(urlsplit(req.get("url", "")).query,
                             keep_blank_values=True))
    except Exception:
        pass
    body = (req.get("body_preview") or "").strip()
    if body and "=" in body and len(body) < 2000 and "\n" not in body:
        try:
            out.extend(parse_qsl(body, keep_blank_values=True))
        except Exception:
            pass
    return out


def analyze(hook_data: dict | None, page_url: str = "") -> dict:
    """Correlate signed requests with observed crypto calls.

    Returns {"signatures": [...], "unknowns": [...]}. Each signature entry:
      endpoint, param, value_preview, algorithm, input_preview, input_fields,
      computed_in, classification, confidence.
    """
    signatures: list[dict] = []
    unknowns: list[str] = []
    if not hook_data:
        return {"signatures": signatures,
                "unknowns": ["hooks captured no data (page may have blocked "
                             "script injection or fired no requests)"]}
    crypto_calls = hook_data.get("crypto") or []
    reqs = hook_data.get("reqs") or []

    for req in reqs:
        params = _request_params(req)
        if not params:
            continue
        sig_params = [(k, v) for k, v in params
                      if _is_sig_name(k) or _looks_like_sig_value(v)]
        if not sig_params:
            continue
        other = [(k, v) for k, v in params if (k, v) not in sig_params]
        req_t = req.get("t") or 0
        try:
            path = urlsplit(req.get("url", "")).path or "/"
        except Exception:
            path = "/"

        for name, value in sig_params:
            # Crypto calls that ran in the 5s before this request.
            window = [c for c in crypto_calls
                      if 0 <= (req_t - (c.get("t") or 0)) <= 5000]
            best, best_score, best_fields = None, -1, []
            for c in window:
                preview = c.get("input_preview") or ""
                fields = []
                for k, v in other:
                    if k and k in preview:
                        fields.append(k)
                    elif v and len(str(v)) >= 2 and str(v) in preview:
                        fields.append(f"{k}={v}")
                score = len(fields)
                # Prefer calls whose stack points at page JS over library code.
                src = _source_from_stack(c.get("stack") or "")
                if src and page_url and src.startswith(page_url.split("?")[0].rsplit("/", 1)[0]):
                    score += 0.5
                if score > best_score:
                    best, best_score, best_fields = c, score, fields

            if best is not None:
                alg = _algorithm_label(best.get("op"), best.get("alg"))
                src = _source_from_stack(best.get("stack") or "")
                verified = best_score >= 1
                signatures.append({
                    "endpoint": path,
                    "method": (req.get("method") or "GET").upper(),
                    "param": name,
                    "value_preview": _redact_sig(value),
                    "algorithm": alg,
                    "input_preview": (best.get("input_preview") or "")[:200],
                    "input_fields": best_fields,
                    "computed_in": src,
                    "classification": "SOURCE_VERIFIED" if verified else "INFERRED",
                    "confidence": 0.9 if best_score >= 2 else (0.75 if verified else 0.55),
                })
            else:
                unknowns.append(
                    f"{path}: '{name}=' present but no crypto call observed in "
                    "the 5s before the request (custom/obfuscated signer, or "
                    "fired before hooks armed)")

    if not signatures and not unknowns:
        unknowns.append("no signature-like parameters observed in "
                        f"{len(reqs)} captured requests")
    return {"signatures": signatures, "unknowns": unknowns}


def trace_signatures(browser, url: str, wait_ms: int = 9000,
                     session_id: str | None = None) -> dict:
    """Load *url* with crypto hooks armed and trace signature computation.

    *browser* is an OwnedBrowser (sync facade). Returns
    {"url", "signatures", "stats", "unknowns"}.
    """
    wait_s = max(1.0, min(int(wait_ms or 9000), 30000) / 1000.0)
    page = browser.goto(url, session_id=session_id)
    pid = page["page_id"]
    browser.add_init_script(pid, HOOK_SCRIPT)
    # Reload so the init script runs before any page JavaScript.
    browser.goto(url, page_id=pid)
    time.sleep(wait_s)
    data = browser.evaluate(pid, "window.__omni || null")
    result = analyze(data if isinstance(data, dict) else None,
                     page_url=page.get("url", url))
    crypto_calls = (data or {}).get("crypto", []) if isinstance(data, dict) else []
    reqs = (data or {}).get("reqs", []) if isinstance(data, dict) else []
    result["url"] = page.get("url", url)
    result["stats"] = {
        "requests_captured": len(reqs),
        "crypto_calls_captured": len(crypto_calls),
        "signed_requests": len(result["signatures"]),
    }
    return result
