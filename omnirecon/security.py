"""Security boundaries for OmniRecon: secret redaction, scope checks,
rate limiting, append-only audit log, and path-traversal-safe file joins.

Shared convention: public helpers raise ReconError (with .code) on failure;
nothing here prints or performs network I/O.
"""
from __future__ import annotations

import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse, urlencode, urlunparse

REDACTED = "[REDACTED]"
_MAX_STR_LEN = 4096
_MAX_DEPTH = 60


class ReconError(Exception):
    """Structured failure. `.code` is machine-readable; message is human-readable."""

    def __init__(self, message: str, code: str = "error", hint: str = ""):
        super().__init__(message)
        self.code = code
        self.hint = hint

    def to_dict(self) -> dict:
        d = {"error": str(self), "code": self.code}
        if self.hint:
            d["hint"] = self.hint
        return d


# --------------------------------------------------------------------------
# secret redaction
# --------------------------------------------------------------------------

# Exact key names (case-insensitive) whose values are always secrets.
_SENSITIVE_EXACT = frozenset({
    "authorization", "proxy-authorization", "proxy-authenticate",
    "cookie", "set-cookie", "set-cookie2", "cookie2",
    "password", "passwd", "pwd", "secret", "secrets",
    "sessionid", "session_id", "session-id",
    "auth", "authentication", "x-auth-token", "auth-token",
    "api-key", "api_key", "apikey",
    "x-session", "x-session-id", "x-sessionid", "sid", "sessid",
    "code", "refresh_token", "refresh-token", "id_token", "id-token",
})

# Substring fragments (case-insensitive) that mark a key as secret-bearing.
# Deliberately does NOT include bare "auth" (would nuke "author").
_SENSITIVE_SUBSTR = (
    "token", "secret", "password", "passwd", "credential",
    "private_key", "privatekey", "apikey", "api_key", "api-key",
    "client_secret", "access_key", "secret_key", "bearer",
    "session_key", "sessionkey",
)

# "auth" only counts when it is a standalone token: auth, x-auth, auth_token…
_AUTH_TOKEN_RE = re.compile(r"(^|[_.\-])auth([_.\-]|$)|^xauth", re.IGNORECASE)

_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{4,}")
_BASIC_RE = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}")
# key=value pairs in free text where the key is secret-bearing
_KV_RE = re.compile(
    r"(?i)\b(token|secret|password|passwd|pwd|api_?key|apikey|"
    r"auth(?:[_\-][\w\-]*)?|authentication|"
    r"session_?id|client_secret|access_key|private_?key|"
    r"code|refresh_token|id_token)\s*=\s*"
    r"(\"[^\"]*\"|'[^']*'|[^\s&;,'\"]+)"
)
# colon-form secrets in free text / JSON-ish: "password": "x", 'token':'y'
_KV_COLON_RE = re.compile(
    r"(?i)(\"(?:token|secret|password|passwd|pwd|api_?key|apikey|"
    r"auth(?:[_\-][\w\-]*)?|session_?id|client_secret|code|"
    r"refresh_token|id_token)\"\s*:\s*)\"[^\"]*\""
)


def _is_sensitive_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    k = key.strip().lower()
    if k in _SENSITIVE_EXACT:
        return True
    if _AUTH_TOKEN_RE.search(k):
        return True
    return any(frag in k for frag in _SENSITIVE_SUBSTR)


def _redact_url_string(s: str) -> str:
    """Redact sensitive query params and userinfo inside anything URL-like."""
    has_qs = "?" in s and ("://" in s or s.startswith("/"))
    has_userinfo = "://" in s and "@" in s.split("://", 1)[1].split("/", 1)[0]
    if not has_qs and not has_userinfo:
        return s
    try:
        parts = urlparse(s)
        # strip userinfo: https://user:pass@host/ -> https://[REDACTED]@host/
        if has_userinfo and "@" in parts.netloc:
            parts = parts._replace(
                netloc=REDACTED + "@" + parts.netloc.rsplit("@", 1)[1])
            s = urlunparse(parts)
        if not parts.query:
            return s
        changed = False
        new_qs = []
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            if _is_sensitive_key(name):
                new_qs.append((name, REDACTED))
                changed = True
            else:
                new_qs.append((name, value))
        if not changed:
            return s
        # urlencode escapes the brackets in [REDACTED]; restore readability
        return urlunparse(parts._replace(query=urlencode(new_qs))).replace(
            "%5BREDACTED%5D", REDACTED).replace("%5bredacted%5d", REDACTED)
    except Exception:
        return s


def _clean_string(s: str) -> str:
    s = _BEARER_RE.sub("Bearer " + REDACTED, s)
    s = _BASIC_RE.sub("Basic " + REDACTED, s)
    s = _KV_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", s)
    s = _KV_COLON_RE.sub(lambda m: f"{m.group(1)}\"{REDACTED}\"", s)
    s = _redact_url_string(s)
    if len(s) > _MAX_STR_LEN:
        s = s[:_MAX_STR_LEN] + "…[truncated]"
    return s


def redact(obj, _depth: int = 0, _seen: set[int] | None = None):
    """Deep-clean a JSON-like structure. Returns a cleaned copy; input untouched.

    - dict keys matching secret patterns → value replaced with "[REDACTED]"
    - strings → bearer/basic tokens scrubbed, sensitive query params redacted,
      bodies longer than 4KB truncated
    - lists/tuples/sets → cleaned element-wise (tuples stay tuples)
    - bytes → decoded (errors ignored) then cleaned as string
    - circular references → replaced with "[CIRCULAR]"
    """
    if _seen is None:
        _seen = set()
    if _depth > _MAX_DEPTH:
        return "[MAX-DEPTH]"
    if isinstance(obj, dict):
        oid = id(obj)
        if oid in _seen:
            return "[CIRCULAR]"
        _seen.add(oid)
        try:
            return {
                k: (REDACTED if _is_sensitive_key(k) else redact(v, _depth + 1, _seen))
                for k, v in obj.items()
            }
        finally:
            _seen.discard(oid)
    if isinstance(obj, (list, tuple)):
        oid = id(obj)
        if oid in _seen:
            return "[CIRCULAR]"
        _seen.add(oid)
        try:
            cleaned = [redact(v, _depth + 1, _seen) for v in obj]
            return tuple(cleaned) if isinstance(obj, tuple) else cleaned
        finally:
            _seen.discard(oid)
    if isinstance(obj, (set, frozenset)):
        return {redact(v, _depth + 1, _seen) for v in obj}
    if isinstance(obj, bytes):
        try:
            return _clean_string(obj.decode("utf-8", errors="ignore"))
        except Exception:
            return REDACTED
    if isinstance(obj, str):
        return _clean_string(obj)
    return obj


# --------------------------------------------------------------------------
# scope checking
# --------------------------------------------------------------------------

def check_scope(url: str, allowed_domains: list[str]) -> bool:
    """True iff url's host is exactly, or a subdomain of, an allowed domain."""
    if not url or not allowed_domains:
        return False
    try:
        host = (urlparse(url).hostname or "").strip().lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    for dom in allowed_domains:
        d = str(dom).strip().lower().rstrip(".")
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


# --------------------------------------------------------------------------
# rate limiting
# --------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe minimum-interval gate for polite crawling."""

    def __init__(self, requests_per_second: float = 3.0):
        if requests_per_second <= 0:
            raise ReconError("requests_per_second must be > 0",
                             code="invalid_rate")
        self._interval = 1.0 / float(requests_per_second)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> float:
        """Block until a request may proceed. Returns seconds slept."""
        with self._lock:
            now = time.monotonic()
            delay = self._next_allowed - now
            if delay > 0:
                time.sleep(delay)
                self._next_allowed = now + delay + self._interval
                return delay
            self._next_allowed = now + self._interval
            return 0.0

    @property
    def requests_per_second(self) -> float:
        return 1.0 / self._interval


# --------------------------------------------------------------------------
# audit log (append-only)
# --------------------------------------------------------------------------

_DEFAULT_SESSIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")


def audit(session_id: str, action: str, detail: str = "",
          base_dir: str | None = None) -> dict:
    """Append {ts, action, detail} to sessions/<sid>/audit.log. Detail is redacted."""
    if not session_id or not action:
        raise ReconError("session_id and action are required", code="invalid_audit")
    root = os.path.abspath(base_dir or _DEFAULT_SESSIONS_DIR)
    sdir = safe_join(root, str(session_id))
    os.makedirs(sdir, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": redact(detail),
    }
    import json
    with open(os.path.join(sdir, "audit.log"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


# --------------------------------------------------------------------------
# path safety
# --------------------------------------------------------------------------

def safe_join(base: str, *parts: str) -> str:
    """Join paths and raise ReconError if the result escapes `base`."""
    base_abs = os.path.abspath(base)
    target = os.path.abspath(os.path.join(base_abs, *parts))
    if os.path.commonpath([base_abs, target]) != base_abs:
        raise ReconError(f"path traversal blocked: {parts!r} escapes {base_abs}",
                         code="path_traversal",
                         hint="Session file writes must stay inside the session dir.")
    return target


# --------------------------------------------------------------------------
# sensitive source paths (prompt-injection defense for recon_analyze_source)
# --------------------------------------------------------------------------

_SENSITIVE_PATH_PARTS = (
    ".ssh", ".aws", ".gnupg", ".pki", ".docker",
)

_SENSITIVE_PATH_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".jks",
)

_SENSITIVE_PATH_NAMES = frozenset({
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "credentials", "secrets",
})


def sensitive_path_blocked(path: str) -> str | None:
    """Return a refusal reason if `path` is credential-bearing, else None.

    Guards recon_analyze_source against prompt-injected paths ("analyze
    ~/.ssh for API keys") — page/repo content is untrusted data and must not
    steer the agent into credential stores.
    """
    expanded = os.path.expanduser(path.strip())
    norm = os.path.abspath(expanded)
    parts = norm.split(os.sep)
    base = os.path.basename(norm).lower()
    if any(p in _SENSITIVE_PATH_PARTS for p in parts):
        return (f"path {path!r} is inside a credential store; "
                "refusing to analyze")
    if base in _SENSITIVE_PATH_NAMES or any(
            base.endswith(s) for s in _SENSITIVE_PATH_SUFFIXES):
        return (f"path {path!r} looks like a private key/credential file; "
                "refusing to analyze")
    return None
