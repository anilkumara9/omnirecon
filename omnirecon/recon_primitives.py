"""Shared recon logic for the xray MCP server.

All functions are defensive: timeouts everywhere, per-target try/except,
bounded output. Nothing here raises on a hostile or dead target — it
returns {"error": ...} instead.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
import tldextract
from bs4 import BeautifulSoup


def _sanitize_no_proxy_env() -> None:
    """Drop bracketed IPv6 literals (e.g. ``[::1]``) from no_proxy/NO_PROXY.

    Some environments export no_proxy with bracketed IPv6 literals; httpx's
    env-proxy parser chokes on them (``Invalid port: ':1]'``) and *every*
    fetch then fails. Bracketed entries are unusable for httpx matching
    anyway, so removing them is strictly safer than leaving them. Runs at
    import time so it covers the MCP server, the CLI, and library users.
    """
    for var in ("no_proxy", "NO_PROXY"):
        raw = os.environ.get(var)
        if not raw or "[" not in raw:
            continue
        kept = [p.strip() for p in raw.split(",") if "[" not in p and "]" not in p]
        os.environ[var] = ",".join(p for p in kept if p)


_sanitize_no_proxy_env()

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) XRay-Recon/1.0 Chrome/126.0 Safari/537.36"
)

_SKIP_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm",
    ".mp3", ".wav", ".pdf", ".zip",
)


# --------------------------------------------------------------------------
# low-level helpers
# --------------------------------------------------------------------------

def _client(timeout: float = 20.0) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": UA, "Accept": "*/*"},
        follow_redirects=True,
        timeout=timeout,
    )


def registrable_domain(host: str | None) -> str:
    if not host:
        return ""
    ext = tldextract.extract(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _forms(soup: BeautifulSoup) -> list[dict]:
    out = []
    for f in soup.find_all("form")[:25]:
        inputs = []
        for i in f.find_all(["input", "select", "textarea"])[:30]:
            inputs.append(
                {"name": i.get("name"), "type": i.get("type", "text"), "tag": i.name}
            )
        out.append(
            {
                "action": f.get("action"),
                "method": (f.get("method") or "GET").upper(),
                "inputs": inputs,
            }
        )
    return out


# --------------------------------------------------------------------------
# tech fingerprinting
# --------------------------------------------------------------------------

def fingerprint_tech(html: str, headers: dict, scripts: list[str]) -> list[dict]:
    """Heuristic framework / platform / infra detection with evidence."""
    h = {k.lower(): v for k, v in headers.items()}
    blob = html[:400000]
    js = " ".join(scripts)
    found: list[dict] = []

    def add(name: str, evidence: str):
        if not any(f["tech"] == name for f in found):
            found.append({"tech": name, "evidence": evidence})

    checks = [
        ("Next.js", "__NEXT_DATA__" in blob, "__NEXT_DATA__ JSON in HTML"),
        ("Next.js", "_next/static" in blob or "_next/static" in js, "_next/static asset path"),
        ("Nuxt.js", "__NUXT__" in blob, "__NUXT__ state in HTML"),
        ("Nuxt.js", "/_nuxt/" in blob or "/_nuxt/" in js, "/_nuxt/ asset path"),
        ("Gatsby", "___gatsby" in blob, "___gatsby marker"),
        ("Remix", "__remixManifest" in blob, "__remixManifest in HTML"),
        ("Angular", "ng-version" in blob, "ng-version attribute"),
        ("Vue.js", "__vue__" in blob or "data-v-" in blob, "Vue markers in DOM"),
        ("Svelte", "svelte-" in blob, "svelte- CSS scoping markers"),
        ("React (SPA)", 'id="root"' in blob and ("react" in js.lower() or "react" in blob.lower()[:2000]), "root div + react bundle"),
        ("WordPress", "wp-content" in blob or "wp-content" in js, "wp-content paths"),
        ("WordPress", "/wp-json/" in blob, "wp-json REST endpoint referenced"),
        ("Shopify", "cdn.shopify" in blob or "cdn.shopify" in js, "Shopify CDN"),
        ("Webflow", "webflow" in blob.lower() and "assets.website-files.com" in blob, "Webflow assets"),
        ("Wix", "wixstatic.com" in blob or "wix.com" in js, "Wix static host"),
        ("Squarespace", "squarespace" in blob.lower(), "Squarespace markers"),
        ("Ghost", "ghost-" in blob and "content/images" in blob, "Ghost content paths"),
        ("Django", "csrftoken" in str(h), "csrftoken cookie (Django)"),
        ("Laravel", "laravel_session" in str(h), "laravel_session cookie"),
        ("Ruby on Rails", "_rails" in str(h).lower() or 'csrf-param' in blob, "Rails markers"),
        ("PHP", h.get("x-powered-by", "").lower().startswith("php"), f"x-powered-by: {h.get('x-powered-by')}"),
        ("ASP.NET", "asp.net" in h.get("x-powered-by", "").lower() or "__viewstate" in blob, "ASP.NET markers"),
        ("Cloudflare", "cloudflare" in h.get("server", "").lower() or "cf-ray" in h, "Cloudflare headers"),
        ("Vercel", "vercel" in h.get("server", "").lower() or "x-vercel-id" in h, "Vercel headers"),
        ("Netlify", "netlify" in h.get("server", "").lower(), "Netlify server header"),
        ("Fastly", "fastly" in h.get("via", "").lower() or "x-served-by" in h and "cache-" in h.get("x-served-by", ""), "Fastly cache headers"),
        ("Akamai", "akamaighost" in h.get("server", "").lower(), "Akamai server header"),
        ("AWS CloudFront", "cloudfront" in h.get("via", "").lower(), "CloudFront via header"),
        ("Google Frontend", "gws" in h.get("server", "").lower() or "sffe" in h.get("server", "").lower(), "Google server header"),
        ("nginx", h.get("server", "").lower().startswith("nginx"), f"server: {h.get('server')}"),
        ("Apache", h.get("server", "").lower().startswith("apache"), f"server: {h.get('server')}"),
    ]
    for name, cond, ev in checks:
        if cond:
            add(name, ev)
    if not found:
        add("Unknown / custom stack", "no known framework markers matched")
    return found


# --------------------------------------------------------------------------
# platform_scan
# --------------------------------------------------------------------------

def _tls_info(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        return {
            "subject_cn": subj.get("commonName"),
            "issuer": iss.get("organizationName") or iss.get("commonName"),
            "expires": cert.get("notAfter"),
            "san_count": len(cert.get("subjectAltName", [])),
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def platform_scan(url: str) -> dict:
    out: dict = {"target": url}
    t0 = time.time()
    try:
        with _client() as c:
            r = c.get(url)
    except Exception as e:
        return {"target": url, "error": f"fetch failed: {e!s}"[:300]}

    out["status"] = r.status_code
    out["final_url"] = str(r.url)
    out["redirect_chain"] = [str(h.url) for h in r.history]
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    out["content_type"] = r.headers.get("content-type")
    out["content_bytes"] = len(r.content)

    hdrs = dict(r.headers)
    keep = ["server", "x-powered-by", "via", "x-aspnet-version", "x-generator"]
    out["server_headers"] = {k: v for k, v in hdrs.items() if k.lower() in keep}
    sec = [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
    ]
    hl = {k.lower(): v for k, v in hdrs.items()}
    out["security_headers"] = {h: (hl.get(h) or "MISSING") for h in sec}
    try:
        out["cookies"] = [c.split("=", 1)[0] for c in hl.get("set-cookie", [])] \
            if isinstance(hl.get("set-cookie"), list) else []
    except Exception:
        out["cookies"] = []
    # httpx stores set-cookie as comma-joined sometimes; parse raw too
    raw_cookies = r.headers.get_list("set-cookie", []) if hasattr(r.headers, "get_list") else []
    out["cookies"] = [c.split("=", 1)[0].strip() for c in raw_cookies]

    u = urlparse(str(r.url))
    if u.scheme == "https" and u.hostname:
        out["tls"] = _tls_info(u.hostname)

    base = f"{u.scheme}://{u.netloc}"
    out["robots_txt"] = _robots(base)
    out["sitemap"] = _sitemap(base)

    if "html" in (r.headers.get("content-type") or ""):
        html = r.text
        soup = _soup(html)
        out["title"] = soup.title.string.strip() if soup.title and soup.title.string else None
        gen = soup.find("meta", attrs={"name": "generator"})
        out["meta_generator"] = gen.get("content") if gen else None
        scripts = [s.get("src") for s in soup.find_all("script", src=True)]
        out["script_tags"] = len(soup.find_all("script"))
        out["external_scripts"] = scripts[:40]
        out["stylesheet_count"] = len(soup.find_all("link", rel="stylesheet"))
        out["image_count"] = len(soup.find_all("img"))
        out["forms"] = _forms(soup)
        out["tech"] = fingerprint_tech(html, hdrs, scripts)
    else:
        out["note"] = "non-HTML response; page-structure analysis skipped"
    return out


def _robots(base: str) -> dict:
    try:
        with _client(timeout=10) as c:
            r = c.get(base + "/robots.txt")
        if r.status_code != 200 or len(r.content) > 300_000:
            return {"present": False}
        lines = r.text.splitlines()
        return {
            "present": True,
            "disallow_rules": sum(1 for l in lines if l.strip().lower().startswith("disallow:")),
            "allow_rules": sum(1 for l in lines if l.strip().lower().startswith("allow:")),
            "sitemaps": [l.split(":", 1)[1].strip() for l in lines
                         if l.strip().lower().startswith("sitemap:")][:10],
        }
    except Exception:
        return {"present": False}


def _sitemap(base: str) -> dict:
    try:
        with _client(timeout=15) as c:
            r = c.get(base + "/sitemap.xml")
        if r.status_code != 200 or len(r.content) > 5_000_000:
            return {"present": False}
        txt = r.text
        locs = len(re.findall(r"<loc>", txt))
        is_index = "<sitemapindex" in txt[:2000]
        return {"present": True, "is_index": is_index,
                "url_count": locs if not is_index else 0,
                "sitemap_count": locs if is_index else 0}
    except Exception:
        return {"present": False}

# --------------------------------------------------------------------------
# endpoint / API-surface extraction from JS + HTML text
# --------------------------------------------------------------------------

_QUOTED_URL = re.compile(
    r"""['"`](\/?[A-Za-z0-9_\-\.\/\?\#\=\&\%\:\+\@]+)['"`]"""
)
_FETCH_CALL = re.compile(r"""\bfetch\s*\(\s*['"`]([^'"`]+)['"`]""")
_AXIOS_CALL = re.compile(r"""\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]""")
_AJAX_URL = re.compile(r"""\burl\s*:\s*['"`]([^'"`\/][^'"`]*|/[^\s'"`]+)['"`]""")
_WS_NEW = re.compile(r"""\bnew\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""")
_ES_NEW = re.compile(r"""\bnew\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]""")
_GQL_OP = re.compile(r"""\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)""")


def _classify_endpoint(s: str, base_reg: str, strict: bool = False) -> dict | None:
    s = s.strip()
    if len(s) < 2 or len(s) > 400:
        return None
    if " " in s or "\n" in s:
        return None
    low = s.lower()
    if low.endswith(_SKIP_EXTS):
        return None
    # skip MIME types like "text/css", "application/json"
    if re.fullmatch(r"[a-z0-9]+/[a-z0-9.+\-]+", low):
        return None
    if not ("/" in s or s.startswith(("http://", "https://", "ws://", "wss://"))):
        return None
    # protocol-relative URLs (//host/path) are absolute
    is_abs = bool(re.match(r"^(https?|wss?|ftp):", low) or low.startswith("//"))
    if strict and not (is_abs or s.startswith("/")):
        # generic quoted-string sweep: only real paths / absolute URLs.
        # (Bare "api/users" shapes come only from fetch()/axios() patterns,
        # which call with strict=False.)
        return None
    if not is_abs and not s.startswith("/"):
        # bare "api/users" style path
        if not re.match(r"^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-\.\?\#\=\&\%]+)+$", s):
            return None
    if is_abs:
        parsed = urlparse(s if "://" in s else "https:" + s)
        # skip bare origins with no path — low signal
        if not parsed.path or parsed.path == "/":
            return None
        host = parsed.hostname or ""
        scope = "internal" if registrable_domain(host) == base_reg else "external"
    else:
        scope = "internal"
    kind = "other"
    if low.startswith(("ws://", "wss://")):
        kind = "websocket"
    elif any(k in low for k in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql",
                                "/rest/", ".php?", "/trpc/", "/query")):
        kind = "api"
    return {"endpoint": s, "kind": kind, "scope": scope}


def extract_endpoints_from_text(text: str, base_url: str = "") -> dict:
    base_reg = registrable_domain(urlparse(base_url).hostname) if base_url else ""
    found: dict[str, dict] = {}

    def add(s: str):
        e = _classify_endpoint(s, base_reg)
        if e and e["endpoint"] not in found:
            found[e["endpoint"]] = e

    for m in _FETCH_CALL.finditer(text):
        add(m.group(1))
    for m in _AXIOS_CALL.finditer(text):
        add(m.group(1))
    for m in _WS_NEW.finditer(text):
        add(m.group(1))
    for m in _ES_NEW.finditer(text):
        add(m.group(1))
    for m in _QUOTED_URL.finditer(text[:1_000_000]):
        e = _classify_endpoint(m.group(1), base_reg, strict=True)
        if e and e["endpoint"] not in found:
            found[e["endpoint"]] = e
    gql_ops = sorted(set(_GQL_OP.findall(text[:500_000])))

    internal = [f for f in found.values() if f["scope"] == "internal"]
    external = [f for f in found.values() if f["scope"] == "external"]
    key = lambda e: (0 if e["kind"] == "api" else 1 if e["kind"] == "websocket" else 2, e["endpoint"])
    return {
        "internal": sorted(internal, key=key),
        "external": sorted(external, key=key)[:100],
        "graphql_operations": gql_ops[:50],
        "total_unique": len(found),
    }


def extract_api_surface(url: str, max_js_files: int = 12, max_js_bytes: int = 1_500_000) -> dict:
    """Fetch a page + its same-origin JS bundles, extract every API-ish endpoint."""
    out: dict = {"target": url}
    try:
        with _client() as c:
            r = c.get(url)
    except Exception as e:
        return {"target": url, "error": f"fetch failed: {e!s}"[:300]}
    if "html" not in (r.headers.get("content-type") or ""):
        return {"target": url, "error": "target is not an HTML page"}

    html = r.text
    soup = _soup(html)
    base_reg = registrable_domain(urlparse(str(r.url)).hostname)
    merged: dict[str, dict] = {}
    gql: set[str] = set()

    def absorb(text: str):
        res = extract_endpoints_from_text(text, str(r.url))
        for e in res["internal"] + res["external"]:
            merged.setdefault(e["endpoint"], e)
        gql.update(res["graphql_operations"])

    absorb(html)  # inline scripts + HTML attributes

    js_urls: list[str] = []
    for s in soup.find_all("script", src=True):
        src = urljoin(str(r.url), s["src"])
        h = urlparse(src).hostname or ""
        if registrable_domain(h) == base_reg and src not in js_urls:
            js_urls.append(src)
    out["js_bundles_found"] = len(js_urls)
    fetched = 0
    with _client(timeout=25) as c:
        for js in js_urls[:max_js_files]:
            try:
                jr = c.get(js)
                if jr.status_code == 200 and len(jr.content) <= max_js_bytes:
                    absorb(jr.text[:2_000_000])
                    fetched += 1
            except Exception:
                continue
    out["js_bundles_analyzed"] = fetched

    internal = [e for e in merged.values() if e["scope"] == "internal"]
    external = [e for e in merged.values() if e["scope"] == "external"]
    key = lambda e: (0 if e["kind"] == "api" else 1 if e["kind"] == "websocket" else 2, e["endpoint"])
    out["internal_endpoints"] = sorted(internal, key=key)[:300]
    out["external_endpoints"] = sorted(external, key=key)[:100]
    out["graphql_operations"] = sorted(gql)[:50]
    out["total_unique"] = len(merged)
    return out


# --------------------------------------------------------------------------
# site crawler
# --------------------------------------------------------------------------

def crawl_site(start_url: str, max_pages: int = 30, max_depth: int = 2) -> dict:
    base_host = urlparse(start_url).hostname or ""
    base_reg = registrable_domain(base_host)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    pages: list[dict] = []
    api_index: dict[str, dict] = {}
    js_bundles: list[str] = []

    with _client(timeout=20) as c:
        while queue and len(pages) < max_pages:
            url, depth = queue.pop(0)
            url, _ = urldefrag(url)
            if url in seen or depth > max_depth:
                continue
            seen.add(url)
            try:
                r = c.get(url)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            if "html" not in (r.headers.get("content-type") or ""):
                continue
            soup = _soup(r.text)
            title = soup.title.string.strip() if soup.title and soup.title.string else None

            links: set[str] = set()
            for a in soup.find_all("a", href=True):
                absu, _ = urldefrag(urljoin(str(r.url), a["href"]))
                h = urlparse(absu).hostname or ""
                if (urlparse(absu).scheme in ("http", "https")
                        and registrable_domain(h) == base_reg
                        and absu not in seen):
                    links.add(absu)

            # same-origin JS bundles: the API surface usually lives here
            for s in soup.find_all("script", src=True):
                src = urljoin(str(r.url), s["src"])
                h = urlparse(src).hostname or ""
                if (registrable_domain(h) == base_reg
                        and src not in js_bundles
                        and len(js_bundles) < 24):
                    js_bundles.append(src)

            eps = extract_endpoints_from_text(r.text, str(r.url))
            for e in eps["internal"]:
                api_index.setdefault(e["endpoint"], e)

            pages.append({
                "url": str(r.url),
                "depth": depth,
                "title": title,
                "internal_links": len(links),
                "forms": _forms(soup),
                "api_hits_on_page": len(eps["internal"]),
            })
            if depth < max_depth:
                for l in sorted(links)[:60]:
                    queue.append((l, depth + 1))
            time.sleep(0.15)

        # JS bundle pass: fetch discovered bundles, extract API endpoints
        js_analyzed = 0
        for js in js_bundles[:12]:
            try:
                jr = c.get(js, timeout=25)
                if jr.status_code == 200 and len(jr.content) <= 1_500_000:
                    eps = extract_endpoints_from_text(jr.text[:2_000_000], js)
                    for e in eps["internal"] + eps["external"]:
                        # API-kind findings from JS win over page-text guesses
                        prev = api_index.get(e["endpoint"])
                        if prev is None or (prev.get("kind") != "api"
                                            and e.get("kind") == "api"):
                            api_index[e["endpoint"]] = e
                    js_analyzed += 1
            except Exception:
                continue
            time.sleep(0.1)

    key = lambda e: (0 if e["kind"] == "api" else 1, e["endpoint"])
    return {
        "start": start_url,
        "pages_crawled": len(pages),
        "unique_internal_api_endpoints": len(api_index),
        "api_endpoints": sorted(api_index.values(), key=key)[:300],
        "pages": pages,
        "js_bundles_found": len(js_bundles),
        "js_bundles_analyzed": js_analyzed,
    }


# --------------------------------------------------------------------------
# DNS recon (+ passive subdomain enum via crt.sh)
# --------------------------------------------------------------------------

def dns_recon(domain: str) -> dict:
    import dns.resolver
    domain = domain.strip().lower().split("/")[0]
    out: dict = {"domain": domain}
    res = dns.resolver.Resolver()
    res.lifetime = 8
    res.timeout = 5
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
        try:
            ans = res.resolve(domain, rtype)
            out[rtype.lower()] = sorted({str(rr).strip('"') for rr in ans})
        except Exception:
            # Fallback: DNS-over-HTTPS (works behind HTTP proxies / blocked UDP)
            out[rtype.lower()] = _doh_lookup(domain, rtype)
    out["subdomains"] = _crtsh_subdomains(domain)
    return out


def _doh_lookup(domain: str, rtype: str) -> list[str]:
    """DNS-over-HTTPS fallback via Cloudflare / Google JSON APIs."""
    for base in ("https://cloudflare-dns.com/dns-query",
                 "https://dns.google/resolve"):
        try:
            with _client(timeout=12) as c:
                r = c.get(base, params={"name": domain, "type": rtype},
                          headers={"Accept": "application/dns-json"})
            if r.status_code != 200:
                continue
            data = r.json()
            vals = sorted({a.get("data", "").strip('"')
                           for a in data.get("Answer", [])
                           if a.get("data")})
            if vals:
                return vals
        except Exception:
            continue
    return []


def _crtsh_subdomains(domain: str, cap: int = 150) -> list[str]:
    try:
        with _client(timeout=25) as c:
            r = c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.status_code != 200:
            return []
        data = r.json()
        subs: set[str] = set()
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name)
                if len(subs) >= cap:
                    break
        return sorted(subs)
    except Exception:
        return []


# --------------------------------------------------------------------------
# codebase / repo architecture analysis
# --------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript", ".go": "Go", ".rs": "Rust", ".java": "Java",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".cpp": "C++", ".c": "C",
    ".h": "C/C++", ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
    ".sh": "Shell", ".sql": "SQL", ".html": "HTML", ".css": "CSS",
    ".vue": "Vue", ".svelte": "Svelte", ".dart": "Dart", ".lua": "Lua",
}

_ROUTE_PATTERNS = [
    (re.compile(r"""\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]"""), "express/fastapi-style"),
    (re.compile(r"""@(?:app|router|blueprint)\s*\.\s*(?:get|post|put|patch|delete|route)\s*\(\s*['"`]([^'"`]+)['"`]"""), "flask/fastapi decorator"),
    (re.compile(r"""\bpath\s*\(\s*['"`]([^'"`]+)['"`]"""), "django path()"),
    (re.compile(r"""\b(?:Get|Post|Put|Delete|Patch)\s*\(\s*["`]([^"`]+)["`]"""), "go/aspnet attribute"),
]


def analyze_codebase(target: str) -> dict:
    workdir = None
    try:
        if target.startswith(("http://", "https://")):
            workdir = tempfile.mkdtemp(prefix="xray_repo_")
            cp = subprocess.run(
                ["git", "clone", "--depth", "1", target, workdir],
                capture_output=True, text=True, timeout=180,
            )
            if cp.returncode != 0:
                return {"target": target, "error": f"git clone failed: {cp.stderr[:300]}"}
            root = workdir
        else:
            root = os.path.abspath(os.path.expanduser(target))
            if not os.path.isdir(root):
                return {"target": target, "error": "directory does not exist"}
    except Exception as e:
        return {"target": target, "error": str(e)[:300]}

    try:
        return _analyze_tree(root, target)
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def _analyze_tree(root: str, target: str) -> dict:
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "dist", "build", ".next", "target", "vendor", ".idea", ".vscode"}
    lang_files: dict[str, int] = {}
    lang_loc: dict[str, int] = {}
    total_files = 0
    route_hits: list[dict] = []
    interesting: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for fn in filenames:
            total_files += 1
            ext = os.path.splitext(fn)[1].lower()
            lang = _LANG_BY_EXT.get(ext)
            fpath = os.path.join(dirpath, fn)
            rel = os.path.relpath(fpath, root)
            if lang:
                lang_files[lang] = lang_files.get(lang, 0) + 1
                try:
                    if os.path.getsize(fpath) < 500_000:
                        with open(fpath, "r", errors="ignore") as fh:
                            loc = sum(1 for _ in fh)
                        lang_loc[lang] = lang_loc.get(lang, 0) + loc
                except Exception:
                    pass
            # route grep on plausible source files
            if ext in (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php") \
                    and len(route_hits) < 80:
                try:
                    if os.path.getsize(fpath) < 500_000:
                        with open(fpath, "r", errors="ignore") as fh:
                            text = fh.read()
                        for pat, style in _ROUTE_PATTERNS:
                            for m in pat.finditer(text):
                                route = m.group(1)
                                if route and len(route) < 120 and " " not in route:
                                    route_hits.append(
                                        {"route": route, "style": style, "file": rel})
                                    if len(route_hits) >= 80:
                                        break
                except Exception:
                    pass
            ln = fn.lower()
            if ln in ("dockerfile", "docker-compose.yml", "docker-compose.yaml",
                      "makefile", "readme.md") or "page." in ln or "route." in ln:
                if len(interesting) < 40:
                    interesting.append(rel)

    languages = sorted(
        ({"language": l, "files": lang_files[l], "loc": lang_loc.get(l, 0)}
         for l in lang_files),
        key=lambda d: -d["files"],
    )[:15]

    out: dict = {
        "target": target,
        "total_files": total_files,
        "languages": languages,
        "routes_found": len(route_hits),
        "routes": route_hits[:80],
        "key_files": interesting,
    }
    out["manifests"] = _read_manifests(root)
    out["framework_guess"] = _guess_framework(out["manifests"], languages, route_hits)
    out["readme_head"] = _readme_head(root)
    out["entry_points"] = _entry_points(root)
    return out


def _read_json(path: str, cap: int = 200_000) -> dict | None:
    try:
        if os.path.getsize(path) > cap:
            return None
        with open(path, "r", errors="ignore") as fh:
            return json.load(fh)
    except Exception:
        return None


def _read_lines(path: str, cap: int = 100_000, n: int = 80) -> list[str]:
    try:
        if os.path.getsize(path) > cap:
            return []
        with open(path, "r", errors="ignore") as fh:
            return [l.strip() for l in fh if l.strip()][:n]
    except Exception:
        return []


def _read_manifests(root: str) -> dict:
    m: dict = {}
    pj = _read_json(os.path.join(root, "package.json"))
    if pj:
        deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
        m["node"] = {"dependencies": sorted(deps)[:60],
                     "scripts": list((pj.get("scripts") or {}).keys())[:20]}
    req = os.path.join(root, "requirements.txt")
    if os.path.exists(req):
        m["python_requirements"] = _read_lines(req)
    for name in ("pyproject.toml", "setup.py", "Pipfile"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            m[name] = _read_lines(p, n=40)
            break
    gm = os.path.join(root, "go.mod")
    if os.path.exists(gm):
        m["go.mod"] = _read_lines(gm, n=40)
    ct = os.path.join(root, "Cargo.toml")
    if os.path.exists(ct):
        m["cargo"] = _read_lines(ct, n=40)
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            m["jvm"] = {"build_file": name}
            break
    for name in ("Gemfile", "composer.json"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            m[name] = _read_lines(p, n=40)
            break
    df = os.path.join(root, "Dockerfile")
    if os.path.exists(df):
        m["dockerfile_head"] = _read_lines(df, n=25)
    return m


def _guess_framework(manifests: dict, languages: list[dict], routes: list[dict]) -> list[str]:
    guesses: list[str] = []
    node_deps = (manifests.get("node") or {}).get("dependencies", [])
    py_req = " ".join(manifests.get("python_requirements", [])).lower()
    if any(d.startswith("next") for d in node_deps):
        guesses.append("Next.js")
    if "react" in node_deps:
        guesses.append("React")
    if "vue" in node_deps:
        guesses.append("Vue")
    if any(d.startswith("@angular/") for d in node_deps):
        guesses.append("Angular")
    if "express" in node_deps:
        guesses.append("Express")
    if any(d.startswith("@nestjs/") for d in node_deps):
        guesses.append("NestJS")
    if "django" in py_req:
        guesses.append("Django")
    if "flask" in py_req:
        guesses.append("Flask")
    if "fastapi" in py_req:
        guesses.append("FastAPI")
    if manifests.get("go.mod"):
        guesses.append("Go service")
    if manifests.get("cargo"):
        guesses.append("Rust service")
    if not guesses and languages:
        guesses.append(f"{languages[0]['language']}-first codebase (no known framework manifest)")
    return guesses


def _readme_head(root: str) -> str:
    for name in ("README.md", "readme.md", "README.txt"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            lines = _read_lines(p, n=30)
            return "\n".join(lines)[:2000]
    return ""


def _entry_points(root: str) -> list[str]:
    cands = ["src/index.ts", "src/index.js", "src/main.ts", "src/main.py",
             "index.js", "index.ts", "main.py", "app.py", "server.js",
             "cmd", "src/main.go", "Main.java", "manage.py"]
    return [c for c in cands if os.path.exists(os.path.join(root, c))]


# --------------------------------------------------------------------------
# raw HTTP prober
# --------------------------------------------------------------------------

def http_probe(url: str, method: str = "GET", headers: dict | None = None,
               body: str = "") -> dict:
    method = (method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {"url": url, "error": f"unsupported method {method}"}
    try:
        with _client(timeout=20) as c:
            r = c.request(method, url, headers=headers or {},
                          content=body.encode() if body else None)
        ctype = r.headers.get("content-type", "")
        out: dict = {
            "url": str(r.url),
            "status": r.status_code,
            "redirect_chain": [str(h.url) for h in r.history],
            "response_headers": dict(r.headers),
            "content_bytes": len(r.content),
        }
        if "json" in ctype and len(r.content) < 200_000:
            try:
                out["json_body"] = r.json()
            except Exception:
                out["text_head"] = r.text[:3000]
        else:
            out["text_head"] = r.text[:3000]
        return out
    except Exception as e:
        return {"url": url, "error": f"probe failed: {e!s}"[:300]}


# --------------------------------------------------------------------------
# live traffic capture (headless browser) — the SPA API-surface killer
# --------------------------------------------------------------------------

def capture_live_traffic(url: str, wait_ms: int = 6000) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"error": "playwright is not installed in the MCP venv"}
    reqs: list[dict] = []
    console_errors: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=UA)
            statuses: dict[str, int] = {}

            def on_req(req):
                if req.resource_type in ("xhr", "fetch", "websocket", "document"):
                    reqs.append({"method": req.method, "url": req.url,
                                 "type": req.resource_type})

            def on_resp(resp):
                try:
                    statuses[resp.url] = resp.status
                except Exception:
                    pass

            def on_console(msg):
                if msg.type == "error" and len(console_errors) < 20:
                    console_errors.append(msg.text[:300])

            page.on("request", on_req)
            page.on("response", on_resp)
            page.on("console", on_console)
            page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_timeout(max(1000, min(wait_ms, 25_000)))
            title = page.title()
            browser.close()
    except Exception as e:
        return {"target": url, "error": f"browser capture failed: {e!s}"[:400]}

    for r in reqs:
        r["status"] = statuses.get(r["url"])
    api = [r for r in reqs
           if r["type"] in ("xhr", "fetch", "websocket")
           or "/api" in r["url"] or "/graphql" in r["url"]]
    return {
        "target": url,
        "page_title": title,
        "requests_captured": len(reqs),
        "api_requests": api[:250],
        "console_errors": console_errors,
    }
