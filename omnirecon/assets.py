"""Lane C — asset inventory.

`inventory(session_id, url) -> dict`

Fetches the page + its stylesheets and inventories:
  - images (src, alt, width/height attrs — dimensions only when cheap,
    i.e. from attributes; no image downloads)
  - fonts (@font-face families + urls from CSS)
  - icons / favicons
  - inline SVG count
  - design tokens: CSS custom properties (--*), top-12 color palette,
    font-family stacks

Saves a JSON artifact to sessions/<sid>/artifacts/assets.json and records
findings in the session evidence ledger (via omnirecon.source_intel's
ledger helper — same fallback semantics).

Classification: each asset is INFERRED unless its URL was fetched with
HTTP 200 (cheap HEAD verification, bounded), in which case OBSERVED.
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omnirecon.source_intel import _ledger_append, _utcnow, REPO_ROOT  # noqa: E402

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) XRay-Recon/1.0 Chrome/126.0 Safari/537.36")
_MAX_CSS_FILES = 10
_MAX_CSS_BYTES = 1_000_000
_MAX_VERIFY = 60
_VERIFY_TIMEOUT = 6.0

_FONT_FACE_RE = re.compile(r"@font-face\s*\{([^}]*)\}", re.IGNORECASE)
_FONT_FAMILY_RE = re.compile(
    r"font-family\s*:\s*([^;}{]+)", re.IGNORECASE)
_FONT_SRC_URL_RE = re.compile(r"url\(\s*['\"]?([^'\"\)]+)['\"]?\s*\)",
                              re.IGNORECASE)
_CUSTOM_PROP_RE = re.compile(r"--([\w-]+)\s*:\s*([^;}{]+);")
_HEX_COLOR_RE = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b")
_DECL_FONT_FAMILY_RE = re.compile(r"font-family\s*:\s*([^;}{]+);",
                                  re.IGNORECASE)


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _abs(base: str, ref: str | None) -> str | None:
    if not ref:
        return None
    ref = ref.strip()
    if ref.startswith("data:"):
        return None
    return urljoin(base, ref)


def _parse_css(css_text: str, css_url: str) -> dict:
    """Pure CSS parser: fonts, custom props, colors, font stacks."""
    fonts: list[dict] = []
    for m in _FONT_FACE_RE.finditer(css_text):
        block = m.group(1)
        fam = _FONT_FAMILY_RE.search(block)
        urls = _FONT_SRC_URL_RE.findall(block)
        fonts.append({
            "family": fam.group(1).strip().strip("\"'") if fam else None,
            "urls": [u for u in urls if not u.startswith("data:")][:6],
            "from_css": css_url,
        })
    props: dict[str, str] = {}
    for m in _CUSTOM_PROP_RE.finditer(css_text):
        name, val = m.group(1), m.group(2).strip()
        if name not in props and len(props) < 500:
            props[name] = val[:200]
    color_counts: dict[str, int] = {}
    for m in _HEX_COLOR_RE.finditer(css_text):
        c = "#" + m.group(1).lower()
        # normalize 3-digit to 6-digit
        if len(c) == 4:
            c = "#" + "".join(ch * 2 for ch in c[1:])
        color_counts[c] = color_counts.get(c, 0) + 1
    palette = sorted(color_counts.items(), key=lambda kv: -kv[1])[:12]
    stacks: dict[str, int] = {}
    for m in _DECL_FONT_FAMILY_RE.finditer(css_text):
        stack = m.group(1).strip()
        if len(stack) < 200:
            stacks[stack] = stacks.get(stack, 0) + 1
    return {
        "font_faces": fonts,
        "custom_properties": props,
        "color_palette": [{"color": c, "uses": n} for c, n in palette],
        "font_stacks": sorted(stacks, key=lambda s: -stacks[s])[:15],
    }


def _verify_url(client: httpx.Client, url: str) -> bool:
    """Cheap existence check: HEAD, falling back to a 1-byte ranged GET."""
    try:
        r = client.head(url, timeout=_VERIFY_TIMEOUT)
        if r.status_code == 200:
            return True
        if r.status_code in (405, 501):
            rg = client.get(url, headers={"Range": "bytes=0-0"},
                            timeout=_VERIFY_TIMEOUT)
            return rg.status_code in (200, 206)
        return False
    except Exception:
        return False


def inventory(session_id: str, url: str) -> dict:
    """Inventory a page's assets. Returns JSON-serializable dict; saves
    sessions/<sid>/artifacts/assets.json; records ledger findings."""
    out: dict = {"session_id": session_id, "target": url}
    session_dir = os.path.join(REPO_ROOT, "sessions", session_id)
    artifacts_dir = os.path.join(session_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    client = httpx.Client(
        headers={"User-Agent": UA, "Accept": "*/*"},
        follow_redirects=True, timeout=20.0)
    try:
        try:
            r = client.get(url)
        except Exception as e:
            return {"session_id": session_id, "target": url,
                    "error": f"page fetch failed: {e!s}"[:300]}
        page_ok = r.status_code == 200
        out["page_status"] = r.status_code
        out["final_url"] = str(r.url)
        base = str(r.url)
        if "html" not in (r.headers.get("content-type") or ""):
            out["note"] = "non-HTML response; asset analysis skipped"
            return out

        soup = _soup(r.text)

        # ---- images ----
        images: list[dict] = []
        seen_srcs: set[str] = set()
        for img in soup.find_all("img"):
            src = _abs(base, img.get("src"))
            if not src or src in seen_srcs:
                continue
            seen_srcs.add(src)
            images.append({
                "src": src,
                "alt": img.get("alt"),
                "width": img.get("width"),
                "height": img.get("height"),
                "loading": img.get("loading"),
            })
        # <source srcset> / <img srcset>
        for tag in soup.find_all(["source", "img"]):
            ss = tag.get("srcset")
            if ss:
                first = ss.split(",")[0].strip().split(" ")[0]
                src = _abs(base, first)
                if src and src not in seen_srcs:
                    seen_srcs.add(src)
                    images.append({"src": src, "alt": None, "width": None,
                                   "height": None, "loading": None,
                                   "from": "srcset"})

        # ---- favicons / icons ----
        icons: list[dict] = []
        for link in soup.find_all("link", rel=True):
            rel = " ".join(link.get("rel", [])).lower()
            if "icon" in rel:
                href = _abs(base, link.get("href"))
                if href:
                    icons.append({"rel": rel, "href": href,
                                  "sizes": link.get("sizes")})

        # ---- inline SVG ----
        inline_svgs = len(soup.find_all("svg"))

        # ---- stylesheets ----
        css_urls: list[str] = []
        for link in soup.find_all("link", rel="stylesheet"):
            href = _abs(base, link.get("href"))
            if href and href not in css_urls:
                css_urls.append(href)
        inline_css = "\n".join(
            (st.string or "") for st in soup.find_all("style"))
        out["stylesheets_found"] = len(css_urls)

        css_blobs: list[tuple[str, str]] = []
        if inline_css.strip():
            css_blobs.append(("inline", inline_css[:_MAX_CSS_BYTES]))
        for css_url in css_urls[:_MAX_CSS_FILES]:
            try:
                cr = client.get(css_url)
                if cr.status_code == 200 and len(cr.content) <= _MAX_CSS_BYTES:
                    css_blobs.append((css_url, cr.text))
            except Exception:
                continue
        out["stylesheets_fetched"] = len(css_blobs)

        # ---- merge CSS parse results ----
        all_fonts: list[dict] = []
        all_props: dict[str, str] = {}
        color_counts: dict[str, int] = {}
        stack_counts: dict[str, int] = {}
        for css_url, blob in css_blobs:
            p = _parse_css(blob, css_url)
            all_fonts.extend(p["font_faces"])
            for k, v in p["custom_properties"].items():
                all_props.setdefault(k, v)
            for c in p["color_palette"]:
                color_counts[c["color"]] = \
                    color_counts.get(c["color"], 0) + c["uses"]
            for s in p["font_stacks"]:
                stack_counts[s] = stack_counts.get(s, 0) + 1
        palette = sorted(color_counts.items(), key=lambda kv: -kv[1])[:12]
        stacks = sorted(stack_counts, key=lambda s: -stack_counts[s])[:15]

        # ---- cheap verification (HEAD) ----
        asset_urls: list[str] = []
        for im in images:
            asset_urls.append(im["src"])
        for ic in icons:
            asset_urls.append(ic["href"])
        for f in all_fonts:
            for u in f["urls"]:
                asset_urls.append(urljoin(base, u))
        uniq = list(dict.fromkeys(asset_urls))[:_MAX_VERIFY]
        verified: dict[str, bool] = {}
        for u in uniq:
            verified[u] = _verify_url(client, u)

        def cls(u: str) -> str:
            return "OBSERVED" if verified.get(u) else "INFERRED"

        for im in images:
            im["classification"] = cls(im["src"])
        for ic in icons:
            ic["classification"] = cls(ic["href"])
        for f in all_fonts:
            f["classification"] = cls(
                urljoin(base, f["urls"][0])) if f["urls"] else "INFERRED"

        out.update({
            "images": images[:200],
            "image_count": len(images),
            "icons": icons,
            "inline_svg_count": inline_svgs,
            "fonts": all_fonts,
            "font_count": len(all_fonts),
            "design_tokens": {
                "custom_properties": all_props,
                "custom_property_count": len(all_props),
                "color_palette": [{"color": c, "uses": n}
                                  for c, n in palette],
                "font_stacks": stacks,
            },
            "assets_verified_200": sum(1 for v in verified.values() if v),
            "assets_checked": len(verified),
        })

        # ---- artifact ----
        artifact_path = os.path.join(artifacts_dir, "assets.json")
        with open(artifact_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False, default=str)
        out["artifact"] = os.path.relpath(artifact_path, session_dir)

        # ---- ledger findings ----
        page_cls = "OBSERVED" if page_ok else "INFERRED"
        _ledger_append(session_id, {
            "type": "asset",
            "title": f"Asset inventory: {len(images)} images, "
                     f"{len(all_fonts)} fonts, {inline_svgs} inline SVGs",
            "detail": (f"{len(images)} images, {len(icons)} icons/favicons, "
                       f"{len(all_fonts)} @font-face fonts, {inline_svgs} inline SVGs. "
                       f"{sum(1 for v in verified.values() if v)}/{len(verified)} "
                       f"asset URLs verified HTTP 200 (rest INFERRED). "
                       f"Artifact: artifacts/assets.json"),
            "classification": page_cls,
            "confidence": 0.9 if page_ok else 0.5,
            "confidence_why": "parsed from fetched HTML/CSS"
                              if page_ok else "page fetch did not return 200",
            "sources": [url],
            "route": None, "component": None, "endpoint": None,
            "artifact": out["artifact"],
            "verification": "unverified",
            "limitations": "Image dimensions from attributes only; no image downloads.",
        })
        if all_props or palette:
            _ledger_append(session_id, {
                "type": "asset",
                "title": f"Design tokens: {len(all_props)} CSS variables, "
                         f"{len(palette)} palette colors",
                "detail": "Top colors: " + ", ".join(
                    c for c, _ in palette[:6]) +
                    (f"; font stacks: {'; '.join(stacks[:3])}" if stacks else ""),
                "classification": page_cls,
                "confidence": 0.85 if page_ok else 0.5,
                "confidence_why": "parsed from fetched stylesheets"
                                  if page_ok else "page fetch did not return 200",
                "sources": [url],
                "route": None, "component": None, "endpoint": None,
                "artifact": out["artifact"],
                "verification": "unverified",
                "limitations": "Tokens from stylesheets reachable at fetch time; "
                               "CSS-in-JS not covered.",
            })
        return out
    finally:
        client.close()
