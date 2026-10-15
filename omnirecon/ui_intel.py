"""Designer-grade UI reverse engineering.

Goes beyond DOM structure to capture what a UI/UX designer would hand off:
computed design tokens (colors, typography, spacing, radii, shadows),
component inventory with visual variants, CSS framework detection, and
layout sectioning. All values are *computed* (what the user actually sees),
not just what's written in stylesheets.
"""
from __future__ import annotations

import json
import os
import re

# Runs in the page. Samples up to ~1500 visible elements; returns compact
# aggregates — never ships the full DOM back.
_UI_TOKENS_JS = r"""
() => {
  const els = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  let n;
  while ((n = walker.nextNode()) && els.length < 1500) {
    const r = n.getBoundingClientRect();
    if (r.width > 0 && r.height > 0) els.push(n);
  }
  const colors = {}, fonts = {}, sizes = {}, weights = {}, radii = {},
        shadows = {}, spacing = {};
  const bump = (m, k) => { k = String(k); m[k] = (m[k] || 0) + 1; };
  const comps = {};
  for (const el of els) {
    const cs = getComputedStyle(el);
    bump(colors, cs.color + '|' + cs.backgroundColor);
    bump(fonts, cs.fontFamily.split(',')[0].trim().replace(/["']/g, ''));
    bump(sizes, cs.fontSize);
    bump(weights, cs.fontWeight);
    if (cs.borderRadius !== '0px') bump(radii, cs.borderRadius);
    if (cs.boxShadow !== 'none') bump(shadows, cs.boxShadow.slice(0, 80));
    const pad = cs.paddingTop + ' ' + cs.paddingLeft;
    if (pad !== '0px 0px') bump(spacing, pad);
    const tag = el.tagName.toLowerCase();
    if (/^(button|a|input|select|textarea)$/.test(tag) || el.getAttribute('role')) {
      // NEVER sample typed values from secret-bearing inputs (H1 fix)
      const t = (el.getAttribute('type') || '').toLowerCase();
      const isSecret = t === 'password'
          || /passw|secret|token/i.test(el.getAttribute('name') || '');
      const sample = isSecret ? '' : (el.innerText || el.value || '').trim().slice(0, 40);
      const sig = [tag, cs.backgroundColor, cs.color, cs.borderRadius,
                   cs.fontSize, cs.fontWeight, cs.paddingTop].join('|');
      if (!comps[sig]) comps[sig] = {tag, bg: cs.backgroundColor, fg: cs.color,
        radius: cs.borderRadius, fontSize: cs.fontSize, weight: cs.fontWeight,
        count: 0, sample: sample};
      comps[sig].count++;
    }
  }
  const top = (m, n) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n);
  // framework detection
  const html = document.documentElement.outerHTML.slice(0, 200000);
  const fw = [];
  if (/tailwind/i.test(html)) fw.push('tailwind');
  if (/Mui[A-Z]/i.test(html)) fw.push('mui');
  if (/chakra-/i.test(html)) fw.push('chakra-ui');
  if (/bootstrap/i.test(html)) fw.push('bootstrap');
  if (/ant-[a-z]+/i.test(html)) fw.push('ant-design');
  for (const s of document.styleSheets) {
    try { const h = s.href || ''; if (/tailwind/i.test(h)) fw.push('tailwind'); } catch (e) {}
  }
  // layout landmarks
  const sections = [];
  document.querySelectorAll('header,nav,main,section,footer,[role=banner],[role=navigation],[role=main],[role=contentinfo]').forEach((el, i) => {
    if (i >= 30) return;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    const h = el.querySelector('h1,h2');
    sections.push({landmark: el.tagName.toLowerCase(),
      heading: h ? h.innerText.trim().slice(0, 60) : '',
      w: Math.round(r.width), h: Math.round(r.height)});
  });
  return {colors: top(colors, 40), fonts: top(fonts, 15), sizes: top(sizes, 20),
    weights: top(weights, 10), radii: top(radii, 15), shadows: top(shadows, 10),
    spacing: top(spacing, 20), components: Object.values(comps).slice(0, 60),
    frameworks: [...new Set(fw)], sections: sections,
    elements_sampled: els.length};
}
"""


_MOTION_JS = r"""
(() => {
  const libs = [];
  if (window.gsap) libs.push('gsap');
  if (window.Motion || document.querySelector('[data-framer-motion]')) libs.push('framer-motion');
  if (window.lottie) libs.push('lottie');
  const desc = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    else if (el.className && typeof el.className === 'string') {
      const c = el.className.trim().split(/\s+/).slice(0, 2).join('.');
      if (c) s += '.' + c;
    }
    return s.slice(0, 80);
  };
  const seen = new Set(), transitions = [], animations = [];
  const els = document.querySelectorAll('*');
  const cap = Math.min(els.length, 1200);
  for (let i = 0; i < cap; i++) {
    const el = els[i], cs = getComputedStyle(el);
    if (cs.transitionProperty !== 'none' && cs.transitionDuration !== '0s') {
      const k = 't:' + cs.transitionProperty + '|' + cs.transitionDuration +
                '|' + cs.transitionTimingFunction;
      if (!seen.has(k) && transitions.length < 25) {
        seen.add(k);
        transitions.push({el: desc(el), property: cs.transitionProperty,
          duration: cs.transitionDuration, easing: cs.transitionTimingFunction,
          delay: cs.transitionDelay});
      }
    }
    if (cs.animationName && cs.animationName !== 'none') {
      const k = 'a:' + cs.animationName + '|' + cs.animationDuration;
      if (!seen.has(k) && animations.length < 25) {
        seen.add(k);
        animations.push({el: desc(el), name: cs.animationName,
          duration: cs.animationDuration, easing: cs.animationTimingFunction,
          delay: cs.animationDelay, iteration: cs.animationIterationCount});
      }
    }
  }
  return {transitions: transitions, animations: animations,
          libraries: libs, elements_scanned: cap};
})()
"""


_VITALS_JS = r"""
(() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const lcp = performance.getEntriesByType('largest-contentful-paint');
  const res = performance.getEntriesByType('resource');
  let js = 0, css = 0, img = 0;
  for (const r of res) {
    const sz = r.transferSize || 0, n = (r.name || '').toLowerCase();
    if (n.endsWith('.js')) js += sz;
    else if (n.endsWith('.css')) css += sz;
    else if (/\.(png|jpe?g|webp|gif|avif|svg)(\?|#|$)/.test(n)) img += sz;
  }
  const rnd = (v) => (v == null || isNaN(v)) ? null : Math.round(v);
  return {
    lcp_ms: lcp.length ? rnd(lcp[lcp.length - 1].startTime) : null,
    dom_content_loaded_ms: rnd(nav.domContentLoadedEventEnd),
    load_ms: rnd(nav.loadEventEnd),
    resources: res.length,
    js_kb: Math.round(js / 1024), css_kb: Math.round(css / 1024),
    img_kb: Math.round(img / 1024),
  };
})()
"""


def _sessions_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")


def _append(session_id: str, finding: dict) -> None:
    from omnirecon import evidence as ev
    sdir = os.path.join(_sessions_dir(), session_id)
    os.makedirs(sdir, exist_ok=True)
    lp = os.path.join(sdir, "evidence.jsonl")
    ledger = ev.EvidenceLedger.load(lp) if os.path.exists(lp) else ev.EvidenceLedger()
    ledger.add(finding)
    ledger.save(lp)


def _mk(ftype, title, detail, classification, confidence, why, sources, **kw):
    d = {"type": ftype, "title": title, "detail": detail[:2000],
         "classification": classification, "confidence": confidence,
         "confidence_why": why, "sources": sources}
    d.update(kw)
    return d


def _clean_color(pair: str) -> str:
    # "rgb(255, 0, 0)|rgba(0, 0, 0, 0)" -> dedupe transparent/neutral noise
    fg, _, bg = pair.partition("|")
    return f"text {fg} on {bg}"


async def analyze_ui(browser, page_id: int, session_id: str,
                     url: str) -> dict:
    """Run the UI token extraction in the page; record designer-grade findings."""
    impl = browser._impl if hasattr(browser, "_impl") else browser
    entry = impl._get_page_entry(page_id)
    page = entry["page"]
    try:
        data = await page.evaluate(_UI_TOKENS_JS)
    except Exception as e:
        _append(session_id, _mk(
            "note", "UI analysis failed",
            f"Token extraction script failed: {str(e)[:200]}",
            "BLOCKED", 1.0, "page.evaluate raised", [url]))
        return {"error": str(e)[:200]}

    if not isinstance(data, dict):
        return {"error": "unexpected token payload"}

    out: dict = {"url": url,
                 "elements_sampled": data.get("elements_sampled", 0),
                 "frameworks": data.get("frameworks", [])}

    # --- design tokens finding (the designer handoff) ---
    def _top(items, n=12):
        return [k for k, _ in (items or [])[:n]]

    palette = _top(data.get("colors"), 16)
    fonts = _top(data.get("fonts"), 8)
    sizes = _top(data.get("sizes"), 12)
    radii = _top(data.get("radii"), 8)
    shadows = [k for k, _ in (data.get("shadows") or [])[:6]]
    spacing = _top(data.get("spacing"), 10)

    token_detail = (
        f"Frameworks: {', '.join(out['frameworks']) or 'none detected'}\n"
        f"Type scale: {', '.join(sizes[:8])}\n"
        f"Fonts: {', '.join(fonts[:5])}\n"
        f"Weights: {', '.join(_top(data.get('weights'), 6))}\n"
        f"Radii: {', '.join(radii[:6]) or 'sharp corners'}\n"
        f"Spacing (padding-y/x): {', '.join(spacing[:6])}\n"
        f"Shadows: {len(shadows)} distinct\n"
        f"Top colors (text|bg): {'; '.join(palette[:8])}"
    )
    _append(session_id, _mk(
        "tech", f"Design tokens: {url[:60]}",
        token_detail, "OBSERVED", 0.9,
        "computed styles sampled from rendered elements (not stylesheets)",
        [url]))
    out["tokens"] = {"colors": palette[:16], "fonts": fonts,
                     "sizes": sizes, "radii": radii, "shadows": shadows,
                     "spacing": spacing}

    # --- component inventory with visual variants ---
    comps = data.get("components") or []
    out["components"] = comps[:40]
    for c in comps[:30]:
        _append(session_id, _mk(
            "component",
            f"Component: {c.get('tag')} ×{c.get('count')} "
            f"({(c.get('sample') or 'no text')[:30]})",
            f"Visual signature — bg: {c.get('bg')}, fg: {c.get('fg')}, "
            f"radius: {c.get('radius')}, font: {c.get('fontSize')} "
            f"w{c.get('weight')}. {c.get('count')} instances share this "
            f"exact signature (a design-system variant).",
            "OBSERVED", 0.9,
            "grouped by computed-style signature across rendered elements",
            [url], component=c.get("tag")))

    # --- layout sections ---
    sections = data.get("sections") or []
    out["sections"] = sections
    if sections:
        sec_list = "; ".join(
            f"{s['landmark']} ({s['w']}×{s['h']})"
            + (f" '{s['heading']}'" if s.get("heading") else "")
            for s in sections[:15])
        _append(session_id, _mk(
            "note", f"Layout: {len(sections)} landmark sections",
            sec_list, "OBSERVED", 0.9,
            "landmark elements measured in the rendered page", [url]))

    # --- framework finding ---
    if out["frameworks"]:
        _append(session_id, _mk(
            "tech", f"CSS framework: {', '.join(out['frameworks'])}",
            "Detected from class-name patterns and stylesheet URLs in the "
            "rendered page. The rebuild should use the same framework for "
            "visual parity.",
            "INFERRED", 0.8, "class/stylesheet pattern matching", [url]))

    # --- motion catalogue (transitions, keyframe animations, libraries) ---
    try:
        motion = await page.evaluate(_MOTION_JS)
    except Exception:
        motion = {}
    if isinstance(motion, dict):
        trans = motion.get("transitions") or []
        anims = motion.get("animations") or []
        libs = motion.get("libraries") or []
        out["motion"] = {"transitions": trans, "animations": anims,
                         "libraries": libs}
        if trans or anims or libs:
            lines = []
            for t in trans[:10]:
                lines.append(
                    f"transition {t.get('property')} {t.get('duration')} "
                    f"{t.get('easing')} on {t.get('el')}")
            for a in anims[:10]:
                lines.append(
                    f"@keyframes {a.get('name')} {a.get('duration')} "
                    f"{a.get('easing')} x{a.get('iteration')} on {a.get('el')}")
            _append(session_id, _mk(
                "motion", f"Motion: {len(trans)} transitions, "
                          f"{len(anims)} animations"
                          + (f" ({', '.join(libs)})" if libs else ""),
                "\n".join(lines)[:1500] or "no distinct motion signatures",
                "OBSERVED", 0.9,
                "computed transition/animation styles sampled from rendered "
                "elements; libraries detected from window globals",
                [url]))
        else:
            _append(session_id, _mk(
                "motion", "Motion: none detected",
                "No CSS transitions or keyframe animations found on sampled "
                "elements; page appears static.",
                "OBSERVED", 0.8, "computed-style sampling", [url]))

    # --- dark-mode support probe ---
    try:
        light_bg = await page.evaluate(
            "getComputedStyle(document.body).backgroundColor")
        await page.emulate_media(color_scheme="dark")
        await page.wait_for_timeout(700)
        dark = await page.evaluate(
            "({bg: getComputedStyle(document.body).backgroundColor, "
            "mq: matchMedia('(prefers-color-scheme: dark)').matches})")
        await page.emulate_media(color_scheme="light")
        dark_bg = (dark or {}).get("bg", "")
        supports_dark = bool(dark_bg and dark_bg != light_bg)
        out["dark_mode"] = {"supported": supports_dark,
                            "light_bg": light_bg, "dark_bg": dark_bg}
        _append(session_id, _mk(
            "tech",
            f"Dark mode: {'supported' if supports_dark else 'not detected'}",
            f"Body background {light_bg} (light) vs {dark_bg} (dark, "
            f"emulated). matchMedia('(prefers-color-scheme: dark)').matches="
            f"{(dark or {}).get('mq')}.",
            "OBSERVED", 0.9,
            "color-scheme emulation in the owned browser", [url]))
    except Exception as e:
        out["dark_mode"] = {"supported": None, "error": str(e)[:120]}

    # --- web-vitals / page-weight snapshot ---
    try:
        vitals = await page.evaluate(_VITALS_JS)
    except Exception:
        vitals = {}
    if isinstance(vitals, dict) and vitals:
        out["vitals"] = vitals
        lcp = vitals.get("lcp_ms")
        _append(session_id, _mk(
            "perf",
            f"Performance: LCP {lcp}ms" if lcp else "Performance snapshot",
            f"LCP: {lcp}ms; DOMContentLoaded: "
            f"{vitals.get('dom_content_loaded_ms')}ms; load: "
            f"{vitals.get('load_ms')}ms. Transfer: "
            f"{vitals.get('js_kb')}KB JS, {vitals.get('css_kb')}KB CSS, "
            f"{vitals.get('img_kb')}KB images across "
            f"{vitals.get('resources')} resources.",
            "OBSERVED", 0.85,
            "Performance API in the owned browser (single load, no throttling)",
            [url],
            limitations="single unthrottled load; not a Lighthouse lab run"))

    return out
