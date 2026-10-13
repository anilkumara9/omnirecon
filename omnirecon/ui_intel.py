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

    return out
