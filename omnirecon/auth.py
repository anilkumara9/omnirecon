"""Authenticated session support.

Lets an agent recon targets behind a login using the operator's OWN
credentials (authorized testing only — never credential theft).

Flow:
  recon_authenticate(session_id, login_url, username, password)
    -> browser performs the login, session cookies are saved to
       sessions/<sid>/cookies.json (never the password, never in the ledger)
  ... all browser tools (inspect/discover/trace/capture/analyze_ui) ...
    -> automatically inject the saved cookies into each new browser context
  recon_deauthenticate(session_id) -> deletes the cookies

Security notes:
- The password is used transiently for the login flow and never persisted.
- Cookies are the operator's own session for their own target. They live in
  the session dir; `recon_deauthenticate` removes them. Operators should
  deauthenticate when done, and never share session dirs.
- Findings record THAT authentication happened, never credential material.
"""
from __future__ import annotations

import json
import os

from omnirecon import security as SEC


def _sessions_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions")


def cookie_path(session_id: str) -> str:
    # safe_join: a hostile/crafted session_id must never escape sessions/
    return SEC.safe_join(_sessions_dir(), session_id, "cookies.json")


def save_cookies(session_id: str, cookies: list[dict]) -> int:
    """Persist browser cookies for a session. Returns count saved."""
    sdir = os.path.join(_sessions_dir(), session_id)
    os.makedirs(sdir, exist_ok=True)
    # strip anything that isn't needed for session replay
    clean = []
    for c in cookies:
        if not isinstance(c, dict):
            continue
        clean.append({k: c.get(k) for k in (
            "name", "value", "domain", "path", "expires", "httpOnly",
            "secure", "sameSite") if k in c})
    with open(cookie_path(session_id), "w", encoding="utf-8") as fh:
        json.dump(clean, fh)
    try:
        os.chmod(cookie_path(session_id), 0o600)
    except OSError:
        pass
    return len(clean)


def load_cookies(session_id: str) -> list[dict]:
    p = cookie_path(session_id)
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def clear_cookies(session_id: str) -> bool:
    p = cookie_path(session_id)
    if os.path.exists(p):
        os.remove(p)
        return True
    return False


def has_cookies(session_id: str) -> bool:
    return bool(load_cookies(session_id))


async def inject_cookies(context, session_id: str) -> int:
    """Add saved session cookies to a fresh Playwright context."""
    cookies = load_cookies(session_id)
    if not cookies:
        return 0
    fixed = [dict(c) for c in cookies if isinstance(c, dict)
             and (c.get("domain") or c.get("url"))]
    if fixed:
        await context.add_cookies(fixed)
    return len(fixed)

async def perform_login(browser, page_id: int, session_id: str,
                        login_url: str, username: str, password: str,
                        username_selector: str = "",
                        password_selector: str = "",
                        submit_selector: str = "") -> dict:
    """Drive a login form in the page; persist session cookies.

    The password is used transiently for the fill and never persisted
    anywhere — not in the session dir, not in the ledger, not in logs.
    Returns {ok, evidence, cookies_saved}.
    """
    impl = browser._impl if hasattr(browser, "_impl") else browser
    entry = impl._get_page_entry(page_id)
    page = entry["page"]

    # heuristic field discovery when selectors aren't given
    if not username_selector:
        username_selector = (
            "input[type='email'], input[name*='user' i], input[name*='email' i],"
            " input[name*='login' i], input[type='text']")
    if not password_selector:
        password_selector = "input[type='password']"

    result: dict = {"ok": False, "evidence": []}
    try:
        user_el = await page.query_selector(username_selector)
        pass_el = await page.query_selector(password_selector)
        if not user_el or not pass_el:
            result["evidence"].append("login fields not found with selectors")
            return result
        # NOTE: password is filled transiently; never stored or logged
        await user_el.fill(username)
        await pass_el.fill(password)
        before_url = page.url
        before_cookies = {c["name"] for c in await entry["context"].cookies()}
        if submit_selector:
            btn = await page.query_selector(submit_selector)
            if btn:
                await btn.click()
            else:
                await pass_el.press("Enter")
        else:
            # try a submit button, else Enter
            btn = await page.query_selector(
                "button[type='submit'], input[type='submit']")
            if btn:
                await btn.click()
            else:
                await pass_el.press("Enter")
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        await page.wait_for_timeout(1500)
        after_url = page.url
        # success heuristics: URL changed, password field gone, logout
        # signal present, or NEW cookies set (common for JS-driven logins
        # that stay on the same URL)
        pw_gone = await page.query_selector(password_selector) is None
        url_changed = after_url.split("?")[0] != before_url.split("?")[0]
        logout_sig = await page.query_selector(
            "a[href*='logout' i], button:has-text('Log out'), "
            "[href*='signout' i]") is not None
        after_cookies = await entry["context"].cookies()
        new_cookies = [c["name"] for c in after_cookies
                       if c["name"] not in before_cookies]
        result["evidence"] = [
            f"url_changed={url_changed}",
            f"password_field_gone={pw_gone}",
            f"logout_signal={logout_sig}",
            f"new_cookies={new_cookies}",
            f"landed={after_url[:120]}",
        ]
        # Corroboration rule: a single weak signal (e.g. any new cookie —
        # analytics/CSRF cookies appear on failed logins too) is not enough.
        # url_changed alone is strong; otherwise require >= 2 signals.
        signals = sum([url_changed, pw_gone, logout_sig])
        result["ok"] = url_changed or signals >= 2 or (
            logout_sig and bool(new_cookies))
        if result["ok"]:
            # capture the authenticated cookies (password never persisted);
            # on failure the pre-login cookies are meaningless — don't save
            result["cookies_saved"] = save_cookies(session_id, after_cookies)
        else:
            result["cookies_saved"] = 0
    except Exception as e:  # noqa: BLE001
        result["evidence"].append(f"login flow error: {str(e)[:200]}")
    return result
