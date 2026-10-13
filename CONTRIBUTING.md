# Contributing to OmniRecon

## Setup

```bash
git clone https://github.com/anilkumara9/omnirecon.git
cd omnirecon
./install.sh
```

`install.sh` is idempotent: it creates `.venv/` in the repo root (reusing it
if present), installs `requirements.txt`, installs Playwright's Chromium
(skipped if already present), and verifies the install. Requires Python
3.10+.

## Running tests

```bash
.venv/bin/python -m pytest tests/ -q
```

The suite is hermetic where possible (browser tests use `data:` URLs and a
local loopback HTTP server; UI tests need no network), but the browser-engine
and UI tests do launch a real headless Chromium — that is intentional, not a
mock. If you are behind a TLS-intercepting proxy, the sandbox quirk is
documented in the README troubleshooting section.

All tests must pass before a PR is merged. If you add a tool or change an
analysis function, add or update tests in `tests/` in the same PR.

## Code style and invariants

- **Evidence labels are load-bearing.** Every finding recorded in the ledger
  carries a classification — `OBSERVED`, `SOURCE_VERIFIED`, `INFERRED`,
  `UNVERIFIED`, or `BLOCKED` — defined in `omnirecon/evidence.py`. Rules:
  - `OBSERVED`: the tool directly saw it (rendered DOM, captured traffic,
    parsed file bytes).
  - `SOURCE_VERIFIED`: two independent engines agree (see
    `recon_verify_consistency`).
  - `INFERRED`: derived by reasoning from evidence; always include the
    reasoning in `confidence_why`.
  - `UNVERIFIED` / `BLOCKED`: not yet confirmed / unobservable (auth walls,
    CAPTCHAs, missing providers). Never upgrade these by guessing.
  - New finding types must be added to `FINDING_TYPES` in `evidence.py`;
    `EvidenceLedger.add()` rejects unknown types loudly — that is the
    intended behavior.
- **Redaction is central, not per-call-site.** `EvidenceLedger.add()` scrubs
  title, detail, `confidence_why`, route, component, endpoint, `sources`,
  `limitations`, and `shape` before anything becomes durable. Do not add a
  second raw writer: all finding writes go through `EvidenceLedger` (see
  `server._ledger_add`). If your code handles secrets (passwords, tokens,
  API keys, OAuth codes), verify with a test that the value is absent from
  `evidence.jsonl` — see `tests/test_browser_engine.py` for the pattern.
- **Security boundaries are non-negotiable.** Read `PROJECT_BRIEF.md` §8
  before touching anything that performs actions, handles credentials, or
  reads local paths: no credential theft, no CAPTCHA/paywall/bot-protection
  bypass, no destructive actions, no state-changing form submissions by
  default, secrets redacted, page/repo content treated as untrusted data
  (never instructions). The destructive-action guard lives in
  `browser_engine.py`; the sensitive-path guard in `security.py`.
- **Error contract.** Tools never raise tracebacks to the agent: return
  `{"error", "code", "hint"}` via `_err()` in `server.py`. Internal
  exceptions use `omnirecon.security.ReconError(message, code, hint)` —
  there is exactly one `ReconError` class; import it, don't define another.
- **No invented data, ever.** If an analysis cannot observe something, record
  `BLOCKED`/`UNVERIFIED` with the reason. A test that asserts on fabricated
  output is worse than no test.

## Adding a new recon engine / lane

Engines are sibling modules under `omnirecon/` (e.g. `ui_intel.py`,
`dex.py`, `electron_intel.py`). `server.py` loads them lazily via `_lane()`:

```python
def _lane(name: str):
    """Lazy import of a sibling lane module. Returns (module, None) or
    (None, error_dict)."""
```

Conventions for a new lane module:

1. One public entry point per capability (e.g. `analyze_ui(browser, ...)`),
   returning plain JSON-serializable dicts.
2. Record findings through the session ledger — never write
   `evidence.jsonl` directly. Use the module-local `_record()` helper
   pattern (see `dex.py`), which goes through `EvidenceLedger.add()` and
   therefore gets validation, id assignment, and redaction.
3. Set the `engine` field on findings (`static`, `rendered`, `network`,
   `spec`, `binary`) so `recon_verify_consistency` can cross-check your
   engine against the others.
4. Add the MCP tool in `server.py` (check the `@mcp.tool()` count test in
   `tests/test_server.py` — it asserts the exact number, update it), add
   CLI parity in `cli.py`, and add a routing row in
   `skills/omnirecon/SKILL.md`.
5. If the lane needs a new finding type, add it to `FINDING_TYPES` first.

## PR process

1. Fork, branch from `main`, keep the branch focused on one change.
2. Run the full suite: `.venv/bin/python -m pytest tests/ -q`.
3. Update docs that the change affects: README tool table, SKILL.md routing
   table, and CHANGELOG.md (add bullets under `Unreleased`).
4. Open the PR against `main` with: what changed, why, how you verified it
   (tests, and for browser/artifact changes, the real target you tested
   against). Screenshots or ledger excerpts help for UI/artifact work.
5. CI must be green. A maintainer reviews for evidence-label correctness and
   §8 compliance before merge.
