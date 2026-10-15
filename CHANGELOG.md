# Changelog

All notable changes to OmniRecon. Dates are commit dates (UTC).

## v2.3.0 — Analyst Dossier (2026-10-15)

**The analyst's methodology, automated.** Five upgrades that close the gap
between what our engine produced and what a rigorous teardown dossier demands:

- **`recon_scope` (25th tool)** — Phase-1 scope ledger, recorded *before* any
  deep recon: ownership tier (`owned` / `open-source` / `third-party`,
  local targets auto-classified as owned), live Terms-of-Service probe,
  robots.txt, access method, and the in-scope/out-of-scope boundary.
  Autopilot runs it as step 1; CLI: `omnirecon.cli scope`.
- **Motion catalog** — `recon_analyze_ui` now reports every distinct CSS
  transition and `@keyframes` animation (property, duration, easing curve,
  delay, element), plus detected motion libraries
  (GSAP / Framer-Motion / Lottie). New `motion` evidence type.
- **Dark-mode probe** — emulates `prefers-color-scheme: dark` in the owned
  browser and reports whether the site adapts (background comparison).
- **Web Vitals snapshot** — LCP, DOMContentLoaded, load timings, and
  transfer weight (JS/CSS/img KB) from the Performance API. New `perf`
  evidence type, honestly labeled as a single unthrottled load.
- **Feature-flag mining** — JS bundles are scanned for flag SDKs
  (LaunchDarkly, Flagsmith, Unleash, GrowthBook, Statsig, Optimizely) and
  flag/experiment names (`useFeatureFlag("…")` etc.), reported as INFERRED.
- **Self-imposed rate limit** — all direct HTTP recon (crawls, probes,
  scans, spec fetches) is now gated at **max 1 request/second** via
  `security.RateLimiter`; the owned browser drives pages at human-like pace.
200 tests.

## v2.2.1 — One-Command Setup (2026-10-15)

**Zero-headache install.** One command does everything:

```bash
curl -fsSL https://raw.githubusercontent.com/anilkumara9/omnirecon/main/install.sh \
  | bash -s -- --client auto
```

No clone needed (the script clones itself when piped), and `--client`
configures your agent automatically — `omnirecon.cli setup` now *writes*
the MCP config instead of telling you what to write: `auto` detects every
installed client (Claude Code, Codex, Cursor, Windsurf, Zed) and merges the
config idempotently (existing entries never duplicated, unparseable files
backed up). `install.bat` takes the client as an argument on Windows.
185 tests.

## v2.2.0 — Signature Tracing (2026-10-15)

**Answer the #1 web RE question: how is `sign=` computed?**
`recon_trace_signatures` live-hooks the page's crypto (WebCrypto
`digest`/`sign`, CryptoJS HMAC/SHA/MD5) and network (fetch/XHR) in the owned
browser, then correlates each signed request with the crypto call that ran
just before it — reporting the algorithm, which request fields fed the
signature input, and the exact page-JS line that computed it. Autopilot
`deep` mode runs it automatically. Signature values are redacted to
prefix/suffix; uncaptured signers are reported UNVERIFIED, never guessed.
24 tools.

## v2.1.0 — Edge States (2026-10-15)

**See the UI nobody crawls.** `recon_mock_network` mocks API responses
(`api_down`, `slow`, `empty`, `unauthorized`) and captures how the UI
degrades — error screens, skeletons, empty states. Real apps contain 2-3x
more UI in edge states than the happy path. Autopilot `deep` mode now runs
it automatically. 23 tools.

## v2.0.0 — Autopilot (2026-10-15)

**One tool call reverse-engineers anything.** `recon_auto_pilot(target)` runs
the entire pipeline automatically — rapid recon → route discovery → deep page
inspection → network capture → UI analysis → sourcemaps → endpoint probing →
spec generation — and returns a build-ready reconstruction blueprint with a
task manifest. Each step is isolated: one failing tool never kills the
pipeline. CLI: `omnirecon auto-pilot https://target.com`.

- 22 tools (was 21). All parameters carry descriptions; tool descriptions
  state sequencing; all error hints filled.
- `tasks.json` split into `build_tasks` / `research_tasks` with concrete
  acceptance criteria; API inventory deduplicated; test plan parameterized.
- RE-depth: sourcemap `sourcesContent` capture, browser storage snapshot,
  SPA endpoint patterns (tRPC/React Query/XHR/beacon), 429 rate-limit mining,
  DEX string-entropy obfuscation signal.

## Unreleased

- Test suite converted to pytest-native (`setup_module`/`teardown_module`);
  163/163 green under plain `pytest tests/` (verified 2026-10-13).
- README contradictions fixed: security section describes the authenticated-recon
  model accurately; test counts state the verified number.
- `verify_consistency` normalizes endpoints/routes before cross-engine
  comparison (previously ~zero agreements by construction); route findings now
  carry the structured `engine` field (`static` vs `rendered`).
- `probe_endpoints`: 401/403/404 verdicts corrected to live-but-guarded;
  probes all discovered endpoint shapes (not just `/api/*`); absolute URLs are
  probed on their own host instead of being mangled into the target origin.
- AXML decoder validated against a real APK (F-Droid): START_ELEMENT
  `comment` field, namespace-chunk header, and fixed attribute base corrected;
  synthetic test rebuilt on the true AOSP layout.
- Replay scripts emit again (`save_replay_script` used an invalid finding
  type, so no script was ever written).
- Security: second password-capture path masked (`_resolve_target`);
  OAuth codes redacted from the auth tool's direct return; `_redact`
  fail-closed; `sources[]`/`limitations` redacted centrally; fallback ledger
  writer routes through `EvidenceLedger`; DEX 256 MB input cap; auth cookie
  paths via `safe_join`; sensitive-path guard on `recon_analyze_source`.
- Auth: login success requires corroborating signals; cookies saved only on
  success. `localhost`/`127.0.0.1` targets route as `http://`.
- Browser tool calls now `shutdown()` (previously leaked one event-loop
  thread per call).
- Electron IPC detection survives minified bundles via `require("electron")`
  dataflow tracking.
- DEX findings distinguish method references from confirmed calls.

## v1.35.0 — 2026-10-13

- Authenticated sessions: new `recon_authenticate` / `recon_deauthenticate`
  tools (21 total). Browser login flow with the operator's own credentials;
  multi-signal success detection (URL change, password field gone, logout
  signal, new cookies — catches JS-driven logins).
- Session cookies saved `0600`, auto-injected into all later browser contexts
  via `goto(session_id=...)`; password verified absent from `cookies.json`
  and the ledger.
- One-command installer: `install.sh` (idempotent, no hardcoded paths) plus
  `requirements.txt` (`mcp<2` hard pin documented).
- Pure-Python DEX parser (`omnirecon/dex.py`): header/checksum validation,
  string pool, type/class/method/field inventory, interesting-API pattern
  matching (network, crypto, reflection, JNI); wired into APK analysis with
  `engine="binary"` findings.

## v1.34.3 — 2026-10-13

- Fixed `checkpoint()` silently discarding module-written findings (data loss):
  `EvidenceLedger.merge_from()` merges file findings into the cache; id
  counter synced past absorbed ids.
- Fixed `recon_export_report(format="openapi")` (100% broken —
  `EvidenceLedger` is not iterable); now iterates `ledger.list()`.
- `verify_consistency` corroboration path repaired via the structured `engine`
  field on findings (`static`/`rendered`/`network`/`spec`/`binary`).
- `"schema"` added to `FINDING_TYPES`.
- Unified the two `ReconError` classes; `browser_engine` imports the single
  `omnirecon.security.ReconError`.

## v1.34.2 — 2026-10-13

- Password input values are no longer captured anywhere: `secretInput()` gate
  in the snapshot JS (type=password, `data-secret`, name matching
  `passw|secret|token`); same gate in the UI-intel token script. Verified:
  typed password absent from snapshot, UI analysis, and ledger.
- Central redaction in `EvidenceLedger.add()`: title, detail,
  `confidence_why`, route, component, endpoint are scrubbed before findings
  become durable, independent of per-tool call sites.
- Redaction patterns expanded: OAuth `?code=`, refresh/id tokens, URL
  userinfo, colon-form JSON secrets, `x-session`/`sid`/`sessid` headers.
- `probe_endpoints` gains a 0.25 s politeness delay between probes.

## v1.34.1 — 2026-10-13

- Documentation-rot fixes from the ecosystem review: tool/command counts,
  test counts, and module counts corrected across README, CLI help, and
  SKILL.md.
- `recon_start` docstring covers the universal front door; CLI `--format`
  gains `openapi`; `discover-routes` gains `--background`.
- SKILL.md: machine-independent venv path; routing table covers
  `recon_extract_assets`.

## v1.34.0 — 2026-10-13

- New 19th tool `recon_analyze_ui` (`omnirecon/ui_intel.py`): design tokens
  (colors, type scale, fonts, spacing, radii, shadows) from rendered computed
  styles; component inventory grouped by visual signature; CSS framework
  detection (Tailwind, MUI, Chakra, Bootstrap, Ant Design); layout landmark
  sectioning.
- CLI parity (`recon-analyze-ui`); 3 hermetic tests via `data:` URLs.
- README "UI reverse engineering" section; SKILL.md gains the UI
  designer-handoff step.

## v1.33.0 — 2026-10-13

- Pure-Python AXML decoder (`omnirecon/axml.py`): binary Android manifests
  decode to package, permissions, activities, services, deep links.
- Response/request body capture with values-free schema inference
  (`infer_shape`); WebSocket frame capture.
- Electron introspection (`omnirecon/electron_intel.py`): `.asar` extraction,
  IPC channel inventory, `BrowserWindow` preferences, REA bridge for
  JavaScript-application analysis.
- Loop memory: `compare_build` persists runs with trend deltas; spec emits a
  machine-readable `tasks.json` build manifest.
- SKILL.md surgery: APK routing contradiction fixed, anti-patterns,
  confidence-to-action thresholds.

## v1.32.0 — 2026-10-13

- New `recon_verify_consistency` (16th tool): cross-engine accuracy check;
  agreements corroborated to `SOURCE_VERIFIED`/0.95, contradictions downgraded
  with reasons, never dropped.
- New `recon_recover_sourcemaps` (17th): reconstruct original source trees
  from published `.js.map` files.
- New `recon_probe_endpoints` (18th): `HEAD`→`GET` live-probing of discovered
  API endpoints with live/dead verdicts.
- `recon_trace_workflow` auto-emits standalone Playwright replay scripts.

## v1.31.0 — 2026-10-13

- Universal target front door: `recon_start` routes `url` / `api_spec` /
  `repo` / `artifact` targets to the right engine.
- New `recon_analyze_artifact` (15th tool): APK manifest, ELF via
  readelf/nm, string-mined URLs; honest `BLOCKED` when deep analysis needs
  REA providers that aren't configured.
- REA bridge: fuses `rea` CLI results into the evidence ledger when REA is
  installed with a configured provider.
- OpenAPI pipeline: `api_spec` targets inventoried; `recon_export_report`
  gains `format="openapi"` with `x-omni-evidence` provenance.

## v1.30.0 — 2026-10-13

- Initial release: session-based reverse-engineering MCP server, 14 tools.
- Owned Playwright browser engine: route crawl, page inspect, workflow
  tracing, live network capture with CDP initiator stacks, screenshots.
- Evidence ledger with `OBSERVED` / `SOURCE_VERIFIED` / `INFERRED` /
  `UNVERIFIED` / `BLOCKED` classifications; secret redaction.
- 15-section reconstruction blueprint generator; build comparator;
  machine-readable exports.
- CLI mirroring all MCP tools; agent skill docs (`skills/omnirecon/SKILL.md`)
  with a target routing table.
- Measured benchmarks against a fixture with ground truth.
