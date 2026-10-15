# OmniRecon: Reverse-Engineering MCP Server for AI Coding Agents

> Point your coding agent at any website, API, APK, or codebase. It drives a real browser, captures the evidence, and hands back a rebuild blueprint. Nothing is ever invented.

<p align="center">
  <img src="assets/mascot.webp" alt="OmniRecon mascot — the reverse-engineering bot" width="320" />
</p>

<p align="center">
  <a href="https://github.com/anilkumara9/omnirecon/stargazers"><img src="https://img.shields.io/github/stars/anilkumara9/omnirecon?style=social" alt="GitHub stars" /></a>
  <img src="https://img.shields.io/github/actions/workflow/status/anilkumara9/omnirecon/test.yml?branch=main" alt="CI" />
  <img src="https://img.shields.io/github/license/anilkumara9/omnirecon" alt="MIT license" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/MCP-compatible-purple" alt="MCP compatible" />
  <img src="https://img.shields.io/badge/tools-25-green" alt="25 tools" />
</p>

<p align="center"><b>Reverse-engineering infrastructure for AI coding agents. v2.2.1</b></p>

<p align="center"><b>One tool call does the whole job.</b><br/>
<code>recon_auto_pilot("https://target.com")</code> crawls routes, inspects pages, captures network traffic, traces how <code>sign=</code> params are computed, and returns a build-ready blueprint — with <code>unknowns</code> and <code>limitations</code> on every response, so the agent always knows what it doesn't know.</p>

Built for [Claude Code](https://docs.anthropic.com/en/docs/claude-code),
[Codex](https://developers.openai.com/codex), Cursor, Windsurf, Zed, and any
other MCP-compatible agent or IDE.

```bash
curl -fsSL https://raw.githubusercontent.com/anilkumara9/omnirecon/main/install.sh | bash -s -- --client auto
# one command: clone + venv + deps + Chromium + agent config. Then restart your agent.
```

Then ask your agent: *"Reverse-engineer https://example.com — explain how it
works and give me a rebuild plan."*

---

## Table of contents

- [How it works](#how-it-works)
- [Comparison with alternatives](#comparison-with-alternatives)
- [See it in action](#see-it-in-action)
- [The 25 tools](#the-25-tools)
- [UI reverse engineering](#ui-reverse-engineering-designer-grade)
- [Authenticated recon](#authenticated-recon-behind-the-login)
- [Installation](#installation)
- [Connecting your agent](#connecting-your-agent)
- [Agent workflow](#agent-workflow)
- [Evidence model](#evidence-model)
- [Measured accuracy](#measured-accuracy)
- [Security boundaries](#security-boundaries)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [FAQ](#frequently-asked-questions)
- [Star history](#star-history)
- [License](#license)

---

## How it works

1. **Point** — give it a URL, API doc, repo, or APK. `recon_start` validates it and does rapid recon in seconds.
2. **Run** — `recon_auto_pilot` drives a real headless browser through the whole pipeline: crawl routes, inspect pages, capture network traffic, trace signatures, probe endpoints.
3. **Rebuild** — you get a blueprint (routes, components, APIs, design tokens, workflows) where every claim cites its evidence and every gap is labeled.

Sessions persist on disk, so the agent can pause, resume, or run long crawls in the background.

## Comparison with alternatives

OmniRecon and [REA](https://github.com/morluto/rea) solve different halves of the problem. REA is the authority on deep binary decompilation (Ghidra/IDA providers) and is deliberately passive on the web. OmniRecon autonomously drives a real browser — crawling, clicking, capturing traffic — and hands binary targets to REA through a bridge when it's installed.

| | OmniRecon | REA | Burp Suite + DevTools |
|---|---|---|---|
| Built for AI coding agents | ✅ 24 MCP tools + skill doc | ❌ CLI for humans | ❌ human-driven |
| One-call full pipeline | ✅ `recon_auto_pilot` | ❌ | ❌ |
| JS signature tracing (how is `sign=` computed?) | ✅ live hooking | ❌ | ❌ manual |
| Autonomous web driving (crawl, click, capture) | ✅ | ❌ deliberately passive | ❌ manual |
| Edge-state UI (mock API failures, capture degraded UI) | ✅ | ❌ | ❌ manual |
| Output contract (unknowns + limitations on every response) | ✅ | ✅ | ❌ |
| Response budgeting (no context thrashing) | ✅ | ❌ | ❌ |
| Evidence ledger (nothing invented, ever) | ✅ 5 classifications | ✅ | ❌ |
| Authenticated recon (behind login) | ✅ | ❌ | ✅ manual |
| APK manifest + DEX code analysis | ✅ | ✅ (via providers) | ❌ |
| Electron app introspection | ✅ | ❌ | ❌ |
| Deep binary decompilation (Ghidra/IDA) | via REA bridge | ✅ | ❌ |
| Rebuild blueprint + verify loop | ✅ | ❌ | ❌ |
| One-command install (configures your agent too) | ✅ `curl … \| bash -s -- --client auto` | ✅ `npm i` (then configure tools yourself) | ❌ commercial |

## See it in action

One call. Full pipeline. Build-ready blueprint:

```bash
$ .venv/bin/python -m omnirecon.cli auto-pilot https://example.com --depth quick
{
  "session_id": "a1b2c3d4",
  "depth": "quick",
  "elapsed_s": 87.3,
  "tools_run": ["recon_start", "recon_discover_routes", "recon_inspect_page",
                "recon_capture_network", "recon_analyze_ui",
                "recon_generate_spec"],
  "evidence": {"total": 42, "by_classification": {"OBSERVED": 38}},
  "unknowns": [],
  "limitations": ["browser tools may fail on bot-protected targets"],
  "manifest": {"build_tasks": 8, "research_tasks": 3},
  "next_steps": "Build 8 tasks in manifest['build_tasks'] order..."
}
```

Every response carries `unknowns` (what wasn't resolved) and `limitations`
(what can't be guaranteed) — the agent always knows what it doesn't know.

Or hand it to your agent: *"Reverse-engineer this platform and give me a
rebuild plan."* It calls `recon_auto_pilot` once and gets the blueprint.

**Teardown gallery:** [`examples/teardowns/`](examples/teardowns/) —
complete reverse-engineering blueprints of real targets. Every claim cites
its evidence.

| Target | Findings | Rebuild score | Teardown |
|---|---|---|---|
| Acme Metrics (demo SaaS) | 36 | — | [teardown-acme-metrics](examples/teardown-acme-metrics/) |
| Linear | — | — | [teardown-linear](examples/teardown-linear/) |

**Full worked example:** [`examples/teardown-acme-metrics/`](examples/teardown-acme-metrics/)
— a complete session (evidence ledger, 15-section spec, design tokens,
screenshots, dependency graph) against a demo SaaS site, committed as proof.

## The 25 tools

| Tool | What it does |
|---|---|
| `recon_auto_pilot` | **One-call full pipeline**: scope ledger → rapid recon → routes → deep inspection → network → UI → spec. Returns build-ready blueprint. |
| `recon_scope` | **Scope ledger**: ownership tier (owned/open-source/third-party), ToS status, robots.txt, access method, and the in-scope/out-of-scope boundary — recorded before any deep recon. |
| `recon_trace_signatures` | **Signature tracing**: live-hooks the page's crypto (WebCrypto/CryptoJS) + fetch/XHR and reports *how* each `sign=`/`token=` is computed — algorithm, which fields fed the input, and the exact JS line. |
| `recon_mock_network` | **Edge-state revelator**: mock API failures/slowness, capture error/empty/loading UI. |
| `recon_start` | Validate target + rapid recon (tech, title, forms, DNS). Targets: web URL, OpenAPI document URL, repo dir/git URL, APK/IPA/binary/JS-bundle file. Returns `session_id`. |
| `recon_status` | Stage, progress, background jobs, ledger stats. |
| `recon_discover_routes` | Crawl internal routes; extracts API endpoints from page text **and** JS bundles. |
| `recon_inspect_page` | Rendered DOM, controls, forms, a11y data, 3-viewport screenshots, console errors. |
| `recon_analyze_ui` | Design tokens (colors, type, spacing, radii, shadows), component variants, layout sections, **motion catalog** (transitions, keyframe animations, GSAP/Framer-Motion/Lottie), **dark-mode probe**, and a **Web Vitals snapshot** (LCP, load timings, transfer weight). |
| `recon_trace_workflow` | Goal-directed clicking through multi-step user journeys. **Auto-emits a replayable Playwright script** per trace. |
| `recon_capture_network` | Live XHR/fetch/WebSocket capture with secrets redacted; each request linked to the script+line that fired it. Captures **values-free request/response shapes** (`type:"schema"` findings) and WebSocket message shapes. |
| `recon_analyze_source` | AST route extraction, components, state management, migrations, auth files, env-var names. |
| `recon_analyze_artifact` | APK/IPA/native-binary/JS-bundle intel: format, symbols, manifest, string-mined URLs; REA deep-dive when available. |
| `recon_verify_consistency` | **Cross-engine accuracy check**: static crawl vs rendered pages vs JS bundles vs network capture. Agreements corroborated, contradictions downgraded — never silently dropped. |
| `recon_recover_sourcemaps` | Fetch published `*.js.map` files and recover the original source tree. Honest when the site ships none. |
| `recon_probe_endpoints` | Live-probe every discovered `/api/*` endpoint (HEAD→GET); records live/dead verdicts with status codes. |
| `recon_extract_assets` | Image/font/icon inventory + static design tokens (CSS parsing). |
| `recon_analyze_ui` | **Designer-grade UI reverse engineering**: computed design tokens (colors, type scale, spacing, radii, shadows) from *rendered* styles, component inventory grouped by visual signature, CSS framework detection, layout sectioning. |
| `recon_get_graph` | Route/component/endpoint dependency graph. |
| `recon_get_evidence` | Query the evidence ledger (filter by classification/type). |
| `recon_generate_spec` | 15-section reconstruction blueprint from the ledger. |
| `recon_compare_build` | Diff a rebuild URL against the reference (route coverage, endpoint overlap). |
| `recon_export_report` | Markdown/JSON report — or an **OpenAPI 3.1 document** reconstructed from the ledger, every path tagged with its evidence classification. |
| `recon_cancel` | Cancel a session and its background jobs. |
| `recon_authenticate` | **Log in with your own credentials**; saves session cookies so all later browser tools browse as the logged-in user. Password used transiently, never stored. |
| `recon_deauthenticate` | Delete saved session cookies (log out). |

## UI reverse engineering (designer-grade)

`recon_analyze_ui` reads the **rendered page** the way a designer would — not the stylesheets:

- **Computed design tokens** — real colors, type scale, fonts, spacing, radii, shadows from `getComputedStyle`.
- **Component inventory** — buttons/inputs grouped by visual signature ("primary button ×14") with exact values, ready to rebuild.
- **Framework detection** — Tailwind, MUI, Chakra, Bootstrap, Ant Design; plus layout landmarks with measured dimensions.

## Authenticated recon (behind the login)

Most real platforms hide 90% of themselves behind a login. OmniRecon goes there with **your own credentials**:

```
recon_authenticate(session_id, login_url, username, password)
→ recon_inspect_page / discover_routes / trace_workflow / capture_network / analyze_ui
→ recon_deauthenticate(session_id)
```

The password is used transiently for the form fill and **never stored** — not in the session dir, not in the ledger, not in logs. Cookies are kept `0600`.

## Installation

Requirements: Python 3.10+, no Node.js.

**One command — installs everything and configures your agent:**

```bash
curl -fsSL https://raw.githubusercontent.com/anilkumara9/omnirecon/main/install.sh \
  | bash -s -- --client auto
```

That single command clones the repo, creates `.venv/`, installs dependencies,
downloads Playwright's Chromium (~300MB, skipped if already present), verifies
the install, **and writes the MCP config for every agent it finds**
(Claude Code, Codex, Cursor, Windsurf, Zed) — no manual JSON editing. Then just
restart your agent and ask it: *"Reverse-engineer https://example.com"*.

Prefer the explicit steps?

```bash
git clone https://github.com/anilkumara9/omnirecon.git
cd omnirecon
./install.sh --client auto   # Linux / macOS
```

Windows: run `install.bat auto` instead (same steps: venv + deps + Chromium + verify + agent config).

`--client` accepts `claude-code`, `codex`, `cursor`, `windsurf`, `zed`,
`generic`, or `auto` (detect everything installed). Safe to re-run — steps
that are already done are skipped, and existing configs are merged, never
duplicated or destroyed (unparseable files are backed up first).

<details>
<summary>Manual install (if you prefer each step explicit)</summary>

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/playwright install chromium   # browser for inspect/trace/capture
```

</details>

Run the server (stdio transport — your agent connects to this, not you directly):

```bash
.venv/bin/python omnirecon/server.py
```

It waits silently for MCP input; that's normal. To verify everything works
from your terminal instead, use the CLI (same 25 tools):

```bash
.venv/bin/python -m omnirecon.cli recon-start https://example.com --mode fast
# → {"session_id": "...", ...} means your install is healthy
```

## Connecting your agent

OmniRecon is a **stdio MCP server**: one Python process, no ports, no daemons.
Restart the agent/IDE after registering.

**Easiest — the command writes the config for you:**

```bash
.venv/bin/python -m omnirecon.cli setup auto
# or pick one: claude-code, codex, cursor, windsurf, zed, generic
# --dry-run previews without writing; everything is idempotent
```

This auto-detects your venv Python and `server.py`, then writes/merges the
config into the right place for each client — no `/path/to/...` to get wrong,
no manual JSON editing. Existing configs are merged, never duplicated;
unparseable files are backed up (`.omnirecon.bak`) rather than destroyed.

Example output:

```json
{
  "ok": true,
  "clients": [
    {"client": "cursor", "changed": true, "note": "written",
     "path": "/home/you/.cursor/mcp.json", "restart": "restart cursor"}
  ],
  "summary": "1/1 client(s) configured"
}
```

<details>
<summary>Manual config (if you prefer each step explicit)</summary>

Every integration below registers the same thing — the Python interpreter from
your virtualenv running `omnirecon/server.py`. Replace `/path/to/omnirecon`
with your clone location and use the venv Python (not system Python), so the
pinned dependencies (`mcp<2`, `playwright`, `httpx`, …) resolve.

### Claude Code (CLI)

```bash
claude mcp add omnirecon -- /path/to/omnirecon/.venv/bin/python /path/to/omnirecon/omnirecon/server.py
claude mcp list          # verify it shows up
```

Project-scoped (shared with your team via `.mcp.json` in the repo root):

```json
{
  "mcpServers": {
    "omnirecon": {
      "command": "/path/to/omnirecon/.venv/bin/python",
      "args": ["/path/to/omnirecon/omnirecon/server.py"]
    }
  }
}
```

Then just ask: *"Reverse-engineer https://example.com — explain how it works
and give me a rebuild plan."*

### Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.omnirecon]
command = "/path/to/omnirecon/.venv/bin/python"
args = ["/path/to/omnirecon/omnirecon/server.py"]
```

Restart Codex. Verify with `/mcp` — `omnirecon` should list 25 tools.

### Cursor

1. Open **Settings → MCP** (or `~/.cursor/mcp.json`).
2. Add:

```json
{
  "mcpServers": {
    "omnirecon": {
      "command": "/path/to/omnirecon/.venv/bin/python",
      "args": ["/path/to/omnirecon/omnirecon/server.py"]
    }
  }
}
```

3. Toggle the server on. In Agent mode, ask it to reverse-engineer a target —
   Cursor will call the tools itself.

### Windsurf

1. Open **Settings → Cascade → MCP servers** (or `~/.codeium/windsurf/mcp_config.json`).
2. Add the same `mcpServers` JSON block as Cursor above.
3. Restart Windsurf. The tools appear in Cascade's tool list.

### Zed

Add to your Zed settings (`~/.config/zed/settings.json`):

```json
{
  "context_servers": {
    "omnirecon": {
      "command": "/path/to/omnirecon/.venv/bin/python",
      "args": ["/path/to/omnirecon/omnirecon/server.py"]
    }
  }
}
```

Restart Zed. Use the assistant panel — it can now drive recon sessions.

### Any other MCP client

Any client that speaks MCP over stdio works: register a server with

- **command:** `/path/to/omnirecon/.venv/bin/python`
- **args:** `["/path/to/omnirecon/omnirecon/server.py"]`
- **transport:** stdio (the default — no SSE/HTTP needed)

</details>

### No MCP support? Use the CLI

All 25 tools are mirrored as CLI commands running the same code — useful for
scripts, CI, or agents without MCP:

```bash
.venv/bin/python -m omnirecon.cli recon-start https://example.com --mode fast
.venv/bin/python -m omnirecon.cli recon-discover-routes <session-id> https://example.com --max-pages 40
.venv/bin/python -m omnirecon.cli recon-generate-spec <session-id>
.venv/bin/python -m omnirecon.cli --help   # all 25 commands
```

Sessions persist on disk (`sessions/<id>/`), so CLI and MCP sessions are
interchangeable — start in one, continue in the other.

## Agent workflow

Once connected, the agent follows the bundled skill
([`skills/omnirecon/SKILL.md`](skills/omnirecon/SKILL.md)):

1. `recon_start` — validate the target, get rapid recon in seconds.
2. Deep engines — crawl routes, inspect pages, trace workflows, capture network, analyze source/artifacts.
3. `recon_verify_consistency` — cross-check every engine against the others; contradictions get downgraded, never hidden.
4. `recon_generate_spec` — a 15-section rebuild blueprint where every claim cites its evidence.
5. Build, then `recon_compare_build` — diff the rebuild against the original and iterate until parity.

Just ask: *"Reverse-engineer https://example.com — explain how it works and give me a rebuild plan."*

## Evidence model

Every finding carries a trust label — the agent (and you) always knows how much to believe it:

| Label | Meaning |
|---|---|
| `OBSERVED` | Seen directly in a live response, DOM, or traffic capture |
| `SOURCE_VERIFIED` | Parsed from source code or manifests |
| `INFERRED` | Best explanation of the evidence, marked as such |
| `UNVERIFIED` | Claimed by the target, not yet confirmed |
| `BLOCKED` | Could not be observed (auth wall, bot protection…) — recorded, never bypassed |

Every response also carries `unknowns` (what couldn't be resolved), `limitations` (what can't be guaranteed), and `truncated` (whether the ~30k-token response budget cut anything). The agent always knows what it doesn't know.

## Measured accuracy

Measured 2026-10-12/13 on real targets (not estimates):

| Target | Result |
|---|---|
| Hand-annotated 3-page fixture | 3/3 routes, 2/2 JS API endpoints vs ground truth |
| Hacker News (live) | 8/8 discovered routes verified returning HTTP 200 |
| Demo SaaS teardown | 36 findings, 5 pages, 5 API endpoints, design tokens, 3-viewport screenshots — [full session committed](examples/teardown-acme-metrics/) |

200 tests green (`pytest tests/`). Raw benchmark data
in [`benchmarks/results/`](benchmarks/results/).

## Security boundaries

- **Read-only by default** — no state-changing requests, no destructive actions, ever.
- **No bypasses** — CAPTCHAs, paywalls, and bot protection become `BLOCKED` findings, not workarounds.
- **No credential harvesting** — authenticated recon only uses credentials you explicitly provide; passwords are never stored.
- **Secrets redacted** — API keys and tokens are scrubbed before anything is stored; page content is treated as untrusted data.

## Project layout

```
omnirecon/            the 23-module package (server, evidence, session,
                      browser_engine, source_intel, assets, spec, …)
tests/                pytest suite (200 tests)
skills/omnirecon/     agent skill doc: workflow, routing table, hard rules
examples/             committed teardown sessions (proof, not docs)
scripts/proxy_relay.py  dumb TCP relay for sandboxes whose egress proxy
                      breaks Chromium (see Troubleshooting)
benchmarks/           hand-annotated fixture + runner + measured results
install.sh            one-command installer (clone + venv + deps + Chromium + agent config)
install.bat           Windows one-command installer (same steps)
requirements.txt      pinned dependencies (mcp<2)
.github/workflows/    CI: full pytest suite on every push/PR
CHANGELOG.md          version history
CONTRIBUTING.md       contributor guide
SECURITY.md           security policy and §8 boundaries
ARCHITECTURE.md       module map and design decisions
REA_INSPECTION.md     REA teardown and the evidence-based comparison
```

## Troubleshooting

- **Agent doesn't see the tools** — the usual causes, in order: (1) you used
  system Python instead of `.venv/bin/python` — re-run
  `.venv/bin/python -m omnirecon.cli setup <client>` and check its output;
  (2) you forgot to restart the agent/IDE after registering; (3) the JSON has
  a typo — validate it with `python -m json.tool <config-file>`.
- **`setup` says python not found** — run `./install.sh` (or `install.bat`)
  first; the venv must exist before the config can point at it.
- **`Executable doesn't exist … ms-playwright`** — run
  `.venv/bin/playwright install chromium`.
- **Browser tunnel/cert errors behind a proxy** — export `HTTPS_PROXY`/
  `https_proxy`; the engine passes it to Playwright. Behind TLS-intercepting
  proxies the server retries automatically past cert errors (recording an
  `OBSERVED` finding); force it with `OMNIRECON_IGNORE_HTTPS_ERRORS=1`. If
  Chromium can't use the egress proxy at all (tunnel failures while curl
  works), run `scripts/proxy_relay.py` and point `HTTPS_PROXY` at
  `http://127.0.0.1:8899`.
- **DNS returns nothing** — direct UDP DNS may be blocked; the tool falls back
  to DNS-over-HTTPS automatically.
- **Tool returns `{"error", …}`** — read `code` and `hint`; the server never
  leaks tracebacks.

## Frequently asked questions

**What can I reverse engineer?**
Web apps (routes, APIs, design systems, workflows), REST APIs (with OpenAPI export), Android APKs, Electron apps, and source codebases. Anything with an observable surface.

**How is this different from REA?**
REA owns deep binary decompilation (Ghidra/IDA) and is passive on the web. OmniRecon drives a real browser autonomously and hands binaries to REA via a bridge. [Comparison table](#comparison-with-alternatives).

**Can it do mobile apps?**
Android APKs: yes (manifest, DEX analysis). iOS: structural only. Native decompilation goes through the REA bridge.

**No MCP client?**
Every tool is mirrored in the CLI: `.venv/bin/python -m omnirecon.cli --help`.

**Safe against production sites?**
Read-only by default — no state-changing requests, ever. Authenticated recon uses only credentials you provide.

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=anilkumara9/omnirecon&type=date)](https://www.star-history.com/#anilkumara9/omnirecon&type=date)

If OmniRecon is useful in your workflow, consider leaving a ⭐ — it helps other developers find it.

## License

MIT — see [LICENSE](LICENSE).
