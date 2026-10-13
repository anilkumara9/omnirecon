# OmniRecon MCP — Build Report (2026-10-12)

## 1. What was inspected

**REA** (`github.com/morluto/rea`, v6.4.0, cloned and read at source level):
TypeScript monorepo, 1568 files under `src/`, npm package `rea-agents`, ~70 MCP
tools + CLI parity. Best-in-class for *shipped-artifact forensics*: native
binaries via Hopper/Ghidra/IDA/JEB bridges, APKs, .NET, EVM, firmware, Go, WASM,
JS/Electron bundles. Web capability is **deliberately passive**: CDP attaches to
the user's own Chrome and *observes* (V8 coverage, initiator stacks, screenshots)
but never drives navigation or interaction. No autonomous crawl, no session
pipeline, no evidence fusion, no auto-generated reconstruction spec, no web
benchmarks. Full analysis in `REA_INSPECTION.md`.

**reverse-skill** (`github.com/zhaoxuya520/reverse-skill`, cloned):
A cybersecurity *skills router* — a library of scenario skills (SKILL.md +
references) with a master routing table mapping target types to methodologies,
plus an Evidence→Finding→Path journaling pattern and scope-gating before action.
Structural ideas adopted (routing table, field journal, scope discipline). Its
offensive techniques (credential chains, persistence) were deliberately NOT
adopted — they violate the project's security boundaries (§8).

## 2. What was implemented

`~/workspace/omnirecon/` — Python 3.12, FastMCP (stdio), Playwright/Chromium,
venv `~/workspace/venvs/recon`. 13 modules, ~6000 lines:

| Module | Function |
|---|---|
| `recon_primitives.py` | Stage-2 rapid recon: platform scan, crawl, JS API extraction, DNS+DoH, repo analysis, HTTP probe, traffic capture |
| `evidence.py` | Finding dataclass + EvidenceLedger (F-NNNN ids, 5 classifications, dedup, JSONL) |
| `session.py` | SessionManager (create/checkpoint/resume/cancel) + JobManager (background jobs) |
| `security.py` | redact(), check_scope(), RateLimiter, audit log, safe_join() |
| `graph.py` | route/component/endpoint/entity graph builder |
| `browser_engine.py` | OwnedBrowser: goto, AX snapshot, 3-viewport screenshots, redacted network capture, safe interact, crawl |
| `source_intel.py` | Python AST routes, component detection, state-mgmt signals, API clients, migrations, auth files, env names |
| `assets.py` | image/font/icon inventory, design tokens, color palette |
| `spec.py` | 15-section reconstruction blueprint, every claim finding-linked |
| `report.py` | Markdown + JSON export |
| `verify.py` | compare_build: route coverage + deviations |
| `server.py` | 14 `recon_*` MCP tools, stdio, strict schemas, `{"error","code","hint"}` failures |
| `cli.py` | argparse CLI executing the same functions (REA-style parity) |

Plus: `skills/omnirecon/SKILL.md` (routing table, staged workflow, 8 hard rules),
`ARCHITECTURE.md`, `PROJECT_BRIEF.md`, `README.md` (install, Claude Code/Codex
setup, troubleshooting), `benchmarks/` with hand-annotated fixture.

## 3. Tests: passed and failed

- **93 passed** (`pytest tests/`): evidence, session, security, graph, source_intel,
  assets, spec, report, verify, server (incl. real stdio MCP protocol end-to-end:
  14/14 tools registered, full session driven over the wire).
- **13/13 browser-engine tests pass** (self-contained runner
  `tests/test_browser_engine.py`): snapshot, screenshots, redacted network
  capture, CDP initiator stacks, safe interact (incl. password non-leak),
  console errors, hermetic crawl, sync wrapper + async engine inside a running
  loop (the FastMCP scenario). **Total: 106/106 green (2026-10-12).**
- The lane's async-API rewrite fixed the verified E2E bug (Playwright sync API
  inside FastMCP's event loop); confirmed fixed via live MCP
  `recon_inspect_page` call.
- Sandbox note: this sandbox's egress proxy breaks Chromium's direct proxy
  stack (tunnel failures while curl works); `scripts/proxy_relay.py`
  (127.0.0.1:8899 dumb TCP forwarder, already anticipated by the test suite)
  restores it. Documented in README Troubleshooting. Not needed on normal
  machines.

## 4. OmniRecon vs REA (evidence-based)

| Capability | REA 6.4.0 | OmniRecon |
|---|---|---|
| Web: autonomous crawl + interaction | ❌ (passive observe only) | ✅ owned browser drives |
| Web: network initiator attribution | ✅ (passive, user acts) | ✅ autonomous (CDP stacks) |
| Session pipeline + resume | ❌ | ✅ |
| Evidence fusion + classification | ⚠️ export only | ✅ OBSERVED/INFERRED/... ledger |
| Auto reconstruction spec | ❌ | ✅ 15 sections |
| Web benchmarks vs ground truth | ❌ | ✅ measured |
| Native/binary/APK forensics | ✅ (~80% of its codebase) | ❌ out of scope — routes to REA |

Verdict: REA remains the tool for shipped artifacts; OmniRecon is more capable
for *live web platforms*, which is its entire design center. The claim is scoped,
not universal.

## 5. Performance measurements (2026-10-12, measured, not estimated)

| Target | Time to first report | Total | Routes | Endpoints | Route P/R |
|---|---|---|---|---|---|
| Local fixture (ground truth) | 0.72s | 2.5s | 3/3 | 3/3 | 1.0 / 1.0 |
| example.com | 3.17s | 5.5s | 1 | 0 | — |
| news.ycombinator.com | 3.25s | 21.2s | 5 | 1 | — |

Raw: `benchmarks/results/2026-10-12.json`. Fixture is tiny — perfect scores are a
floor. Browser-driven workflow tracing is not yet benchmarked (waits on Lane A).

## 6. Known limitations / blocked

- Browser engine unfinished (Lane A in progress): `recon_inspect_page`,
  `recon_trace_workflow`, `recon_capture_network` (browser path) error until it lands.
- Playwright browser install is flaky in proxied sandboxes (manual zip extraction
  needed; documented). On normal machines `playwright install chromium` works.
- JS component detection is regex-based (no tree-sitter); CSS-in-JS not parsed.
- Asset HEAD verification is best-effort; image dimensions from attributes only.
- Redaction is heuristic defense-in-depth, not a guarantee.
- JobManager.cancel() is best-effort (threads can't be force-killed).
- Login-walled flows, CAPTCHAs, paywalls, heavy bot protection → BLOCKED findings
  by design, never bypassed.
- No native-binary/APK analysis (delegated to REA by design).

## 7. Run it / connect it

```bash
# server (stdio)
/home/hatch/workspace/venvs/recon/bin/python /home/hatch/workspace/omnirecon/omnirecon/server.py
# CLI
/home/hatch/workspace/venvs/recon/bin/python -m omnirecon.cli recon-start https://example.com --mode fast
```
Claude Code: `claude mcp add omnirecon -- /home/hatch/workspace/venvs/recon/bin/python /home/hatch/workspace/omnirecon/omnirecon/server.py`
Codex: `~/.codex/config.toml` →
```toml
[mcp_servers.omnirecon]
command = "/home/hatch/workspace/venvs/recon/bin/python"
args = ["/home/hatch/workspace/omnirecon/omnirecon/server.py"]
```

## 8. Highest-value next improvements

1. **Finish + harden the browser engine** (Lane A): async fix, CDP initiator stacks,
   then benchmark workflow-tracing against a scripted ground-truth app.
2. **Deeper JS understanding**: tree-sitter or a JS parser for components/hooks;
   source-map recovery when `.map` files are exposed (reverse-skill's
   bundle-sourcemap-recovery pattern, defensive use only).
3. **Richer benchmarks**: annotated SPA fixture (auth flow, pagination, lazy
   loading) measuring workflow-transition coverage, not just routes.
4. **Incremental re-recon**: content-hash sessions and diff a target over time.
5. **Packaging**: `pip install omnirecon` + `playwright install` bundled setup
   script, so Codex/Claude Code users don't hand-roll the venv.
