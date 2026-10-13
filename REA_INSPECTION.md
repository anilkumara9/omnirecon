# REA Inspection Report

**Date:** 2026-10-12
**Repo:** https://github.com/morluto/rea.git (cloned depth-1, v6.4.0)
**Method:** source tree, README, docs/, skill files, MCP contracts — no assumptions.

## 1. What REA is

- **Name/package:** `rea-agents` (npm), MCP name `io.github.morluto/rea`, MIT license.
- **Language/stack:** TypeScript (ESM), Node.js 22/24+, 1568 files under `src/`, vitest tests, turbo build.
- **Tagline:** "One MCP for reverse engineering across binaries, applications, and runtime behavior."
- **Distribution:** `npx rea-agents setup` registers the MCP server + workflow skills for Claude Code, Codex, Cursor, Gemini CLI, Grok Build, etc. CLI + MCP parity (`rea` command mirrors every tool).

## 2. Architecture (file evidence)

| Layer | Location | Role |
|---|---|---|
| MCP server + CLI | `src/cli/`, `scripts/rea.mjs`, `server.json` | stdio MCP server, ~70+ tools, JSON evidence output |
| Contracts | `src/contracts/` | strict per-tool input/output schemas, error contract (`docs/error-contract.schema.json`) |
| Native analysis | `src/application/native/`, `bridge/ghidra/*`, `bridge/hopper_bridge.py` | Hopper/Ghidra/IDA/JEB bridges, function analysis, pseudocode |
| Managed/.NET | `src/application/managed/` | PE/CLI assemblies, NativeAOT metadata |
| Android | `src/android/`, `src/adb/`, `src/apktool/`, `bridge/android/` | APK inspection, adb device analysis, jadx bridge |
| JS/Electron | `src/application/javascript/`, `src/artifacts/javascript/` | static JS app analysis, ASAR, module graphs, source-map recovery |
| EVM / firmware / Go / WASM | `src/application/evm|firmware|go|wasm/` | bytecode, binwalk/unblob, Go metadata, WAT |
| Browser (passive) | `src/browser/` (CDP: `CdpPageCapture.ts`, `CdpObservationSession.ts`, `CdpCaptureEvents.ts`…) | attach to **user-owned** Chrome via CDP; DOM/AX capture, V8 coverage, network events, screenshots, WebMCP discovery |
| Browser (owned) | `src/browser/` Playwright scenario provider | scripted step scenarios, capture + compare (`compare_web_captures`) |
| Network captures | `bridge/mitmproxy/capture.py`, `inspect_web_network_capture` | retained HAR/mitmproxy capture inspection (offline, no live fetch) |
| Evidence | `export_evidence_bundle`, `get_evidence_bundle` | content-addressed evidence IDs, provenance, obligation ledgers |
| Skills | `.agents/skills/reverse-engineer-anything/` (+ 7 reference docs) | agent workflow routing: "route the target first", per-artifact tool selection |
| Docs site | `docs/` (~45 guides), `website/` | per-target guides, showcases, error catalog |

## 3. Web capabilities (overlap with OmniRecon mission)

- `inspect_web_page`: DOM structure, accessibility nodes, scripts, resources, network/console metadata, WebSocket frame sizes, workers, storage key names (values redacted/fingerprinted).
- `observe_web_execution`: V8 precise coverage + armed-window network requests with initiator stacks and script joins. **Passive**: arms a window, the *user* performs actions.
- `analyze_web_bundle`: static JS parse → chunk edges, route/endpoint candidates, vendor fingerprints, source-map evidence.
- `capture_web_screenshot` / `compare_web_screenshots`: viewport PNGs, pixel diff with memory budget.
- `observe_web_session`: records reload/SPA-navigation/redirect/failure lifecycle metadata for external user actions.
- `discover_webmcp_tools`: experimental WebMCP registrations.
- `compare_web_captures`: exact-step-aligned scenario comparison.
- **Deliberate limitation (docs/browser-observation.md):** "This is a passive reverse-engineering capability, **not a general browser automation or remote-control surface**." CDP attaches to an already-running target and "never launch, drive, evaluate, or mutate it."

## 4. Gaps vs the OmniRecon mission

1. **No autonomous web crawling.** REA never drives navigation itself (CDP side is passive; Playwright side runs caller-scripted scenarios). No autonomous multi-page crawl, no self-directed link following.
2. **No interaction discovery.** It inspects listeners (`inspect_web_event_listeners`) but does not click/type to discover state transitions itself.
3. **No session pipeline.** Tools are composable primitives; there is no staged engine (rapid recon → deep analysis → fusion → spec) and no resumable session object.
4. **No evidence fusion.** Evidence bundles are exported, not fused: no dedup of routes/endpoints across pages, no OBSERVED/INFERRED conflict resolution, no cross-page graph.
5. **No automatic reconstruction spec.** `build_reconstruction_obligation_ledger` and `evaluate_reconstruction_coverage` exist for *guided* reconstruction, but no generator that turns a session into a full technical blueprint (routes, components, journeys, entities, requirements, test plan).
6. **No benchmark suite vs ground truth.** Extensive `real-*` CI lanes verify providers against fixtures, but no route-recall / endpoint-precision benchmark on web targets.
7. **Binary-centric weight.** ~80% of the codebase serves native/managed/mobile/firmware — irrelevant to web-platform RE, but it sets the maintenance surface an alternative can sidestep.
8. **Setup friction for web:** web analysis needs the user's own Chrome with `--remote-debugging-port`; no owned headless browser out of the box.

## 5. Feature matrix: REA vs OmniRecon (planned)

| Capability | REA 6.4.0 (observed) | OmniRecon (target) |
|---|---|---|
| MCP + CLI | ✅ ~70+ tools, strict contracts | ✅ compact composable tools (~14), strict schemas |
| Native/binary RE | ✅ Hopper/Ghidra/IDA/JEB, EVM, firmware | ❌ out of scope (web platforms only) |
| Web: passive CDP observation | ✅ V8 coverage, initiator stacks | ✅ (adopt pattern: evidence IDs, redaction) |
| Web: owned autonomous browser | ⚠️ scripted scenarios only | ✅ Playwright drives crawl + interactions itself |
| Multi-page crawl + site map | ❌ | ✅ |
| Interaction/state-transition discovery | ❌ (listener inspection only) | ✅ bounded safe exploration |
| Network/API catalog + UI linkage | ⚠️ events listed, not linked to UI actions | ✅ endpoint catalog joined to components/workflows |
| Secret redaction | ✅ (storage fingerprints, header exclusions) | ✅ (adopt + extend: headers, bodies, tokens) |
| Session pipeline + resumability | ❌ | ✅ staged engine, checkpoints |
| Evidence ledger + fusion | ⚠️ export only | ✅ dedup, OBSERVED/INFERRED/UNVERIFIED/BLOCKED |
| Reconstruction spec generation | ⚠️ obligation ledgers (guided) | ✅ full auto-generated blueprint |
| Verification (compare build) | ✅ capture/screenshot compare | ✅ route + behavior + visual compare |
| Benchmarks vs ground truth | ❌ (provider fixture tests only) | ✅ precision/recall on annotated targets |
| Install | npm, Node 22+ | pip, Python 3.10+ (venv) |

## 6. Reuse / improve / replace

- **Reuse the ideas:** evidence IDs + provenance on every finding; strict error contracts; secret redaction by default; CLI/MCP parity; "never claim equivalence from missing evidence"; skill-based agent routing docs.
- **Improve:** make the browser *owned and autonomous* (drive, don't just watch); fuse evidence across pages into one graph; generate the reconstruction spec automatically.
- **Replace:** the passive-only web posture for our use case; the binary-analysis stack (out of scope).
- **Independently implement:** session engine, staged pipeline, interaction explorer, spec generator, benchmark harness — none exist in REA.

**Bottom line:** REA is the best-in-class tool for *shipped-artifact* forensics with an honesty-first evidence model. OmniRecon's "more capable" claim is scoped to **web platforms**: where REA watches, OmniRecon drives — autonomous crawl, interaction, fusion, and blueprint generation that REA deliberately does not do.
