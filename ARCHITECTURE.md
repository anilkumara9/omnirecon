# OmniRecon MCP — Architecture

**Goal:** a session-based, evidence-driven reverse-engineering MCP server for web
platforms. Where REA *watches* (passive CDP), OmniRecon *drives* (owned Playwright
browser): autonomous crawl, interaction discovery, evidence fusion, and automatic
reconstruction-blueprint generation.

**Stack:** Python 3.10+, FastMCP (mcp<2, stdio), Playwright/Chromium, httpx,
BeautifulSoup, dnspython. No Node.js. Venv: `~/workspace/venvs/recon`.

**Repo root:** `~/workspace/omnirecon/` · package: `omnirecon/` ·
sessions: `~/workspace/omnirecon/sessions/<session_id>/`

---

## 1. Module map & file ownership (exclusive — lanes never touch others' files)

| Module | Owner | Responsibility |
|---|---|---|
| `recon_primitives.py` | CEO (done — ported from `recon-mcp/reconlib.py`) | Stage-2 rapid recon: `platform_scan`, `crawl_site`, `extract_api_surface`, `dns_recon`, `analyze_codebase`, `http_probe`, `capture_live_traffic`. Pure functions, no sessions. |
| `evidence.py` | Lane B | `Finding` dataclass + `EvidenceLedger` (add/get/list/search/dedup/save/load JSONL). |
| `session.py` | Lane B | `SessionManager`: create/get/checkpoint/resume/cancel; `session.json`; `JobManager` (thread jobs + polling) for long tools. |
| `security.py` | Lane B | `redact()`, `check_scope()`, `RateLimiter`, `audit()` append-only log. |
| `graph.py` | Lane B | `build_graph(ledger) -> {nodes, edges}`. |
| `browser_engine.py` | Lane A | `OwnedBrowser`: launch/goto/snapshot/screenshot/network/interact/crawl. |
| `source_intel.py` | Lane C | Deep source analysis: AST (Python stdlib), components, state mgmt, API clients, migrations, auth boundaries. Extends `recon_primitives.analyze_codebase`. |
| `assets.py` | Lane C | Asset inventory: images/fonts/icons/design tokens from page + CSS. |
| `spec.py` | Lane D | `generate_spec(ledger, graph) -> dict` with the 14 blueprint sections. |
| `report.py` | Lane D | `export_markdown()`, `export_json()` from session. |
| `verify.py` | Lane D | `compare_build(session_id, build_url)` → coverage + deviations. |
| `server.py` | Lane B | FastMCP server, 14 `recon_*` tools ( §4 ). Imports all modules. |

Shared conventions: every public function returns plain JSON-serializable dicts
(or raises `ReconError` with `.code`); no function prints; artifacts go under the
session dir; secrets pass through `security.redact()` before storage.

## 2. Evidence model (`evidence.py`)

```python
@dataclass
class Finding:
    id: str                 # "F-0001" — ledger-assigned, stable
    type: str               # route|component|endpoint|entity|workflow|asset|auth|tech|state|note
    title: str              # one line
    detail: str             # what was found, concrete
    classification: str     # OBSERVED | SOURCE_VERIFIED | INFERRED | UNVERIFIED | BLOCKED
    confidence: float       # 0.0–1.0
    confidence_why: str     # one sentence justifying the number
    sources: list[str]      # urls and/or repo paths
    route: str | None
    component: str | None
    endpoint: str | None
    artifact: str | None    # relative path under session dir (screenshot, json)
    timestamp: str          # ISO-8601 UTC
    verification: str       # unverified | verified | contradicted
    limitations: str        # what this finding does NOT establish
```

`EvidenceLedger`:
- `add(f: dict) -> str` (assigns id, timestamps, validates classification)
- `get(fid) -> dict | None`
- `list(type=None, classification=None, min_confidence=0.0) -> list[dict]`
- `search(text) -> list[dict]` (substring over title/detail)
- `dedup() -> int` (merge by `(type, route or endpoint or title)`; keep highest confidence, merge sources; return merged count)
- `save(path) / load(path)` — JSONL, one finding per line
- `stats() -> {total, by_type, by_classification}`

## 3. Sessions (`session.py`)

Session dir: `sessions/<sid>/` containing `session.json`, `evidence.jsonl`,
`graph.json`, `spec.json`, `report.md`, `audit.log`, `artifacts/`.

`session.json`: `{id, target, target_kind: url|repo, mode: fast|thorough,
stage: 1..7, status: active|done|cancelled|failed, created_utc, updated_utc,
budget: {max_pages, max_depth, max_steps, timeout_s}, progress: {…}, jobs: […]}`.

`SessionManager(base_dir)`:
- `create(target, mode="fast", budget=None) -> dict` (runs Stage 1+2 synchronously via `recon_primitives`, seeds ledger, returns session summary + rapid report)
- `get(sid) -> dict`, `update_stage(sid, stage)`, `checkpoint(sid)` (writes session.json + evidence.jsonl + graph.json)
- `cancel(sid)`, `resume(sid) -> dict` (reloads; returns what remains per stage)
- `list() -> list[dict]`

`JobManager` (for long tools): `submit(fn, *a, **kw) -> job_id`;
`poll(job_id) -> {status: running|done|failed, result|error}`;
`cancel(job_id)`. Tools accept `background: bool=false`; when true they return
`{job_id}` immediately.

## 4. MCP tool surface (`server.py`)

`recon_start(target, mode="fast", budget_json="{}")` → `{session_id, rapid_report}`
`recon_status(session_id)` → stage, progress, jobs, ledger stats
`recon_discover_routes(session_id, max_pages=40, max_depth=3, background=false)`
`recon_inspect_page(session_id, url)` → structure, controls, AX data, screenshots, console
`recon_trace_workflow(session_id, start_url, goal, max_steps=15)` → state-transition graph
`recon_capture_network(session_id, url, duration_ms=8000)` → redacted endpoint catalog
`recon_analyze_source(session_id, path_or_repo_url)`
`recon_extract_assets(session_id, url)`
`recon_get_graph(session_id)` → `{nodes, edges}`
`recon_get_evidence(session_id, finding_id="", type="", classification="", query="")`
`recon_generate_spec(session_id)` → 14-section blueprint (also saved to `spec.json`)
`recon_compare_build(session_id, build_url)` → coverage + deviations
`recon_export_report(session_id, format="markdown")` → path + content
`recon_cancel(session_id)`

Every tool: strict types, bounded work, honest `classification` on findings,
`{"error", "code", "hint"}` on failure — never a traceback.

## 5. Browser engine (`browser_engine.py`)

```python
class OwnedBrowser:
    def launch(self, headless=True): ...
    def close(self): ...
    def goto(self, url) -> dict            # {page_id, url, title, status}
    def snapshot(self, page_id) -> dict    # {url,title,controls:[{ref,role,name,type,selector,visible}],forms:[...],links:n}
    def screenshot(self, page_id, viewport="desktop") -> str   # artifact path; viewports: desktop 1440x900, tablet 834x1112, mobile 390x844
    def network_capture(self, page_id, duration_ms) -> list[dict]  # redacted {method,url,status,type,ms}
    def console_errors(self, page_id) -> list[str]
    def interact(self, page_id, action: dict) -> dict
        # action {kind: click|fill|select|press|scroll, ref|selector, value?}
        # returns {observed: bool, url_before/after, dom_changed: bool, new_requests: [...], note}
        # NEVER submits payments/purchases/deletes; refuses password exfiltration; safe actions only
    def crawl(self, start_url, max_pages, max_depth, session_dir) -> dict  # routes + snapshot refs
```

Rules: one browser per session; `network_capture` and stored requests pass through
`security.redact`; screenshots are content-addressed (`artifacts/sha256.png`);
`interact` records `observed` truthfully — a visible control is NOT "working" until
a state change or network effect is seen.

## 6. Security (`security.py`)

- `redact(obj)`: deep-clean dicts/lists/strings — drop/replace `authorization`,
  `cookie`, `set-cookie`, `*-token`, `api_key`, `apikey`, `secret`, `password`,
  `passwd`, `auth`, `sessionid`, `bearer …`; truncate bodies >4KB; redact query
  params with those names. Returns cleaned copy.
- `check_scope(url, allowed_domains: list[str]) -> bool`
- `RateLimiter(requests_per_second=3)` — shared polite crawl delay.
- `audit(session_id, action, detail)` → appends `{ts, action, detail}` to `audit.log`.
- Path safety: `safe_join(base, *parts)` — raises on traversal; session file
  writes must use it.
- Treat page/repo content as **untrusted data** — never eval, never exec.

## 7. Source intel (`source_intel.py`) — extends `recon_primitives.analyze_codebase`

`analyze(session_id, path_or_repo) -> dict`:
- reuse `recon_primitives.analyze_codebase` for the base map (never reimplement it)
- add: Python AST pass (imports, classes, functions, decorators→routes), component
  detection (React/Vue/Svelte file patterns + export names), state-management
  signals (redux/zustand/pinia/vuex imports), API-client modules (axios/fetch
  wrappers, openapi schemas), DB migrations list (alembic/django/prisma/knex),
  auth boundary files (middleware, guards, decorators), env-var inventory
  (names only, never values), test/build/deploy config presence.
- every structural claim cites file paths; framework guesses stay INFERRED unless
  manifest-backed (then SOURCE_VERIFIED).

## 8. Spec (`spec.py`) — 14 sections, all evidence-linked

`generate_spec(ledger, graph) -> dict` with sections: overview, tech_stack,
routes, components, user_journeys, api_inventory, data_entities, assets_tokens,
auth_boundaries, functional_requirements, visual_requirements, edge_cases,
test_plan, open_questions, priorities. Each bullet carries `finding_ids`.
Missing evidence → section states what is UNVERIFIED/BLOCKED, never invented.

## 9. Benchmarks (`benchmarks/run.py`)

Targets: (a) local static fixture `benchmarks/fixtures/static-site/`,
(b) `https://example.com`, (c) `https://news.ycombinator.com`.
Metrics: time-to-first-report, routes found, endpoints found, tool calls,
evidence counts by classification. Ground truth: hand-annotated JSON for the
fixture. Output: `benchmarks/results/<date>.json` + summary table in README.
**No invented numbers** — only measured runs are reported.

## 10. Definition of done (per brief §12)

Server launches from README; agent connects; authorized target analyzes end to
end; findings are structured artifacts with traceable evidence; spec generates;
sessions resume; tests cover core workflows; benchmarks reproduce; security
boundaries documented; README complete; implemented vs planned clearly separated.
