# OmniRecon Viral Playbook (v2.0)

How Cursor, v0, Tailwind, and LangChain actually went viral — applied to OmniRecon.
No "build community" hand-waving. Every item is actionable this week.

The pattern across all four: **one unforgettable demo** (v0's prompt→website GIF,
Cursor's tab-completion) + **zero-friction first run** (Tailwind's CDN script tag,
LangChain's `pip install`) + **an artifact people share without being asked**
(Tailwind's docs, LangChain's templates). OmniRecon has the demo (auto_pilot)
and the shareable artifact (teardown blueprints). What's missing is the loop
that connects them.

---

## 1. THE DEMO — the 60 seconds that make someone hit share

**Concept: "One command. Then it grades your clone."**

Nobody else has the verify loop. REA doesn't do web. v0 doesn't show receipts.
The demo's wow isn't the recon — it's the *receipts*: every claim cited, then
your rebuild scored against the original.

**Exact script (recorded, never live — see §5 Trap):**

| Time | Shot | Command / visual |
|---|---|---|
| 0:00–0:08 | Terminal, clean prompt | `$ omnirecon auto-pilot https://linear.app --depth quick` — timer starts |
| 0:08–0:35 | Fast-forward pipeline log (jump-cut, keep the tool names visible: `discover_routes → inspect_page → capture_network → analyze_ui → probe_endpoints → generate_spec`) | Timer hits ~2:00 |
| 0:35–0:45 | The output: `spec.json` opens — 15 sections; `tasks.json` — `build_tasks` with acceptance criteria | "One call. Build-ready blueprint." |
| 0:45–0:55 | Split screen: agent builds a clone from the blueprint (jump-cut), then `$ omnirecon compare-build <session> https://localhost:3000` | **"Rebuild score: 94/100"** ← THE frame people screenshot |
| 0:55–1:00 | Evidence ledger snippet: one claim → its cited finding → classification badge | "Nothing invented. Every claim cites its evidence." |

**Why Linear:** dev-famous, widely admired frontend, and the repo already has
`examples/teardown-linear/` seeded. If Linear's bot defenses make the recording
flaky, fallback target in order: Vercel homepage → Raycast → Arc. Pick the one
that records cleanly; fame of target matters less than a flawless 60 seconds.

**Deliverable this week:** one MP4/GIF, committed as `assets/demo-autopilot.mp4`
(+ GIF fallback), embedded at the top of the README above the fold. The user
records it on their own machine (sandbox browser egress is unreliable).

---

## 2. THE ARTIFACT — what people share organically

**Build: the Teardown Gallery + Rebuild Leaderboard.**

Create `examples/teardowns/` with this structure per teardown:

```
examples/teardowns/<target>/
  README.md        # the story: what the target is, what surprised us
  spec.json        # the 15-section blueprint
  tasks.json       # build_tasks + research_tasks
  evidence.jsonl   # the ledger (receipts)
  screenshots/     # captured viewports
  rebuild-score.md # compare_build output if a clone was attempted
```

And a leaderboard table in the main README:

| Target | Findings | Rebuild score | Teardown |
|---|---|---|---|
| linear.app | 312 | 94/100 | [link] |
| … | | | |

**Why this works (the v0/Tailwind lesson):** the gallery is content marketing
that doesn't look like marketing. "Here's Linear's full frontend blueprint,
every API endpoint mapped" is a link devs *want* to share — each teardown is a
backlink magnet and an HN-worthy post on its own. The leaderboard adds the
competitive mechanic: scores are inherently screenshot-able ("my clone scored
94").

**Seed it this week:** 3 teardowns minimum before launch (Linear + 2). Then add
`.github/ISSUE_TEMPLATE/teardown-request.md` — "Request a teardown" — so the
community votes on the next target. Every voted teardown is a guaranteed
audience for the result.

---

## 3. THE LOOP — one user's success brings the next user

**The flywheel, concretely:**

1. User runs `auto-pilot` on a target they care about → gets a blueprint.
2. Gallery + issue template invite them to **contribute the teardown back**
   (one PR adding `examples/teardowns/<target>/`).
3. Each contributed teardown is a standalone shareable page (target's fans
   share "the X blueprint") → new visitors → new stars.
4. New visitors run auto-pilot → step 1 repeats.
5. The **rebuild score** is the accelerant: anyone who clones from a blueprint
   posts their score. Scores → competition → more clones → more teardowns.

**The compounding detail:** every teardown README links back to the install
(one-click via Smithery, §4 step 2). The artifact *is* the distribution.

**This week's action:** write `examples/teardowns/CONTRIBUTING.md` (5 lines:
run auto-pilot, copy the 6 files, open a PR) and the issue template. The loop
must exist before launch traffic arrives, or the traffic evaporates.

---

## 4. THE LAUNCH — ranked 5-step sequence

Order matters: registries before HN (so HN visitors can install in one click),
HN before X (so the thread amplifies an already-live discussion).

**Step 1 — Seed (Mon): finish the ammunition.**
Record the demo, commit 3 teardowns, write the gallery contributing guide +
issue template. Nothing public yet.

**Step 2 — Registries (Tue): kill install friction.**
Submit to Smithery, mcp.so, PulseMCP, Glama (checklist already in
LAUNCH_DRAFTS.md). Smithery's one-click install is the single highest-leverage
friction fix: it bypasses the Chromium-download drop-off entirely.

**Step 3 — Show HN (Wed or Thu, 9–11am US Eastern): the honesty post.**
Use the v2.0 failure-story draft in LAUNCH_DRAFTS.md verbatim — HN upvotes
"I found the bug in my own product" and destroys "revolutionary AI" claims.
Title: *Show HN: OmniRecon v2 – reverse-engineer any software with one tool call*.
Body leads with the failure, then the fix, then the teardown link. Founder
replies to every technical comment within the hour (this is what separates
front-page from buried).

**Step 4 — X thread (same day, 30 min after HN post): amplify.**
The v2.0 thread in LAUNCH_DRAFTS.md. Hook tweet is the failure story, tweet 3
is the demo GIF, final tweet links HN ("discussing live on HN"). Quote-tweet,
don't duplicate.

**Step 5 — The unconventional channel (Thu/Fri): teardown as content.**
Post ONE teardown blueprint (not the repo) to r/webdev as "I mapped Linear's
entire frontend API surface — here's the blueprint (method + data)". Same for
Indie Hackers. These audiences share teardowns, not tools — the blueprint is
the trojan horse, and every one links the repo. This is the Tailwind-docs play:
give away the valuable thing free, the tool rides along.

---

## 5. THE TRAP — the #1 virality killer

**Install friction + a demo that fails live. Either one kills it stone dead.**

Concretely:
- The `./install.sh` path downloads ~300MB of Chromium into a Python venv.
  Measured drop-off on multi-step installs is brutal — v0 won on "type and
  see," Cursor won on "download and tab." If the HN front page sends 10k
  visitors and half bounce at the install, the launch is wasted.
- A live demo against a JS-heavy target can hit bot detection, a slow page,
  or a timeout — one frozen terminal on the recording and the "one call"
  claim becomes a meme.

**Mitigations (do before Step 3):**
1. Smithery one-click install live (Step 2) — non-negotiable before HN.
2. Demo is **recorded, edited, 60 seconds** — never live, never a stream.
3. `auto-pilot --depth quick` must finish in under 2 minutes on the demo
   target, verified 3× on the recording machine.
4. README's first screen: GIF → one-click install → 3-line quickstart. No
   scrolling to understand what it does.
5. Never claim "reverse-engineer *anything*" without the honesty footnote —
   HN will find the overclaim in minutes and the thread becomes about that.
   The failure-story framing in the v2.0 draft is the shield; keep it.

---

## This-week checklist

- [ ] Record + edit the 60s demo (user's machine), commit to `assets/`
- [ ] 3 seeded teardowns in `examples/teardowns/` + gallery contributing guide
- [ ] `.github/ISSUE_TEMPLATE/teardown-request.md`
- [ ] Leaderboard table in README
- [ ] Registry submissions (Smithery, mcp.so, PulseMCP, Glama)
- [ ] Post Show HN (Wed/Thu 9–11am ET) + X thread same day
- [ ] Teardown-as-content post to r/webdev + Indie Hackers
