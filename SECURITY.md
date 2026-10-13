# Security Policy

OmniRecon is a reverse-engineering tool: it inspects software — web
platforms, APIs, codebases, and shipped artifacts — and writes down what it
observes. Because the tool operates near credentials, private code, and live
systems, this policy states exactly what it does and does not do, and how to
report a problem.

## What OmniRecon does

- **Reads and observes.** Crawls routes, renders pages in an owned headless
  browser, captures the network traffic its own browser generates, parses
  local code and binaries, and records everything in a classified evidence
  ledger (`OBSERVED` / `SOURCE_VERIFIED` / `INFERRED` / `UNVERIFIED` /
  `BLOCKED`).
- **Authenticated recon only with the operator's own credentials.**
  `recon_authenticate` performs a browser login using credentials the
  operator explicitly supplies for targets they own or are authorized to
  test. The password is used transiently and never stored; session cookies
  are saved with `0600` permissions and cleared on `recon_deauthenticate`.
- **Redacts secrets centrally.** API keys, tokens, passwords, OAuth codes,
  and session identifiers are scrubbed in `EvidenceLedger.add()` before any
  finding becomes durable state — across titles, details, URLs, sources,
  and captured shapes. Typed password values are never captured from form
  fields, including in snapshots and control names.
- **Treats target content as untrusted data.** Page text, third-party JS,
  and repository files are analyzed, never executed as instructions; the
  tool does not follow instructions embedded in a target.

## What OmniRecon does not do

- No credential theft, session hijacking, or privilege escalation.
- No CAPTCHA, paywall, or bot-protection bypass — blocked areas become
  `BLOCKED` findings, not workarounds.
- No destructive actions: no purchases, payments, deletions, emails, or
  other external side effects. The browser engine refuses actions whose
  target looks destructive, and consequential actions require explicit user
  approval.
- No state-changing form submissions during recon by default.
- `.env` *values* are never read — only variable *names* from example
  files. Credential-bearing local paths (`~/.ssh`, `~/.aws`, private keys)
  are refused by `recon_analyze_source`.
- No exfiltration: findings stay in the session directory on the operator's
  machine.

Intended use is limited to applications the operator owns, has permission
to test, or is otherwise authorized to inspect.

## Reporting a vulnerability

If you find a security issue — particularly a secret-leak path, a redaction
bypass, a way to trigger destructive actions, or a scope-escape — please
report it privately:

- Email: `security@[yourdomain]` (maintainer: replace with the real address
  before publishing)
- Include: what you did, what you expected, what actually happened, and the
  OmniRecon version/commit.

Please do not open a public issue for a suspected vulnerability. We will
acknowledge within a reasonable time and fix verified issues before
disclosing.

## Scope notes for researchers

- The evidence ledger (`sessions/<id>/evidence.jsonl`) is the ground truth
  for redaction claims: a value is "not captured" only if it is absent from
  that file. Tests in `tests/test_browser_engine.py` and
  `tests/test_evidence.py` encode the current guarantees — a report that
  includes a failing test gets priority.
- Known accepted risks (documented, not bugs): the operator's password
  transits MCP arguments and server memory by design during
  `recon_authenticate`; do not run authenticated recon in shared or
  multi-tenant deployments.
