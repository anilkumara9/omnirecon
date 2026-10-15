#!/usr/bin/env bash
#
# OmniRecon one-command installer.
#
#   ./install.sh [--client <name|auto>]
#
# Or straight from the internet, no clone needed:
#   curl -fsSL https://raw.githubusercontent.com/anilkumara9/omnirecon/main/install.sh \
#     | bash -s -- --client auto
#
# What it does:
#   1. (curl-pipe only) clones the repo to ~/omnirecon
#   2. Checks for python3 (>= 3.10)
#   3. Creates .venv/ in the repo root (reuses it if present)
#   4. Installs requirements.txt into the venv
#   5. Installs Playwright's Chromium (~300MB, skipped if already present)
#   6. Verifies the install
#   7. With --client: configures your agent automatically (no manual JSON)
#
# Idempotent: safe to re-run; steps that are already done are skipped.
# No machine-specific paths: everything resolves relative to this script.
set -euo pipefail

# -- helpers ---------------------------------------------------------------
info()  { printf '\033[1;34m[omnirecon]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
fail()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# -- flags -----------------------------------------------------------------
CLIENT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --client=*) CLIENT="${1#--client=}"; shift ;;
        --client) CLIENT="${2:-}"; shift 2 ;;
        -h|--help)
            echo "Usage: ./install.sh [--client <claude-code|codex|cursor|windsurf|zed|generic|auto>]"
            echo "   or: curl -fsSL .../install.sh | bash -s -- --client auto"
            exit 0 ;;
        *) fail "unknown flag: $1 (try --help)" ;;
    esac
done

# -- curl-pipe bootstrap -----------------------------------------------------
# When piped via curl, this script isn't inside the repo yet. Clone it and
# re-exec from the clone so the rest of the script is unchanged.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd 2>/dev/null || echo "")"
if [ ! -f "$_SCRIPT_DIR/requirements.txt" ]; then
    DEST="${OMNIRECON_DIR:-$HOME/omnirecon}"
    if [ -f "$DEST/requirements.txt" ]; then
        info "found existing checkout at $DEST"
    else
        command -v git >/dev/null 2>&1 \
            || fail "git not found — install git first: https://git-scm.com/downloads"
        info "cloning OmniRecon to $DEST ..."
        git clone --depth 1 https://github.com/anilkumara9/omnirecon.git "$DEST" \
            || fail "git clone failed — check your network connection."
    fi
    if [ -n "$CLIENT" ]; then
        exec bash "$DEST/install.sh" --client="$CLIENT"
    else
        exec bash "$DEST/install.sh"
    fi
fi

# Repo root = directory containing this script (no hardcoded paths).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PLAYWRIGHT="$VENV/bin/playwright"

info "Installing OmniRecon from $REPO_ROOT"

# -- 1. python3 >= 3.10 -----------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found. Install Python 3.10+ first: https://www.python.org/downloads/"
fi
PYVER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYMAJOR="$(python3 -c 'import sys; print(sys.version_info.major)')"
PYMINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
if [ "$PYMAJOR" -lt 3 ] || { [ "$PYMAJOR" -eq 3 ] && [ "$PYMINOR" -lt 10 ]; }; then
    fail "python3 is $PYVER — OmniRecon needs Python 3.10 or newer."
fi
ok "python3 $PYVER found"

# -- 2. virtualenv (reuse if present) ---------------------------------------
if [ -x "$PY" ]; then
    ok "reusing existing venv at .venv/"
else
    info "creating virtualenv at .venv/ ..."
    python3 -m venv "$VENV" || fail "could not create virtualenv (is python3-venv installed? on Debian/Ubuntu: sudo apt install python3-venv)"
    ok "virtualenv created"
fi

# -- 3. pip dependencies ----------------------------------------------------
if [ ! -f "$REPO_ROOT/requirements.txt" ]; then
    fail "requirements.txt not found in $REPO_ROOT — is this the OmniRecon repo root?"
fi
info "installing Python dependencies (this can take a minute) ..."
"$PIP" install --quiet --disable-pip-version-check -r "$REPO_ROOT/requirements.txt" \
    || fail "pip install failed — check your network connection and try again."
ok "dependencies installed"

# sanity: the pinned mcp<2 must hold (mcp 2.x removed the FastMCP API)
MCP_MAJOR="$("$PY" -c "from importlib.metadata import version; print(version('mcp').split('.')[0])" 2>/dev/null || echo "?")"
if [ "$MCP_MAJOR" = "1" ]; then
    ok "mcp 1.x confirmed (FastMCP API intact)"
elif [ "$MCP_MAJOR" != "?" ]; then
    warn "mcp major version is $MCP_MAJOR (expected 1.x) — continuing anyway"
fi

# -- 4. Playwright Chromium (~300MB; skipped when already present) -----------
# Idempotency check: look for any installed chromium headless shell.
if ls ~/.cache/ms-playwright/chromium_headless_shell-* >/dev/null 2>&1 \
   || ls ~/.cache/ms-playwright/chromium-* >/dev/null 2>&1; then
    ok "Playwright Chromium already installed — skipping download"
else
    info "downloading Playwright Chromium (~300MB, one-time) ..."
    info "this is the slow step — grab a coffee, it resumes cleanly if interrupted."
    "$PLAYWRIGHT" install chromium \
        || fail "Chromium download failed — check your network/proxy and re-run ./install.sh"
    ok "Chromium installed"
fi

# -- 5. verify ---------------------------------------------------------------
info "verifying the install ..."
"$PY" -m omnirecon.cli --help >/dev/null 2>&1 \
    || fail "verification failed: 'python -m omnirecon.cli --help' did not run."
TOOL_COUNT="$("$PY" - <<'EOF'
import sys; sys.path.insert(0, ".")
from omnirecon import server as SRV
import asyncio
tools = asyncio.run(SRV.mcp.list_tools())
print(len(tools))
EOF
)"
ok "OmniRecon installed — $TOOL_COUNT MCP tools available"

# -- next steps --------------------------------------------------------------
if [ -n "$CLIENT" ]; then
    info "configuring agent client: $CLIENT ..."
    if "$PY" -m omnirecon.cli setup "$CLIENT" >/tmp/omnirecon_setup.json 2>&1; then
        ok "agent configured"
        "$PY" -c "
import json
r = json.load(open('/tmp/omnirecon_setup.json'))
for c in r.get('clients', []):
    name = c.get('client', '?')
    if c.get('changed'):
        print(f'  [ok] {name}: {c.get(\"note\", \"configured\")}')
    elif c.get('error'):
        print(f'  [warn] {name}: {c[\"error\"]}')
    else:
        print(f'  [ok] {name}: {c.get(\"note\", \"ok\")}')
    if c.get('restart'):
        print(f'       -> {c[\"restart\"]}')
" 2>/dev/null || true
    else
        warn "automatic client setup had issues — run this yourself:"
        warn "  $PY -m omnirecon.cli setup $CLIENT"
    fi
    cat <<EOF

  Done. Restart your agent, then ask it:
    "Reverse-engineer https://example.com"
EOF
else
    cat <<EOF

  Installation complete. Connect your agent with one command (no manual JSON):

    $PY -m omnirecon.cli setup auto

  Or pick a client explicitly: claude-code, codex, cursor, windsurf, zed, generic.

  No MCP client? Use the terminal instead:
    $PY -m omnirecon.cli recon-start https://example.com --mode fast

  Note: browser tools take 30-60s per page (real Chromium) — that's normal.
  Full guide: $REPO_ROOT/README.md ("Connecting your agent")
EOF
fi
