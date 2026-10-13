"""Lane C — deep source-code intelligence.

`analyze(session_id, path_or_repo_url) -> dict`

Builds on recon_primitives.analyze_codebase (the base map) and adds:
  - Python AST pass: imports, classes, functions, route decorators/calls
    (FastAPI/Flask/Django) with file:line precision
  - component detection (React/Vue/Svelte/Angular file patterns + export names)
  - state-management signals (redux/zustand/pinia/vuex/ngrx/...)
  - API-client modules + OpenAPI/Swagger schemas
  - DB migration inventory (names only)
  - auth boundary files (middleware/guards/decorators)
  - env-var inventory (NAMES only — never values, never reads .env)
  - test/build/deploy config presence

Every structural claim cites file paths. Framework claims are
SOURCE_VERIFIED only when manifest-backed, else INFERRED.
Findings are appended to the session evidence ledger
(Lane B's EvidenceLedger when importable, else a schema-compatible
JSONL fallback at sessions/<sid>/evidence.jsonl).

Never executes repo code — files are only read and parsed.
"""
from __future__ import annotations

import ast
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omnirecon import recon_primitives as RP  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.path.join(REPO_ROOT, "sessions")

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".next", "target", "vendor", ".idea", ".vscode",
              ".tox", ".eggs", "__pypackages__"}
_MAX_PY_FILES = 400
_MAX_FILE_BYTES = 500_000

_ROUTE_DECORATOR_RE = re.compile(
    r"(?:^|\.)(get|post|put|patch|delete|options|head|route|all)\s*$",
    re.IGNORECASE)
_DJANGO_PATH_RE = re.compile(r"(?:^|\.)(path|re_path|url)\s*$")

_COMPONENT_EXPORT_RES = [
    re.compile(r"export\s+(?:default\s+)?(?:function|class)\s+([A-Z][A-Za-z0-9_]*)"),
    re.compile(r"export\s+(?:default\s+)?const\s+([A-Z][A-Za-z0-9_]*)\s*="),
    re.compile(r"module\.exports\s*=\s*([A-Z][A-Za-z0-9_]*)"),
    re.compile(r"export\s*\{\s*([A-Z][A-Za-z0-9_]*)\s*\}"),
]
_ANGULAR_COMPONENT_RE = re.compile(r"export\s+class\s+(\w+Component)\b")
_VUE_NAME_RE = re.compile(r"""name\s*:\s*['"]([\w-]+)['"]""")

_STATE_MGMT_LIBS = {
    "redux": "Redux", "@reduxjs/toolkit": "Redux Toolkit",
    "zustand": "Zustand", "pinia": "Pinia", "vuex": "Vuex",
    "mobx": "MobX", "recoil": "Recoil", "jotai": "Jotai",
    "@ngrx/store": "NgRx", "xstate": "XState",
}

_AUTH_NAME_RE = re.compile(r"(auth|login|jwt|session|passport|oauth|guard|middleware)",
                           re.IGNORECASE)
_AUTH_DECORATOR_RE = re.compile(
    r"(login_required|jwt_required|auth_required|authenticated|authorize|"
    r"require_auth|protected)", re.IGNORECASE)

_CONFIG_FILES = [
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile",
    "pytest.ini", "setup.cfg", "tox.ini", "pyproject.toml", "requirements.txt",
    "package.json", "tsconfig.json", "jest.config.js", "jest.config.ts",
    "vite.config.js", "vite.config.ts", "webpack.config.js",
    ".github/workflows", ".gitlab-ci.yml", "vercel.json", "netlify.toml",
    "Procfile", "go.mod", "Cargo.toml", "Gemfile", "pom.xml",
    "build.gradle", "build.gradle.kts", "composer.json",
]

_MIGRATION_DIR_RES = [
    re.compile(r"(^|/)migrations(/|$)"),
    re.compile(r"(^|/)alembic(/|$)"),
    re.compile(r"(^|/)versions(/|$)"),          # alembic/versions
    re.compile(r"(^|/)prisma(/|$)"),
]


# --------------------------------------------------------------------------
# evidence ledger helper (Lane B compatible, with fallback)
# --------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ledger_append(session_id: str, finding: dict) -> str | None:
    """Append one finding dict to sessions/<sid>/evidence.jsonl.

    Uses Lane B's EvidenceLedger when importable; otherwise writes a
    schema-compatible JSONL line directly (same field names as the
    Finding dataclass in ARCHITECTURE.md §2).
    """
    os.makedirs(os.path.join(SESSIONS_DIR, session_id), exist_ok=True)
    ledger_path = os.path.join(SESSIONS_DIR, session_id, "evidence.jsonl")

    # 1) try Lane B's ledger (load is a classmethod returning a new ledger)
    try:
        from omnirecon import evidence as ev
        if os.path.exists(ledger_path):
            ledger = ev.EvidenceLedger.load(ledger_path)
        else:
            ledger = ev.EvidenceLedger()
        fid = ledger.add(finding)
        ledger.save(ledger_path)
        return fid
    except Exception:
        pass

    # 2) fallback: compatible JSONL append
    try:
        n = 0
        if os.path.exists(ledger_path):
            with open(ledger_path, "r", encoding="utf-8") as fh:
                n = sum(1 for line in fh if line.strip())
        f = dict(finding)
        f.setdefault("id", f"F-{n + 1:04d}")
        f.setdefault("timestamp", _utcnow())
        f.setdefault("verification", "unverified")
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(f, ensure_ascii=False, default=str) + "\n")
        return f["id"]
    except Exception:
        return None


def _record(session_id: str, ftype: str, title: str, detail: str,
            classification: str, confidence: float, confidence_why: str,
            sources: list, route=None, component=None, endpoint=None,
            limitations=""):
    _ledger_append(session_id, {
        "type": ftype,
        "title": title,
        "detail": detail,
        "classification": classification,
        "confidence": confidence,
        "confidence_why": confidence_why,
        "sources": sources,
        "route": route,
        "component": component,
        "endpoint": endpoint,
        "artifact": None,
        "verification": "unverified",
        "limitations": limitations,
    })


# --------------------------------------------------------------------------
# repo resolution (local path or shallow git clone)
# --------------------------------------------------------------------------

def _resolve_root(target: str):
    """Return (root_path, tempdir_or_None, note)."""
    if target.startswith(("http://", "https://")):
        tmp = tempfile.mkdtemp(prefix="omnirecon_src_")
        cp = subprocess.run(
            ["git", "clone", "--depth", "1", target, tmp],
            capture_output=True, text=True, timeout=180)
        if cp.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {cp.stderr[:300]}")
        return tmp, tmp, f"shallow-cloned {target}"
    root = os.path.abspath(os.path.expanduser(target))
    if not os.path.isdir(root):
        raise RuntimeError(f"directory does not exist: {target}")
    return root, None, "local directory"


def _iter_files(root: str, exts: set[str], max_files: int = 2000):
    """Yield (rel_path, abs_path) for files with given extensions."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in exts:
                ap = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(ap) > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                out.append((os.path.relpath(ap, root), ap))
                if len(out) >= max_files:
                    return out
    return out


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# Python AST pass
# --------------------------------------------------------------------------

def _dotted_name(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _ast_pass(root: str) -> dict:
    """Parse Python files with stdlib ast. Returns imports/classes/functions/routes."""
    imports: dict[str, list[str]] = {}
    classes: list[dict] = []
    functions: list[dict] = []
    routes: list[dict] = []
    files_parsed = 0

    for rel, ap in _iter_files(root, {".py"}, _MAX_PY_FILES):
        try:
            tree = ast.parse(_read_text(ap), filename=rel)
        except (SyntaxError, ValueError):
            continue
        files_parsed += 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imports.setdefault(a.name.split(".")[0], []).append(
                        f"{rel}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.setdefault(node.module.split(".")[0], []).append(
                        f"{rel}:{node.lineno}")
            elif isinstance(node, ast.ClassDef):
                classes.append({"name": node.name, "file": rel,
                                "line": node.lineno,
                                "methods": sum(isinstance(n, (ast.FunctionDef,
                                                              ast.AsyncFunctionDef))
                                               for n in node.body)})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append({"name": node.name, "file": rel,
                                  "line": node.lineno,
                                  "decorators": [_dotted_name(d.func)
                                                 if isinstance(d, ast.Call)
                                                 else _dotted_name(d)
                                                 for d in node.decorator_list]})
                for dec in node.decorator_list:
                    call = dec if isinstance(dec, ast.Call) \
                        else None
                    dname = _dotted_name(call.func) if call \
                        else _dotted_name(dec)
                    short = dname.rsplit(".", 1)[-1]
                    if _ROUTE_DECORATOR_RE.search(dname) \
                            or _AUTH_DECORATOR_RE.search(short):
                        path = _first_str_arg(call) if call else None
                        if path and _ROUTE_DECORATOR_RE.search(dname):
                            routes.append({"route": path, "file": rel,
                                           "line": node.lineno,
                                           "via": f"@{dname}",
                                           "auth_decorated":
                                               bool(_AUTH_DECORATOR_RE.search(
                                                   " ".join(functions[-1][
                                                       "decorators"])))})
            elif isinstance(node, ast.Call):
                cname = _dotted_name(node.func)
                if _DJANGO_PATH_RE.search(cname):
                    path = _first_str_arg(node)
                    if path:
                        routes.append({"route": path, "file": rel,
                                       "line": node.lineno,
                                       "via": cname,
                                       "auth_decorated": False})
    return {"imports": imports, "classes": classes, "functions": functions,
            "routes": routes, "files_parsed": files_parsed}


# --------------------------------------------------------------------------
# JS/TS component + state-management detection (regex-based; no tree-sitter)
# --------------------------------------------------------------------------

def _js_component_pass(root: str) -> dict:
    components: list[dict] = []
    state_signals: list[dict] = []
    api_clients: list[dict] = []
    exts = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}
    seen_state: set[str] = set()

    for rel, ap in _iter_files(root, exts, 2000):
        low = rel.lower()
        try:
            text = _read_text(ap)
        except OSError:
            continue
        head = text[:200_000]

        # --- state management imports ---
        for m in re.finditer(
                r"""(?:import|require)\s*[^'"]*['"]([^'"]+)['"]""", head):
            lib = m.group(1)
            for key, label in _STATE_MGMT_LIBS.items():
                if lib == key or lib.startswith(key + "/"):
                    if label not in seen_state:
                        seen_state.add(label)
                        state_signals.append(
                            {"library": label, "import": lib, "file": rel})

        # --- API client modules ---
        if ("axios" in head and "import" in head) or \
                (re.search(r"\baxios\s*\.", head)):
            api_clients.append({"file": rel, "kind": "axios"})
        elif ("api" in low or "client" in low or "service" in low) and \
                re.search(r"\bfetch\s*\(", head):
            api_clients.append({"file": rel, "kind": "fetch-wrapper"})
        if re.search(r"""['"]openapi['"]\s*:\s*['"]3\.""", head):
            api_clients.append({"file": rel, "kind": "openapi-schema"})

        # --- components ---
        names: list[str] = []
        if low.endswith(".vue"):
            m = _VUE_NAME_RE.search(head)
            names.append(m.group(1) if m
                         else os.path.splitext(os.path.basename(rel))[0])
            components.append({"name": names[-1], "file": rel,
                               "framework": "Vue"})
            continue
        if low.endswith(".svelte"):
            components.append({
                "name": os.path.splitext(os.path.basename(rel))[0],
                "file": rel, "framework": "Svelte"})
            continue
        is_angular = low.endswith(".component.ts")
        is_reactish = (low.endswith((".jsx", ".tsx"))
                       or "/components/" in low or "component" in low)
        if not (is_angular or is_reactish):
            continue
        if is_angular:
            m = _ANGULAR_COMPONENT_RE.search(head)
            if m:
                components.append({"name": m.group(1), "file": rel,
                                   "framework": "Angular"})
            continue
        for rx in _COMPONENT_EXPORT_RES:
            for m in rx.finditer(head):
                nm = m.group(1)
                if nm and not any(c["name"] == nm and c["file"] == rel
                                  for c in components):
                    # keep only plausible component names (avoid consts like API_URL)
                    if re.match(r"^[A-Z][A-Za-z0-9]*$", nm):
                        components.append({"name": nm, "file": rel,
                                           "framework": "React-like"})
    return {"components": components[:300],
            "state_management": state_signals,
            "api_clients": api_clients[:100]}


# --------------------------------------------------------------------------
# migrations / auth / env names / configs
# --------------------------------------------------------------------------

def _migration_inventory(root: str) -> list[dict]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_DIRS and not d.startswith(".")]
        rel_dir = os.path.relpath(dirpath, root)
        if any(rx.search("/" + rel_dir + "/") for rx in _MIGRATION_DIR_RES):
            for fn in sorted(filenames):
                if fn.lower().endswith((".py", ".sql", ".js", ".ts")) \
                        and not fn.startswith("."):
                    out.append({"migration": fn,
                                "path": os.path.join(rel_dir, fn)})
                    if len(out) >= 60:
                        return out
    return out


def _auth_boundary_files(root: str) -> list[dict]:
    out = []
    exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php"}
    for rel, ap in _iter_files(root, exts, 3000):
        base = os.path.basename(rel)
        if _AUTH_NAME_RE.search(base):
            out.append({"file": rel, "why": "filename signal"})
            if len(out) >= 60:
                break
    return out


def _env_var_names(root: str) -> dict:
    """Variable NAMES only. Never reads .env values; never opens .env."""
    names: dict[str, list[str]] = {}
    for fname in (".env.example", ".env.sample", ".env.template",
                  ".env.dist"):
        p = os.path.join(root, fname)
        if os.path.isfile(p):
            try:
                for line in _read_text(p).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key = line.split("=", 1)[0].strip().strip("\"'")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                        names.setdefault(key, []).append(fname)
            except OSError:
                continue
    for cfname in ("docker-compose.yml", "docker-compose.yaml",
                   "compose.yml", "compose.yaml"):
        p = os.path.join(root, cfname)
        if not os.path.isfile(p):
            continue
        try:
            in_env, indent = False, 0
            for line in _read_text(p).splitlines():
                if re.match(r"\s*environment\s*:\s*$", line):
                    in_env, indent = True, len(line) - len(line.lstrip())
                    continue
                if in_env:
                    cur = len(line) - len(line.lstrip())
                    if not line.strip() or cur <= indent:
                        in_env = False
                        continue
                    item = line.strip().lstrip("- ").strip()
                    key = re.split(r"\s*[:=]\s*", item, maxsplit=1)[0].strip(
                        "\"'")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                        names.setdefault(key, []).append(cfname)
        except OSError:
            continue
    return names


def _config_presence(root: str) -> list[str]:
    return [c for c in _CONFIG_FILES
            if os.path.exists(os.path.join(root, c))]


# --------------------------------------------------------------------------
# main entry
# --------------------------------------------------------------------------

def analyze(session_id: str, path_or_repo_url: str) -> dict:
    """Deep source analysis. Returns JSON-serializable dict; records findings
    to the session evidence ledger. Raises RuntimeError on bad target."""
    root, tmpdir, note = _resolve_root(path_or_repo_url)
    try:
        base = RP.analyze_codebase(root)

        ast_info = _ast_pass(root)
        js_info = _js_component_pass(root)
        migrations = _migration_inventory(root)
        auth_files = _auth_boundary_files(root)
        env_names = _env_var_names(root)
        configs = _config_presence(root)

        manifests = base.get("manifests", {}) or {}
        manifest_backed = bool(manifests)
        fw_guess = base.get("framework_guess", []) or []

        # ---- framework claim ----
        if fw_guess:
            cls = "SOURCE_VERIFIED" if manifest_backed else "INFERRED"
            _record(session_id, "tech",
                    f"Framework guess: {', '.join(fw_guess)}",
                    f"Detected frameworks: {', '.join(fw_guess)}. "
                    f"{'Backed by dependency manifests.' if manifest_backed else 'No dependency manifest found; heuristic only.'}",
                    cls, 0.9 if manifest_backed else 0.6,
                    "manifest-backed" if manifest_backed
                    else "file-pattern heuristic without manifest",
                    [root],
                    limitations="Does not prove runtime behavior; build config may override.")

        # ---- routes (AST, file:line) ----
        for r in ast_info["routes"][:200]:
            _record(session_id, "route", f"Route {r['route']}",
                    f"Route '{r['route']}' declared via {r['via']} "
                    f"at {r['file']}:{r['line']}"
                    + (" (auth-decorated)" if r.get("auth_decorated") else ""),
                    "SOURCE_VERIFIED", 0.95,
                    "parsed directly from Python AST; decorator/call and string literal observed",
                    [f"{root}/{r['file']}"],
                    route=r["route"],
                    limitations="Route registration may be conditional at import time.")

        # ---- components ----
        for c in js_info["components"][:200]:
            _record(session_id, "component", f"Component {c['name']}",
                    f"{c['framework']} component '{c['name']}' in {c['file']}",
                    "INFERRED", 0.65,
                    "file pattern + exported capitalized name heuristic (no tree-sitter)",
                    [f"{root}/{c['file']}"],
                    component=c["name"],
                    limitations="Name heuristic; may miss HOC-wrapped or anonymous components.")

        # ---- state management ----
        for s in js_info["state_management"]:
            _record(session_id, "state",
                    f"State management: {s['library']}",
                    f"Import of '{s['import']}' in {s['file']} indicates {s['library']}",
                    "SOURCE_VERIFIED", 0.85,
                    "import statement observed in source",
                    [f"{root}/{s['file']}"])

        # ---- API clients ----
        for a in js_info["api_clients"]:
            _record(session_id, "endpoint",
                    f"API client module: {a['file']}",
                    f"{a['kind']} API client in {a['file']}",
                    "INFERRED" if a["kind"] != "openapi-schema" else "SOURCE_VERIFIED",
                    0.7 if a["kind"] != "openapi-schema" else 0.9,
                    "module wraps HTTP calls" if a["kind"] != "openapi-schema"
                    else "OpenAPI document present",
                    [f"{root}/{a['file']}"],
                    limitations="Endpoints used by the client are not enumerated here.")

        # ---- migrations ----
        if migrations:
            _record(session_id, "entity",
                    f"{len(migrations)} migration files",
                    "Migration files: " + ", ".join(
                        m["path"] for m in migrations[:15])
                    + ("..." if len(migrations) > 15 else ""),
                    "SOURCE_VERIFIED", 0.9,
                    "migration files observed on disk",
                    [f"{root}/{m['path']}" for m in migrations[:15]],
                    limitations="File names only; schema contents not parsed.")

        # ---- auth boundaries ----
        for a in auth_files[:40]:
            _record(session_id, "auth", f"Auth-related file: {a['file']}",
                    f"{a['file']} ({a['why']})",
                    "INFERRED", 0.6,
                    "filename contains auth/security keyword",
                    [f"{root}/{a['file']}"],
                    limitations="Filename heuristic; verify by reading the file.")

        # ---- env var names ----
        if env_names:
            _record(session_id, "note",
                    f"{len(env_names)} env var names inventoried",
                    "Names (only) from .env.example/docker-compose: "
                    + ", ".join(sorted(env_names)[:30])
                    + ("..." if len(env_names) > 30 else ""),
                    "SOURCE_VERIFIED", 0.95,
                    "names read from example/config files; values never read",
                    [root],
                    limitations="Names only; actual values and .env contents never inspected.")

        result = {
            "session_id": session_id,
            "target": path_or_repo_url,
            "root_note": note,
            "base_map": {
                "total_files": base.get("total_files"),
                "languages": base.get("languages"),
                "framework_guess": fw_guess,
                "framework_manifest_backed": manifest_backed,
                "entry_points": base.get("entry_points"),
                "key_files": base.get("key_files"),
                "readme_head": (base.get("readme_head") or "")[:1500],
            },
            "python_ast": {
                "files_parsed": ast_info["files_parsed"],
                "imports_top": sorted(ast_info["imports"].items(),
                                      key=lambda kv: -len(kv[1]))[:30],
                "classes": ast_info["classes"][:100],
                "functions": len(ast_info["functions"]),
                "routes": ast_info["routes"][:200],
                "routes_found": len(ast_info["routes"]),
            },
            "components": js_info["components"],
            "components_found": len(js_info["components"]),
            "state_management": js_info["state_management"],
            "api_clients": js_info["api_clients"],
            "migrations": migrations,
            "migrations_found": len(migrations),
            "auth_boundary_files": [a["file"] for a in auth_files],
            "env_var_names": sorted(env_names),
            "env_var_count": len(env_names),
            "configs_present": configs,
        }
        return result
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
