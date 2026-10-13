"""Tests for omnirecon.source_intel (Lane C).

Builds a tiny fixture repo (FastAPI backend + React frontend) under
tests/fixtures/demo-app and asserts routes/components/migrations/
env-names/state-signals are found end to end.
"""
import json
import os
import shutil
import sys
import unittest

os.environ["no_proxy"] = "localhost,127.0.0.1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from omnirecon import source_intel  # noqa: E402

FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "demo-app")
SESSION_ID = "test-lane-c-source"


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


MAIN_PY = '''\
from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()

class ItemStore:
    def __init__(self):
        self.items = {}

    def add(self, item):
        self.items[item["id"]] = item

@app.get("/items")
def list_items():
    return []

@app.post("/items", status_code=201)
def create_item(payload: dict):
    return payload

@app.get("/items/{item_id}")
def get_item(item_id: int, creds=Depends(security)):
    return {"id": item_id}
'''

BUTTON_JSX = '''\
import React from "react";

export function Button({ label, onClick }) {
  return <button onClick={onClick}>{label}</button>;
}

export default Button;
'''

STORE_JS = '''\
import { create } from "zustand";

export const useCart = create((set) => ({
  items: [],
  add: (item) => set((s) => ({ items: [...s.items, item] })),
}));
'''

API_CLIENT_JS = '''\
import axios from "axios";

const api = axios.create({ baseURL: "/api/v1" });

export async function fetchItems() {
  const res = await api.get("/items");
  return res.data;
}
'''

AUTH_PY = '''\
from functools import wraps

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        return fn(*a, **kw)
    return wrapper
'''

MIGRATION_PY = '''\
"""init tables"""
revision = "001"

def upgrade():
    pass
'''

ENV_EXAMPLE = """\
# example env — values are fake
DATABASE_URL=postgres://user:pass@localhost/db
SECRET_KEY=changeme
DEBUG=false
"""

COMPOSE_YML = """\
services:
  web:
    build: .
    environment:
      - DATABASE_URL=postgres://db/app
      - REDIS_URL=redis://redis:6379
"""


class SourceIntelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shutil.rmtree(FIXTURE, ignore_errors=True)
        _write(os.path.join(FIXTURE, "app", "main.py"), MAIN_PY)
        _write(os.path.join(FIXTURE, "app", "auth.py"), AUTH_PY)
        _write(os.path.join(FIXTURE, "alembic", "versions",
                            "001_init.py"), MIGRATION_PY)
        _write(os.path.join(FIXTURE, "frontend", "src", "components",
                            "Button.jsx"), BUTTON_JSX)
        _write(os.path.join(FIXTURE, "frontend", "src", "store.js"),
               STORE_JS)
        _write(os.path.join(FIXTURE, "frontend", "src", "api",
                            "client.js"), API_CLIENT_JS)
        _write(os.path.join(FIXTURE, ".env.example"), ENV_EXAMPLE)
        _write(os.path.join(FIXTURE, "docker-compose.yml"), COMPOSE_YML)
        _write(os.path.join(FIXTURE, "requirements.txt"),
               "fastapi==0.110\nuvicorn\n")
        _write(os.path.join(FIXTURE, "frontend", "package.json"),
               json.dumps({"dependencies": {"react": "^18.0.0",
                                            "zustand": "^4.0.0"}}))

    @classmethod
    def tearDownClass(cls):
        sess = os.path.join(REPO_ROOT, "sessions", SESSION_ID)
        shutil.rmtree(sess, ignore_errors=True)

    def test_analyze_end_to_end(self):
        res = source_intel.analyze(SESSION_ID, FIXTURE)

        # base map reused from recon_primitives
        langs = {l["language"] for l in res["base_map"]["languages"]}
        self.assertIn("Python", langs)
        self.assertIn("JavaScript", langs)
        self.assertIn("FastAPI", res["base_map"]["framework_guess"])

        # AST routes with file:line ("/items" has both GET and POST entries)
        routes = res["python_ast"]["routes"]
        by_route: dict[str, list[dict]] = {}
        for r in routes:
            by_route.setdefault(r["route"], []).append(r)
        self.assertIn("/items", by_route)
        self.assertIn("/items/{item_id}", by_route)
        self.assertTrue(any("app.get" in r["via"]
                            for r in by_route["/items"]))
        first = by_route["/items"][0]
        self.assertTrue(first["file"].endswith("app/main.py"))
        self.assertIsInstance(first["line"], int)
        self.assertGreater(first["line"], 0)

        # classes + imports
        cls_names = {c["name"] for c in res["python_ast"]["classes"]}
        self.assertIn("ItemStore", cls_names)
        self.assertIn("fastapi", dict(res["python_ast"]["imports_top"]))

        # components
        comp_names = {c["name"] for c in res["components"]}
        self.assertIn("Button", comp_names)

        # state management
        libs = {s["library"] for s in res["state_management"]}
        self.assertIn("Zustand", libs)

        # api clients
        client_files = [a["file"] for a in res["api_clients"]]
        self.assertTrue(any("client.js" in f for f in client_files))

        # migrations
        mig_paths = [m["path"] for m in res["migrations"]]
        self.assertTrue(any("001_init.py" in p for p in mig_paths))

        # auth boundary files
        self.assertTrue(any("auth.py" in f
                            for f in res["auth_boundary_files"]))

        # env var NAMES only — values must never appear
        blob = json.dumps(res)
        self.assertIn("DATABASE_URL", res["env_var_names"])
        self.assertIn("SECRET_KEY", res["env_var_names"])
        self.assertIn("REDIS_URL", res["env_var_names"])
        self.assertNotIn("postgres://user:pass", blob)
        self.assertNotIn("changeme", blob)

        # configs
        self.assertIn("docker-compose.yml", res["configs_present"])

    def test_ledger_written(self):
        source_intel.analyze(SESSION_ID, FIXTURE)
        ledger = os.path.join(REPO_ROOT, "sessions", SESSION_ID,
                              "evidence.jsonl")
        self.assertTrue(os.path.isfile(ledger))
        with open(ledger, encoding="utf-8") as fh:
            findings = [json.loads(l) for l in fh if l.strip()]
        self.assertGreater(len(findings), 5)
        types = {f["type"] for f in findings}
        self.assertTrue({"route", "component", "tech"} <= types)
        # schema check on one finding
        f0 = findings[0]
        for key in ("id", "type", "title", "detail", "classification",
                    "confidence", "confidence_why", "sources",
                    "timestamp", "verification", "limitations"):
            self.assertIn(key, f0)
        route_f = [f for f in findings if f["type"] == "route"][0]
        self.assertEqual(route_f["classification"], "SOURCE_VERIFIED")

    def test_bad_target_raises(self):
        with self.assertRaises(RuntimeError):
            source_intel.analyze(SESSION_ID, "/nonexistent/path/xyz")


if __name__ == "__main__":
    unittest.main()
