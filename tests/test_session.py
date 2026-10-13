"""Tests for omnirecon.session — SessionManager lifecycle + JobManager.

Network-touching primitives are mocked for determinism; one live test is
skipped unless OMNIRECON_LIVE_TESTS=1.
"""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from omnirecon import session as S
from omnirecon.session import SessionManager, JobManager
from omnirecon.security import ReconError


FAKE_SCAN = {
    "status": 200, "final_url": "https://demo.test/",
    "title": "Demo", "script_tags": 3,
    "forms": [{"action": "/login", "method": "POST", "inputs": []}],
    "tech": [{"tech": "Next.js", "evidence": "__NEXT_DATA__"}],
    "robots_txt": {"present": True}, "sitemap": {"present": True},
}
FAKE_DNS = {"a": ["1.2.3.4"], "subdomains": ["api.demo.test", "staging.demo.test"]}


def _mgr(tmp):
    return SessionManager(base_dir=os.path.join(tmp, "sessions"))


class TestCreateURL(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mgr = _mgr(self.tmp.name)

    def _create(self, target="https://demo.test", **kw):
        with mock.patch.object(S.RP, "platform_scan", return_value=dict(FAKE_SCAN)), \
             mock.patch.object(S.RP, "dns_recon", return_value=dict(FAKE_DNS)):
            return self.mgr.create(target, **kw)

    def test_create_seeds_ledger_and_files(self):
        res = self._create()
        sid = res["session_id"]
        self.assertEqual(res["stage"], 2)
        self.assertEqual(res["status"], "active")
        self.assertEqual(res["target_kind"], "url")
        self.assertGreaterEqual(res["rapid_report"]["findings_seeded"], 2)
        techs = self.mgr.ledger(sid).list(type="tech")
        self.assertEqual(len(techs), 1)
        self.assertEqual(techs[0]["classification"], "OBSERVED")
        self.assertIn("Next.js", techs[0]["title"])
        subs = [f for f in self.mgr.ledger(sid).list()
                if f["title"].startswith("Subdomain:")]
        self.assertEqual(len(subs), 2)
        sdir = os.path.join(self.tmp.name, "sessions", sid)
        for name in ("session.json", "evidence.jsonl", "graph.json", "audit.log"):
            self.assertTrue(os.path.exists(os.path.join(sdir, name)), name)

    def test_create_unreachable_target_records_blocked(self):
        with mock.patch.object(S.RP, "platform_scan",
                               return_value={"error": "fetch failed: timeout"}):
            res = self.mgr.create("https://dead.test")
        blocked = self.mgr.ledger(res["session_id"]).list(classification="BLOCKED")
        self.assertEqual(len(blocked), 1)
        self.assertEqual(res["stage"], 2)  # session survives

    def test_create_bare_domain_gets_scheme(self):
        res = self._create("demo.test")
        self.assertEqual(res["target"], "https://demo.test")

    def test_create_invalid_target(self):
        with self.assertRaises(ReconError) as ctx:
            self.mgr.create("")
        self.assertEqual(ctx.exception.code, "invalid_target")
        with self.assertRaises(ReconError):
            self.mgr.create("/nonexistent/path/xyz")

    def test_create_bad_mode(self):
        with self.assertRaises(ReconError):
            self.mgr.create("https://demo.test", mode="turbo")

    def test_budget_merge(self):
        res = self._create(budget={"max_pages": 5})
        s = self.mgr.get(res["session_id"])
        self.assertEqual(s["budget"]["max_pages"], 5)
        self.assertIn("timeout_s", s["budget"])


class TestCreateRepo(unittest.TestCase):
    def test_local_repo_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "tinyapp")
            os.makedirs(repo)
            with open(os.path.join(repo, "app.py"), "w") as fh:
                fh.write('from flask import Flask\napp = Flask(__name__)\n'
                         '@app.route("/hello")\ndef hello():\n    return "hi"\n')
            mgr = _mgr(tmp)
            res = mgr.create(repo)
            self.assertEqual(res["target_kind"], "repo")
            self.assertEqual(res["rapid_report"]["routes_found"], 1)
            routes = mgr.ledger(res["session_id"]).list(type="route")
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["classification"], "SOURCE_VERIFIED")
            self.assertEqual(routes[0]["route"], "/hello")


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mgr = _mgr(self.tmp.name)
        with mock.patch.object(S.RP, "platform_scan", return_value=dict(FAKE_SCAN)), \
             mock.patch.object(S.RP, "dns_recon", return_value=dict(FAKE_DNS)):
            self.res = self.mgr.create("https://demo.test")
        self.sid = self.res["session_id"]

    def test_get_and_update_stage(self):
        s = self.mgr.get(self.sid)
        self.assertEqual(s["stage"], 2)
        s2 = self.mgr.update_stage(self.sid, 3)
        self.assertEqual(s2["stage"], 3)
        with self.assertRaises(ReconError) as ctx:
            self.mgr.update_stage(self.sid, 9)
        self.assertEqual(ctx.exception.code, "invalid_stage")

    def test_get_missing(self):
        with self.assertRaises(ReconError) as ctx:
            self.mgr.get("deadbeefdeadbeef")
        self.assertEqual(ctx.exception.code, "session_not_found")

    def test_checkpoint_writes_graph(self):
        out = self.mgr.checkpoint(self.sid)
        self.assertTrue(os.path.exists(out["graph_json"]))
        graph_path = out["graph_json"]
        with open(graph_path, encoding="utf-8") as fh:
            graph = json.load(fh)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreater(graph["counts"]["findings"], 0)

    def test_resume_from_fresh_manager(self):
        fresh = _mgr(self.tmp.name)  # no in-memory cache
        r = fresh.resume(self.sid)
        self.assertEqual(r["session_id"], self.sid)
        self.assertEqual(r["stage"], 2)
        self.assertEqual([s["stage"] for s in r["remaining_stages"]], [3, 4, 5, 6, 7])
        self.assertGreater(r["ledger_stats"]["total"], 0)

    def test_cancel_then_resume_refused(self):
        self.mgr.cancel(self.sid)
        self.assertEqual(self.mgr.get(self.sid)["status"], "cancelled")
        with self.assertRaises(ReconError) as ctx:
            self.mgr.resume(self.sid)
        self.assertEqual(ctx.exception.code, "session_cancelled")

    def test_list(self):
        with mock.patch.object(S.RP, "platform_scan", return_value=dict(FAKE_SCAN)), \
             mock.patch.object(S.RP, "dns_recon", return_value=dict(FAKE_DNS)):
            self.mgr.create("https://other.test")
        lst = self.mgr.list()
        self.assertEqual(len(lst), 2)
        self.assertTrue(all("session_id" in s and "findings" in s for s in lst))


class TestJobManager(unittest.TestCase):
    def test_submit_and_poll_done(self):
        jm = JobManager()
        jid = jm.submit(lambda a, b: a + b, 2, 3, name="adder")
        for _ in range(100):
            p = jm.poll(jid)
            if p["status"] == "done":
                break
            time.sleep(0.02)
        self.assertEqual(p["status"], "done")
        self.assertEqual(p["result"], 5)

    def test_failure_surfaced(self):
        jm = JobManager()
        def boom():
            raise ValueError("kaput")
        jid = jm.submit(boom)
        for _ in range(100):
            p = jm.poll(jid)
            if p["status"] == "failed":
                break
            time.sleep(0.02)
        self.assertEqual(p["status"], "failed")
        self.assertIn("kaput", p["error"])

    def test_cancel_running_job(self):
        jm = JobManager()
        evt_holder = {}
        def slow():
            time.sleep(5)
        jid = jm.submit(slow)
        time.sleep(0.1)
        self.assertTrue(jm.cancel(jid))
        p = jm.poll(jid)
        self.assertEqual(p["status"], "cancelled")
        self.assertFalse(jm.cancel(jid))  # already settled

    def test_poll_unknown(self):
        jm = JobManager()
        with self.assertRaises(ReconError) as ctx:
            jm.poll("j-nope")
        self.assertEqual(ctx.exception.code, "job_not_found")


if __name__ == "__main__":
    unittest.main()
