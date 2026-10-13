"""Tests for omnirecon.security — redaction, scope, rate limiting, audit, safe_join."""
import json
import os
import tempfile
import time
import unittest

from omnirecon.security import (
    ReconError, redact, check_scope, RateLimiter, audit, safe_join, REDACTED,
)


class TestRedact(unittest.TestCase):
    def test_exact_keys_case_insensitive(self):
        obj = {"Authorization": "Bearer abc", "AUTHORIZATION": "x",
               "cookie": "sess=1", "Set-Cookie": "a=b", "PASSWORD": "hunter2"}
        out = redact(obj)
        for v in out.values():
            self.assertEqual(v, REDACTED)

    def test_substring_and_tricky_casings(self):
        obj = {"X-Api-Key": "k", "apiKey": "k", "APIKEY": "k",
               "client_secret": "s", "db_passwd": "p", "access_token": "t",
               "X-Auth-Token": "t", "sessionId": "s", "private_key": "k"}
        out = redact(obj)
        for k, v in out.items():
            self.assertEqual(v, REDACTED, f"key {k} was not redacted")

    def test_auth_word_boundary_does_not_nuke_author(self):
        obj = {"author": "Jane Doe", "author_name": "jane", "authorship": "x"}
        out = redact(obj)
        self.assertEqual(out["author"], "Jane Doe")
        self.assertEqual(out["author_name"], "jane")

    def test_nested_structures(self):
        obj = {"req": {"headers": {"Authorization": "tok",
                                   "X-Custom": "keep"},
                        "cookies": ["a=1"]},
               "items": [{"password": "p", "name": "n"}]}
        out = redact(obj)
        self.assertEqual(out["req"]["headers"]["Authorization"], REDACTED)
        self.assertEqual(out["req"]["headers"]["X-Custom"], "keep")
        self.assertEqual(out["items"][0]["password"], REDACTED)
        self.assertEqual(out["items"][0]["name"], "n")

    def test_bearer_and_basic_in_free_text(self):
        s = "header was Bearer eyJhbGciOiJIUzI1NiJ9.payload and Basic dXNlcjpwYXNz"
        out = redact(s)
        self.assertIn("Bearer " + REDACTED, out)
        self.assertIn("Basic " + REDACTED, out)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)

    def test_query_params_redacted_in_urls(self):
        url = "https://api.example.com/data?token=abc123&foo=bar&api_key=zzz"
        out = redact({"url": url})
        self.assertIn("token=" + REDACTED, out["url"])
        self.assertIn("api_key=" + REDACTED, out["url"])
        self.assertIn("foo=bar", out["url"])

    def test_long_strings_truncated(self):
        out = redact({"body": "x" * 5000})
        self.assertLess(len(out["body"]), 5000)
        self.assertIn("[truncated]", out["body"])

    def test_input_not_mutated(self):
        obj = {"a": {"Authorization": "tok"}, "b": ["x" * 5000]}
        snapshot = json.dumps(obj)
        redact(obj)
        self.assertEqual(json.dumps(obj), snapshot)

    def test_tuples_and_bytes(self):
        out = redact({"t": ("Authorization", "ok"), "b": b"Bearer secret-token-here"})
        self.assertIsInstance(out["t"], tuple)
        self.assertIn(REDACTED, out["b"])
        self.assertNotIn("secret-token-here", out["b"])

    def test_circular_reference_safe(self):
        obj = {"a": 1}
        obj["self"] = obj
        out = redact(obj)
        self.assertEqual(out["self"], "[CIRCULAR]")
        self.assertEqual(out["a"], 1)

    def test_scalars_pass_through(self):
        self.assertEqual(redact(42), 42)
        self.assertEqual(redact(None), None)
        self.assertEqual(redact(True), True)


class TestCheckScope(unittest.TestCase):
    def test_exact_and_subdomain(self):
        self.assertTrue(check_scope("https://example.com/x", ["example.com"]))
        self.assertTrue(check_scope("https://api.example.com/x", ["example.com"]))
        self.assertTrue(check_scope("https://EXAMPLE.com/", ["example.com"]))

    def test_rejects(self):
        self.assertFalse(check_scope("https://evilexample.com/", ["example.com"]))
        self.assertFalse(check_scope("https://example.com.evil.com/", ["example.com"]))
        self.assertFalse(check_scope("https://other.com/", ["example.com"]))

    def test_edge_cases(self):
        self.assertFalse(check_scope("https://example.com/", []))
        self.assertFalse(check_scope("", ["example.com"]))
        self.assertFalse(check_scope("not a url", ["example.com"]))
        self.assertTrue(check_scope("https://example.com./", ["example.com"]))  # trailing dot ok


class TestRateLimiter(unittest.TestCase):
    def test_enforces_interval(self):
        rl = RateLimiter(requests_per_second=10)  # 0.1s interval
        t0 = time.monotonic()
        rl.wait(); rl.wait(); rl.wait()
        self.assertGreaterEqual(time.monotonic() - t0, 0.19)

    def test_invalid_rate(self):
        with self.assertRaises(ReconError):
            RateLimiter(requests_per_second=0)

    def test_thread_safe(self):
        import threading
        rl = RateLimiter(requests_per_second=50)
        stamps = []
        def w():
            rl.wait()
            stamps.append(time.monotonic())
        threads = [threading.Thread(target=w) for _ in range(5)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(stamps), 5)
        self.assertGreaterEqual(max(stamps) - min(stamps), 0.07)


class TestAudit(unittest.TestCase):
    def test_appends_redacted_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit("s1", "test.action", "token=abc password=x", base_dir=tmp)
            audit("s1", "test.action2", base_dir=tmp)
            path = os.path.join(tmp, "s1", "audit.log")
            self.assertTrue(os.path.exists(path))
            lines = [json.loads(l) for l in open(path)]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["action"], "test.action")
            self.assertIn("ts", lines[0])
            self.assertNotIn("abc", lines[0]["detail"])

    def test_requires_ids(self):
        with self.assertRaises(ReconError):
            audit("", "action")


class TestSafeJoin(unittest.TestCase):
    def test_normal_join(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = safe_join(tmp, "sessions", "abc123", "session.json")
            self.assertTrue(p.startswith(os.path.abspath(tmp)))

    def test_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ReconError) as ctx:
                safe_join(tmp, "..", "..", "etc", "passwd")
            self.assertEqual(ctx.exception.code, "path_traversal")
            with self.assertRaises(ReconError):
                safe_join(tmp, "/etc/passwd")


if __name__ == "__main__":
    unittest.main()
