"""Tests for omnirecon.assets (Lane C).

Unit-tests the CSS parser with synthetic CSS, then runs inventory()
end to end against https://example.com (sandbox: needs no_proxy fix).
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

from omnirecon import assets  # noqa: E402

SESSION_ID = "test-lane-c-assets"

SYNTHETIC_CSS = """
@font-face {
  font-family: 'Brand Sans';
  src: url('/fonts/brand-sans.woff2') format('woff2'),
       url("/fonts/brand-sans.woff") format('woff');
}
:root {
  --primary: #1a73e8;
  --surface: #ffffff;
  --spacing: 8px;
}
.hero {
  color: #1A73E8;
  background: #1a73e8;
  border-color: #ff0000;
  font-family: 'Brand Sans', system-ui, sans-serif;
}
.card { font-family: Georgia, serif; }
"""


class CssParseTest(unittest.TestCase):
    def test_parse_css(self):
        p = assets._parse_css(SYNTHETIC_CSS, "inline")
        self.assertEqual(len(p["font_faces"]), 1)
        self.assertEqual(p["font_faces"][0]["family"], "Brand Sans")
        self.assertTrue(any("brand-sans.woff2" in u
                            for u in p["font_faces"][0]["urls"]))
        self.assertEqual(p["custom_properties"]["primary"], "#1a73e8")
        self.assertEqual(p["custom_properties"]["spacing"], "8px")
        colors = {c["color"]: c["uses"]
                  for c in p["color_palette"]}
        # #1A73E8 appears 3x (var + 2 decls), normalized to lowercase 6-digit
        self.assertEqual(colors.get("#1a73e8"), 3)
        self.assertIn("#ff0000", colors)
        self.assertTrue(any("Brand Sans" in s
                            for s in p["font_stacks"]))


class InventoryTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        sess = os.path.join(REPO_ROOT, "sessions", SESSION_ID)
        shutil.rmtree(sess, ignore_errors=True)

    def test_inventory_example_com(self):
        res = assets.inventory(SESSION_ID, "https://example.com")
        self.assertNotIn("error", res)
        self.assertEqual(res["page_status"], 200)
        # structure
        for key in ("images", "icons", "fonts", "design_tokens",
                    "inline_svg_count", "artifact"):
            self.assertIn(key, res)
        self.assertIsInstance(res["images"], list)
        # artifact saved under session dir
        art = os.path.join(REPO_ROOT, "sessions", SESSION_ID,
                           res["artifact"])
        self.assertTrue(os.path.isfile(art))
        with open(art, encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual(saved["target"], "https://example.com")
        # ledger findings recorded
        ledger = os.path.join(REPO_ROOT, "sessions", SESSION_ID,
                              "evidence.jsonl")
        self.assertTrue(os.path.isfile(ledger))
        with open(ledger, encoding="utf-8") as fh:
            findings = [json.loads(l) for l in fh if l.strip()]
        self.assertTrue(any(f["type"] == "asset" for f in findings))
        for f in findings:
            self.assertIn(f["classification"],
                          ("OBSERVED", "SOURCE_VERIFIED", "INFERRED",
                           "UNVERIFIED", "BLOCKED"))

    def test_inventory_bad_url(self):
        res = assets.inventory(SESSION_ID,
                               "https://nonexistent.invalid-xyz-123.com/")
        self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main()
