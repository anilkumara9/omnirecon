"""TEST-ONLY stdio entrypoint: injects the session shim, then runs the server.

Used by test_server.py to integration-test the MCP protocol end to end.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import shim_session  # noqa: E402

sys.modules["omnirecon.session"] = shim_session

from omnirecon import server  # noqa: E402

if __name__ == "__main__":
    server.mcp.run()
