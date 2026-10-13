#!/usr/bin/env python3
"""Local proxy relay for sandboxed environments.

Some sandboxes (like this one) put egress behind an HTTP proxy that Chromium
cannot use directly (seccomp/network-namespace quirks break Chromium's proxy
stack, while curl and raw sockets work fine). This relay listens on
127.0.0.1:8899 and forwards every TCP connection byte-for-byte to the real
egress proxy taken from the HTTPS_PROXY/HTTP_PROXY environment variable.

Usage:
    ~/workspace/venvs/recon/bin/python scripts/proxy_relay.py &
    export HTTPS_PROXY=http://127.0.0.1:8899 HTTP_PROXY=http://127.0.0.1:8899

Then Chromium/Playwright connects to the relay (loopback always works) and
the relay speaks to the real proxy. The relay never inspects, logs, or
modifies traffic; proxy credentials stay in the environment, not in code.

On a normal machine this script is unnecessary -- point Playwright at the
proxy directly (or at nothing).
"""
import asyncio
import os
import sys
from urllib.parse import urlparse

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8899


def _upstream():
    raw = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not raw:
        print("proxy_relay: no proxy env var set", file=sys.stderr)
        sys.exit(2)
    # Guard against pointing the relay at itself.
    if "127.0.0.1:8899" in raw or "localhost:8899" in raw:
        print("proxy_relay: refusing to relay to itself", file=sys.stderr)
        sys.exit(2)
    u = urlparse(raw)
    return u.hostname, u.port or 8080


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle(client_r, client_w, up_host, up_port):
    try:
        up_r, up_w = await asyncio.open_connection(up_host, up_port)
    except Exception as e:
        print(f"proxy_relay: upstream {up_host}:{up_port} failed: {e}",
              file=sys.stderr)
        client_w.close()
        return
    await asyncio.gather(
        _pipe(client_r, up_w),
        _pipe(up_r, client_w),
    )


async def main():
    up_host, up_port = _upstream()
    server = await asyncio.start_server(
        lambda r, w: _handle(r, w, up_host, up_port),
        LISTEN_HOST, LISTEN_PORT)
    print(f"proxy_relay: 127.0.0.1:{LISTEN_PORT} -> {up_host}:{up_port}",
          flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
