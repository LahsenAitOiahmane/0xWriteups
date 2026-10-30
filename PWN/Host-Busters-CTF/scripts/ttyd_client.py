"""Minimal ttyd WebSocket client for driving the challenge web-shell.

Protocol (reverse-engineered from the served app bundle):
  * connect to wss://<host>/ws  WITH subprotocol "tty"
  * binary frame 0x01: JSON {"AuthToken":"","columns":C,"rows":R}   <- init
  * server -> client: one-byte prefix + payload
        '0' OUTPUT | '1' SET_WINDOW_TITLE | '2' SET_PREFERENCES | '4' SET_RECONNECT
  * client -> server: b'0' + keystrokes , or b'1' + JSON resize
"""
import asyncio
import json
import os
import sys

import websockets
from websockets.asyncio.client import connect

HOST = os.environ.get("DCTF_HOST", "hostbusters.dctf.io")
URL = f"wss://{HOST}/ws"

# Commands we send earth time to warm the shell up and hide our own echo.
WARMUP = "export TERM=xterm-256color; export PS1='@@ '; stty -echo 2>/dev/null; clear\n"

CMD_PREFIXES = ("0", "1", "2", "4")


def decode(raw) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    out, i = [], 0
    while i < len(raw):
        if raw[i:i + 1].decode("latin-1") not in CMD_PREFIXES:
            out.append(raw[i:])
            break
        j = raw.find(b"\n", i + 1)
        if j < 0:
            break
        payload = raw[i + 1:j + 1]
        if raw[i:i + 1] == b"0":
            out.append(payload)
        i = j + 1
    return b"".join(out).decode("utf-8", "replace")


class Shell:
    """One live web-shell session. Fresh box per connection."""

    def __init__(self, cols=120, rows=40):
        self.cols, self.rows = cols, rows
        self.ws = None
        self.buf = bytearray()

    async def __aenter__(self):
        self.ws = await connect(
            URL,
            user_agent_header="Mozilla/5.0 (X11; Linux x86_64) Chrome/126",
            additional_headers={"Origin": f"https://{HOST}"},
            subprotocols=["tty"],
            proxy=True,
            open_timeout=30,
            max_size=None,
        ).__aenter__()
        init = json.dumps({"AuthToken": "", "columns": self.cols,
                           "rows": self.rows}).encode()
        await self.ws.send(init)
        return self

    async def __aexit__(self, *exc):
        try:
            await self.ws.send(b"0exit\n")
        except Exception:
            pass
        try:
            await self.ws.close()
        except Exception:
            pass

    async def _drain(self, seconds: float):
        loop = asyncio.get_event_loop()
        end = loop.time() + seconds
        while True:
            left = end - loop.time()
            if left <= 0:
                return
            try:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=left)
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                return
            self.buf += raw if isinstance(raw, bytes) else raw.encode()

    async def send(self, line: str):
        await self.ws.send(b"0" + line.encode() + b"\n")

    async def read(self, seconds=2.0) -> str:
        await self._drain(seconds)
        txt = decode(bytes(self.buf))
        self.buf.clear()
        return txt

    async def run(self, cmd: str, settle=2.5, wait=25.0) -> str:
        """Run one command, return output between markers."""
        await self.send(cmd)
        return await self.read(settle)

    async def warmup(self):
        await self._drain(2.5)
        await self.send(WARMUP.strip("\n"))
        await self.read(2.5)

    async def script(self, body: str, settle=3.0, timeout=40.0) -> str:
        """Run a multi-line script; returns everything after our start marker."""
        tag = "RC%d" % (id(self) % 100000)
        await self.send(f"echo {tag}START")
        await self.read(1.0)
        await self.send(body)
        await self.send(f"echo {tag}END")
        return await self.read(timeout)


async def amain(cmds):
    async with Shell() as sh:
        await sh.warmup()
        for c in cmds:
            print("=" * 70)
            print("$ " + c)
            print("=" * 70)
            print(await sh.run(c))


def main():
    args = [a for a in sys.argv[1:]]
    if args:
        cmds = args
    else:
        cmds = ["id", "pwd", "ls -la", "hostname"]
    asyncio.run(amain(cmds))


if __name__ == "__main__":
    main()
