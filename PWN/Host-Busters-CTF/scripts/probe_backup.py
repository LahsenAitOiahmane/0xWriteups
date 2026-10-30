"""Probe /usr/local/bin/charon-backup (SUID root, 216 KB)."""
import asyncio
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

MORT_PW = "princess2015"


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

    steps = [
        ("--help", "charon-backup --help 2>&1 | head -40"),
        ("no args", "charon-backup 2>&1 | head -25"),
        ("real strings", "strings -a -n 6 /usr/local/bin/charon-backup 2>/dev/null | grep -vE '^[^a-zA-Z]{0,3}$' | head -70"),
        ("usage/usage-like", "strings -a -n 4 /usr/local/bin/charon-backup 2>/dev/null | grep -iE 'usage|backup|tar|log|conf|root|dest|src|dir|opt|tmp' | head -50"),
    ]
    for label, c in steps:
        print(f"\n----- {label} -----", flush=True)
        res, _ = await cmd(sh, c, 50)
        print(res[:1800], flush=True)
    return True


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
