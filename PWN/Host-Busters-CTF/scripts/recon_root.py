"""Heavy is the Crown (500): mort1cia -> root. Find the way up."""
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
    if not await su(sh, "mort1cia", MORT_PW):
        print("[!] su mort1cia failed", flush=True)
        return False
    print("as:", (await cmd(sh, "id"))[0][:120], flush=True)

    steps = [
        ("sudo -l WITH password", "echo " + MORT_PW + " | sudo -S -l 2>&1 | head -25"),
        ("SUID root binaries", "find / -xdev -perm -4000 -o -perm -4040 2>/dev/null | grep -v '^/proc'"),
        ("charon-backup perms", "ls -la /usr/local/bin/ 2>&1; echo ---; stat /usr/local/bin/charon-backup 2>&1"),
        ("charon-backup type", "head -c 20 /usr/local/bin/charon-backup | od -c | head -2; wc -c /usr/local/bin/charon-backup"),
        ("strings in charon-backup", "strings -n 5 /usr/local/bin/charon-backup 2>/dev/null | head -60"),
        ("/opt/ops", "ls -la /opt/ops/ 2>&1; sudo -n cat /opt/ops/leverage.txt 2>&1"),
        ("root flag readable?", "ls -la /root/ 2>&1"),
        ("getcap full", "getcap -r / 2>/dev/null"),
        ("writable paths as mort1cia", "find / -xdev -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys' | head -30"),
    ]
    for label, c in steps:
        print(f"\n----- {label} -----", flush=True)
        res, ok = await cmd(sh, c, 40)
        print(res.strip()[:1500], flush=True)
    return True


async def su(sh, user, password):
    await sh.send(f"su - {user}")
    got, _ = await wait_for(sh, "Password:", 25.0)
    if not got:
        return False
    await sh.send(password)
    await asyncio.sleep(3.0)
    await sh.read(2.0)
    who, _ = await cmd(sh, "id", 25)
    return user in who


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
