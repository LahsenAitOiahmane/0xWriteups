"""Recon for On Schedule (cron), Lilith (sudo), Old Habits (spookyboi's notes)."""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402


async def run(sh, cmd, timeout=30.0):
    """Command + unique sentinel; read until the sentinel returns."""
    tag = "ZQ" + uuid.uuid4().hex[:8]
    await sh.send(cmd)
    await sh.send(f"echo {tag}END")
    buf, loop = "", asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        buf += await sh.read(1.0)
        if f"{tag}END" in buf:
            break
    out = []
    for line in buf.splitlines():
        if tag in line:
            continue
        out.append(line)
    return "\n".join(out).strip()


STEPS = [
    ("id", "id"),
    ("opt tree", "ls -la /opt/ /opt/scrape/ /opt/crypto/ 2>&1"),
    ("collect.sh", "cat /opt/scrape/collect.sh 2>&1"),
    ("collect perms", "ls -la /opt/scrape/collect.sh; stat -c '%A %U:%G %n' /opt/scrape /opt/scrape/collect.sh 2>&1"),
    ("crontab user", "crontab -l 2>&1 | head -20"),
    ("etc crontab", "cat /etc/crontab 2>&1 | head -30"),
    ("cron.d", "ls -la /etc/cron.d/ 2>&1; echo ---; cat /etc/cron.d/* 2>&1 | head -40"),
    ("cron dirs", "ls -la /etc/cron.hourly/ /etc/cron.daily/ 2>&1"),
    ("spool", "ls -laR /var/spool/cron/ 2>&1 | head -30"),
    ("sudo -l", "sudo -n -l 2>&1 | head -20"),
    ("sudoers readable?", "ls -la /etc/sudoers /etc/sudoers.d/ 2>&1; cat /etc/sudoers.d/* 2>&1 | head -40"),
    ("home list", "ls -la /home/ 2>&1"),
    ("who runs cron", "ps aux 2>&1 | head -30"),
]


async def body(sh):
    if not await ff.handshake_ok(sh):
        return False

    print("########## AS svc-deploy ##########", flush=True)
    for label, cmd in STEPS:
        print(f"\n----- {label} -----\n{await run(sh, cmd)}", flush=True)

    print("\n########## VIA cryptctl -> spookyboi ##########", flush=True)
    await sh.send("/opt/crypto/cryptctl")
    await sh.read(6.0)
    print("\n----- id -----\n" + await run(sh, "id"), flush=True)
    print("\n----- spookyboi home -----\n" + await run(sh, "ls -laR /home/spookyboi/ 2>&1 | head -40"), flush=True)
    print("\n----- NOTES (Old Habits) -----\n" + await run(
        sh, "for f in /home/spookyboi/*.txt /home/spookyboi/*.md /home/spookyboi/.notes* "
            "/home/spookyboi/notes/*; do echo \"== $f\"; cat \"$f\" 2>/dev/null; done"), flush=True)
    print("\n----- can we write collect.sh? -----\n" + await run(
        sh, "test -w /opt/scrape/collect.sh && echo WRITABLE || echo not-writable; "
            "test -w /opt/scrape && echo DIR-WRITABLE || echo dir-not-writable"), flush=True)
    print("\n----- sudo -n -l as spookyboi -----\n" + await run(sh, "sudo -n -l 2>&1 | head -20"), flush=True)
    return True


async def main():
    for attempt in range(1, 6):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                raise RuntimeError("silent")
        except Exception as e:
            print(f"[attempt {attempt}] {type(e).__name__}", flush=True)
            await asyncio.sleep(6)
    print("[!] failed", flush=True)


asyncio.run(main())
