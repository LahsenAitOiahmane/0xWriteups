"""Recon cryptctl with sentinel-terminated reads (no guessing at timing)."""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_flags as ff  # noqa: E402
from find_flags import Shell  # noqa: E402


async def run_until(sh, cmd, timeout=35.0):
    """Run cmd, then echo a unique marker; read until the marker comes back."""
    tag = "ZQ" + uuid.uuid4().hex[:8]
    await sh.send(cmd)
    await sh.send(f"echo {tag}END")
    buf, loop = "", asyncio.get_event_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        buf += await sh.read(1.0)
        if f"{tag}END" in buf:
            break
    # drop the echoed command + marker line
    lines = [l for l in buf.splitlines()
             if tag not in l and not l.strip().startswith("charon:~$")]
    return "\n".join(lines).strip()


async def body(sh):
    if not await ff.handshake_ok(sh):
        return False

    steps = [
        ("A. binary", "ls -la /opt/crypto/; file /opt/crypto/cryptctl 2>/dev/null || "
                      "echo 'no file(1)'; wc -c /opt/crypto/cryptctl"),
        ("B. caps", "getcap -r / 2>/dev/null"),
        ("C. help", "/opt/crypto/cryptctl --help 2>&1 | head -30"),
        ("D. users", "awk -F: '$3>=1000 && $3<65534 {print $1, $3}' /etc/passwd"),
        ("E. home perms", "ls -la /home/"),
        ("F. cryptctl dir", "ls -laR /opt/crypto/ 2>&1 | head -40"),
    ]
    for label, cmd in steps:
        print(f"\n===== {label} =====\n{await run_until(sh, cmd)}", flush=True)

    # now actually run it and see what identity we land in
    print("\n===== G. run cryptctl, then ask who we are =====", flush=True)
    await sh.send("/opt/crypto/cryptctl")
    print("immediate:", (await sh.read(10.0)).strip()[:500], flush=True)
    print("id      :", await run_until(sh, "id"), flush=True)
    print("home    :", await run_until(sh, "echo HOME=$HOME; pwd"), flush=True)
    print("flags   :", await run_until(sh, "cat /home/*/flag.txt 2>/dev/null"), flush=True)

    await sh.send("exit")
    await sh.read(2.0)
    return True


async def main():
    for attempt in range(1, 5):
        try:
            async with Shell() as sh:
                if await body(sh):
                    return
                raise RuntimeError("backend silent")
        except Exception as e:
            print(f"[attempt {attempt}] {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(6)
    print("[!] all attempts failed", flush=True)


asyncio.run(main())
