# Necro Game (Pwn) - Writeup

## Overview
This challenge is a 64-bit Linux PIE binary that exposes a format-string bug in the ritual input path. The bug gives both read and write primitives. We use it to leak stack values (canary, saved rbp, return addresses), compute PIE/libc bases, then overwrite the saved return address with a short ROP chain to call system("/bin/sh").

## Binary properties
- Arch: amd64
- PIE: enabled
- NX: enabled
- Stack canary: enabled
- RELRO: Full
- IBT/SHSTK: enabled (CET)

## Vulnerability
Function ritual reads 0x200 bytes into a stack buffer and then calls printf on that buffer:

- read(0, buf, 0x200)
- printf(buf)

This is a classic format string vulnerability. Stack canary blocks a straight overflow, but the format string lets us leak and write arbitrary addresses on the stack.

## Recon notes
The menu options are:
1) Bind a Soul
2) Inscribe Ritual
3) Release Soul
4) Exit

The exploit uses only option 2.

## Primitive 1: stack leaks
We first find the stack argument index of the buffer. A marker proves that buffer offset 0 is argument index 6:

- payload: "AAAABBBB|%6$p|%7$p"
- result: %6$p prints 0x4242424241414141 (little endian for AAAABBBB)

Useful leak indices (stable across runs):
- %71$p -> stack canary
- %72$p -> saved rbp (from main)
- %73$p -> saved rip (return into main)
- %77$p -> libc return (inside __libc_start_main)

## Base calculations
From the leaked values:
- PIE base = saved_rip - 0x1468
  - 0x1468 is main+0xbc in this binary
- libc base = libc_ret - __libc_start_main - 243
  - 243 is the standard offset to the return site in __libc_start_main

## Primitive 2: arbitrary writes with %hn
We build a format string that uses %hn to write 2 bytes at a time. The target addresses are appended after the format string, and positional %n$hn arguments are used to reference them.

To stabilize argument indexing, the script computes the correct argument base from the final length of the format string and 8-byte alignment.

## ROP chain
We overwrite the saved return address of ritual to pivot into a short ROP chain:

- ret (stack alignment)
- pop rdi; ret
- /bin/sh
- system

Addresses:
- pop rdi; ret = PIE base + 0x1503
- ret = PIE base + 0x101a
- system, /bin/sh from libc

The saved RIP address is computed via the saved rbp from main:
- ritual rbp = saved_rbp - 0x20
- saved_rip_addr = ritual rbp + 8

## Exploit flow
1) Leak canary, saved rbp, saved rip, libc return.
2) Compute PIE and libc bases.
3) Build a %hn write payload to overwrite saved RIP with the ROP chain.
4) Trigger the return from ritual and get a shell.
5) Read flag.txt.

## Files
- solve.py: full exploit implementation
- libs/libc-2.31.so: provided libc
- libs/ld-linux-x86-64.so.2: provided loader

## Run
Local:

```
cd necro_unzipped/necro
python3 solve.py
```

Remote:

```
cd necro_unzipped/necro
python3 solve.py REMOTE=1
```

## Flag
NSC{ce3ebacdc635532fe94537bc7a549a30}}
