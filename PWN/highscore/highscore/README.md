# highscore - INSEC CTF Pwn Writeup

## Challenge Info
- Name: highscore
- Category: pwn
- Author: siegward
- Points: 500
- Remote: `nc challs.insec.club 40009`
- Files: `highscore`, `libc.so.6`, `ld-linux-x86-64.so.2`

## TL;DR
The bug is a classic format-string vulnerability in menu option 1:
- User-controlled input is passed directly to `printf(name_buf)`.
- We use positional format specifiers to leak libc and stack pointers.
- We use `%12$hhn` for arbitrary byte writes.
- We overwrite the saved return address with a ret2libc chain:
  - `ret`
  - `pop rdi; ret`
  - `"/bin/sh"`
  - `system`
  - `exit`
- Trigger return via option 4.
- Get shell, read flag.

Final flag:

`INSEC{s1MPlE_ReT2syst3m_1_hoPE_1T_D1Dnt_t4K3_t0O_much_t1Me:)}`

---

## 1) Recon

### Binary properties
`file highscore`:
- ELF 64-bit PIE executable, dynamically linked, not stripped

`readelf` highlights:
- PIE: enabled (`Type: DYN`)
- NX: enabled (`GNU_STACK` is RW, not RWE)
- Canary: enabled (`__stack_chk_fail` present)
- RELRO: Full (`BIND_NOW`, `FLAGS_1: NOW PIE`)
- Linked libc: provided local `libc.so.6`
- Interpreter: provided local `ld-linux-x86-64.so.2`

### Symbols / globals
- `main` at `0x11d9`
- `player` global at `0x4060`, size `36`
  - name buffer at `player + 0x00` (32 bytes)
  - score at `player + 0x20` (int)

Because of Full RELRO, direct GOT overwrite is not viable. We need a stack/control-flow target.

---

## 2) Root Cause

In menu option 1 (set player name), the binary does:
1. `fgets(local_buf, 0x20, stdin)`
2. `printf(local_buf)`  <-- vulnerable format string
3. `strncpy(player, local_buf, 0x1f)`

Key disassembly pattern:

```asm
lea    rax,[rbp-0x30]
mov    esi,0x20
mov    rdi,rax
call   fgets@plt
...
lea    rax,[rbp-0x30]
mov    rdi,rax
mov    eax,0x0
call   printf@plt   ; format string vulnerability
```

No stack overflow is required. The format primitive is enough for leak + write.

---

## 3) Primitive Development

### 3.1 Leak Primitive
By probing positional specifiers (`%N$p`), useful stable leaks are:
- `%17$p` -> libc return-site pointer
- `%18$p` -> stack pointer near saved RIP

Recovered relation:
- `libc_base = leak17 - 0x29ca8`
- `saved_rip_slot = leak18 - 0xf8`

The `0xf8` delta was verified repeatedly both local and remote.

### 3.2 Byte-Write Primitive
We use `%12$hhn` to write one byte to an arbitrary address.

Payload layout:
- format chunk at start: `%<width>c%12$hhn`
- padded to 16 bytes
- append target address with `p64(addr)`

Example builder:

```python
width = byte_value if byte_value != 0 else 256
fmt = f"%{width}c%12$hhn".encode()
payload = (fmt + b"\x00").ljust(16, b"A") + p64(addr)
```

Then write qwords byte-by-byte.

### Important reliability edge case
`fgets` stops at newline (`0x0a`).
If any byte of `p64(target_addr)` is `0x0a`, payload is truncated and the process can die.

Fix used in final exploit:
- Detect unsafe target address bytes (`0x0a` in pointer bytes).
- Retry with a fresh connection and new ASLR layout until safe.

This was essential for stable remote exploitation.

---

## 4) ROP Chain

Using provided `libc.so.6`:
- `ret` offset: `0x2846b`
- `pop rdi; ret` offset: `0x2a145`
- `system` offset: `0x53110`
- `exit` offset: `0x42340`
- `"/bin/sh"` offset: `0x1a7ea4`

Final chain at saved RIP:

```text
ret
pop rdi; ret
/bin/sh
system
exit
```

Trigger return by choosing menu option `4`.

---

## 5) Final Exploit Script

Implemented in: `solve.py`

### Local run
```bash
python3 solve.py
```

### Remote run
```bash
python3 solve.py REMOTE
```

The script:
1. Leaks `%17$p` and `%18$p`
2. Computes libc base and saved RIP slot
3. Verifies newline-safe write plan
4. Writes full ROP chain byte-by-byte
5. Exits menu to return into chain
6. Sends flag-read commands and prints `INSEC{...}`

---

## 6) Verification Logs

### Local
- Shell obtained:
  - `uid=0(root) gid=0(root) groups=0(root)`

### Remote
- Shell obtained:
  - `uid=10001(ctf) gid=10001(ctf) groups=10001(ctf)`
- Flag extracted:
  - `INSEC{s1MPlE_ReT2syst3m_1_hoPE_1T_D1Dnt_t4K3_t0O_much_t1Me:)}`

---

## 7) Useful GDB Workflow

Useful breakpoint at vulnerable call:

```gdb
break *main+0x204
run
info registers rdi rsi rdx rcx r8 r9 rsp rbp
x/20gx $rbp-0x60
x/20gx $rsp
```

This is enough to map stack argument positions for format specifiers and confirm saved RIP location relative to leaks.

---

## 8) Why This Works Despite Mitigations

- Canary: irrelevant (no stack smash needed)
- NX: bypassed via ret2libc
- PIE/ASLR: defeated with format-string leaks
- Full RELRO: avoided by targeting saved return address instead of GOT

The exploit path is straightforward once leak/write positions are mapped.
