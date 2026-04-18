# read (499) - Pwn Writeup

## Challenge Info

- Category: pwn
- Points: 499
- Author: siegward
- Remote: `nc challs.insec.club 40003`
- Files provided: `read`, `loader`

## TL;DR

The binary `read` has a stack overflow (`read(0, buf, 0xb4)` into a 0x50-byte stack buffer).
By itself, exploitation is constrained by NX and a tiny gadget set.

The helper binary `loader` lets us patch exactly one byte in a temporary copy before execution.
We patch ELF program-header flags at file offset `0x15c` from `0x06` (RW) to `0x07` (RWE), making the `.bss` segment executable.

Then we use a 2-stage stack pivot:

1. Stage 1 overflow sets saved `rbp` to `.bss + 0x50` and returns to `0x4011c2` (inside the vulnerable function) to trigger another controlled `read`.
2. Stage 2 is written into `.bss`: shellcode at `.bss`, plus a fake frame so `leave; ret` jumps into shellcode.

Result: shell on remote, then read flag.

Flag:

`INSEC{aN0th3r_0ne_byt3s_th3_duSt111111}`

---

## 1) Recon

### `read` protections

- Arch: amd64
- PIE: disabled (fixed text base)
- Canary: absent
- NX: enabled
- RELRO: partial
- Stripped: yes

Important imported symbols are minimal: `read`, `alarm`, `setvbuf`, `__libc_start_main`.

### Vulnerable function (`read`)

Core snippet:

```asm
4011ba: push rbp
4011bb: mov rbp, rsp
4011be: sub rsp, 0x50
4011c2: lea rax, [rbp-0x50]
4011c6: mov edx, 0xb4
4011cb: mov rsi, rax
4011ce: mov edi, 0x0
4011d3: call read@plt
4011dd: leave
4011de: ret
```

This is a classic stack overflow:

- buffer size: `0x50`
- bytes read: `0xb4`
- overwrite reaches saved `rbp` and saved `rip`

Offset to saved RIP = `0x50 + 0x8 = 0x58`.

---

## 2) `loader` Analysis

`loader` behavior:

1. Prints a banner.
2. Reads `Offset (hex):` and `Value (hex):`.
3. Creates `/tmp/read_XXXXXX` with `mkstemp`.
4. Copies the original target there via `sendfile`.
5. Patches one byte at user-controlled file offset.
6. `fork` + `execve` on the patched temp file.
7. Parent waits and unlinks temp file.

So the original `read` file is never modified; patch applies only to the child instance.

### Loader guardrails

`loader` tries to block syscall-byte construction:

- blocks creating `0x0f 0x05` (`syscall`) via adjacent-byte patches
- blocks creating `0xcd 0x80` (`int 0x80`) via adjacent-byte patches

This only prevents *creating* those two-byte patterns by patching one byte next to the other.
It does not stop us from making `.bss` executable and running shellcode that already contains `syscall` bytes.

---

## 3) Exploit Strategy

## 3.1 Make `.bss` executable with one byte

In ELF64 program headers, each entry is 0x38 bytes.
For the RW load segment, `p_flags` is at:

- `e_phoff + index * sizeof(Phdr) + 0x4`

For this binary, that resolves to file offset `0x15c`.

Byte value there is `0x06` (PF_R | PF_W).
Patching to `0x07` (PF_R | PF_W | PF_X) makes the data segment executable:

```text
offset = 0x15c
value  = 0x07
```

Now `.bss` can host shellcode.

## 3.2 Stage 1: stack pivot + re-entry

We craft first overflow (`0xb4` bytes):

- `saved rbp = 0x404080 + 0x50`
- `saved rip = 0x4011c2`

When the vulnerable function returns, execution re-enters at `0x4011c2` and executes another `read`.
Because `rbp` is forged, `lea rax, [rbp-0x50]` points to `.bss`.
So second `read` writes controlled bytes directly into `.bss`.

## 3.3 Stage 2: shellcode + fake frame in `.bss`

Layout for second payload:

- `.bss + 0x00`: NOP sled + `execve("/bin//sh", 0, 0)` shellcode
- `.bss + 0x50`: next `rbp` (dummy valid pointer)
- `.bss + 0x58`: next `rip = .bss + 0x00`

At function epilogue (`leave; ret`), control flows into `.bss` shellcode.

---

## 4) Reliability Note (important)

`loader` reads offset/value with stdio (`fgets`/`strtoul` path). If exploit bytes are sent too early,
stdio buffering may consume part of stage 1 before the child process `execve`s.

A short delay after sending patch values (about 350ms here) makes delivery stable.

---

## 5) Final Exploit Script

Exploit is provided in `solve.py`.

Features:

- Local mode: talks to `./loader`
- Remote mode: talks to `challs.insec.club:40003`
- Optional one-shot command mode via `CMD='...'`
- GDB attach support in local mode

### Usage

```bash
# Remote interactive shell
python3 solve.py

# Remote one-shot command
python3 solve.py CMD='id'

# Local one-shot command
python3 solve.py LOCAL CMD='id'

# Read remote flag
python3 solve.py CMD='cat /home/ctf/flag.txt'
```

---

## 6) GDB Setup

Use:

```bash
python3 solve.py LOCAL GDB
```

Or manual:

```gdb
set disassembly-flavor intel
set follow-fork-mode child
set detach-on-fork off
set breakpoint pending on
catch exec
b *0x4011ba
b *0x4011c2
b *0x4011dd
continue
```

What to check:

- after first overflow, verify `rbp = 0x4040d0` (or expected `.bss + 0x50`)
- on re-entry at `0x4011c2`, confirm destination pointer is `.bss`
- after second read, confirm fake frame and shellcode are in place
- at final `ret`, confirm RIP lands in `.bss`

---

## 7) Why This Works Despite Mitigations

- NX: bypassed by making data segment executable through loader byte patch
- PIE off: fixed addresses simplify pivot and re-entry
- No canary: direct stack smash to saved RIP
- Partial RELRO: not directly needed for this chain

---

## 8) Minimal Exploit Flow Recap

1. Connect to loader service.
2. Send patch offset/value: `15c` / `7` (hex).
3. Send stage1 overflow (pivot + re-entry).
4. Send stage2 (`.bss` shellcode + fake frame).
5. Get shell and read `/home/ctf/flag.txt`.
