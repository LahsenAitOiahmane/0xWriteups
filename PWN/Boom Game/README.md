# Boom Game (Pwn 421) - Writeup

## Challenge Summary

Boom Game is a 64-bit Linux PIE binary with modern mitigations enabled. The goal is to make the binary execute hidden functionality and print the flag.

Final recovered remote flag:

`NSC{0971196c4828b4886fbef9ef9d9e14bb}`

---

## Recon

### Binary properties

Using pwntools/checksec:

- Full RELRO
- Stack Canary found
- NX enabled
- PIE enabled
- Not stripped

This immediately removes easy GOT-overwrite plans (Full RELRO) and makes direct linear stack smash harder (Canary + PIE).

### Interesting symbols and strings

- `challenge()` main game loop
- `win()` executes `system("cat flag.txt")`
- format strings:
  - `"[%d] > "`
  - `"You said: %s\n"`
  - `"Correct: %s\n"`

### Key disassembly observations in `challenge()`

- `read(0, rbp-0x40, 0x50)` -> reads 0x50 bytes into a stack region that starts at `rbp-0x40`
- then `printf("You said: %s\n", rbp-0x40)` is called **before** the code forces a NUL at `rbp-0x31`
- then:
  - `dst` pointer at `rbp-0x18` is set to `rbp-0x40`
  - `src` pointer at `rbp-0x20` points to either `"boom"` or a stack string (`rbp-0x30`)
  - `strcpy(dst, src)`

Important stack offsets used in exploit (`solve.py`):

- `OFF_SRC_PTR = 0x20` (from input start)
- `OFF_CANARY = 0x38`
- `OFF_RET = 0x48`

---

## Vulnerability Analysis

This is a combined bug pattern:

1. **Unterminated `%s` print on attacker-controlled stack buffer**
   - `read()` accepts raw bytes and does not append NUL.
   - Program prints `You said: %s` before adding a terminating zero at `rbp-0x31`.
   - Result: controlled over-read into adjacent stack metadata.

2. **Stack overflow primitive**
   - `read(..., 0x50)` into area based at `rbp-0x40` allows overwrite beyond the intended input area.
   - Adjacent locals include pointer variables used later (`src` and `dst`) and canary/return path region.

3. **Post-read `strcpy()` with writable source pointer local**
   - `src` is at `rbp-0x20` and can be overwritten by crafted input.
   - This enables directed stack disclosure and controlled copy behavior.

Because of Full RELRO, canary, PIE, and NX, the clean route is:

- leak stack pointer
- derive canary address
- leak canary bytes
- preserve canary
- perform targeted partial RIP overwrite into `win`

---

## Exploit Strategy

Implemented in [solve.py](solve.py).

### Stage 1 - Leak stack pointer (`src_ptr`) from `You said:`

Round 1 payload:

- send exactly `b"A" * 0x20`
- parse bytes printed after the known prefix in `You said:` line

Why this works:

- print walks past attacker bytes into neighboring stack locals
- first useful leaked object is the `src` pointer at offset 0x20
- 6 leaked pointer bytes are enough for canonical 64-bit userland reconstruction

Computation:

- `src_ptr` points to `rbp-0x30`
- canary is at `rbp-0x8`
- therefore `canary_addr = src_ptr + 0x28`

### Stage 2 - Leak canary via `Correct: %s`

Round 2 payload:

- `b"B" * 0x20 + p64(canary_addr + 1)`
- this overwrites local `src` pointer

Effect:

- `strcpy(dst=rbp-0x40, src=canary+1)` copies 7 non-zero canary bytes
- then `printf("Correct: %s")` prints these copied bytes
- reconstruct canary as: `b"\x00" + leaked7`

### Stage 3 - Keep state stable

Rounds 3..29:

- send short safe byte (`b"Z"`) each round
- avoid disturbing canary/ret before final round

### Stage 4 - Final round overwrite (round 30)

Goal: return into `win` while keeping stack canary valid.

Final payload (`bytearray`, length `OFF_RET + 2`):

- set `payload[0x10:0x12] = b"Q\x00"` (safe short string for `strcpy` source)
- restore `src` local to valid stack pointer (`src_ptr`)
- restore exact leaked canary at `OFF_CANARY`
- fill saved RBP
- overwrite low 2 bytes of saved RIP at `OFF_RET` with `p16(0x11AA)`

`0x11AA` corresponds to `win+1` (skip `push rbp`).

Why `win+1` and not `win`:

- entering at function start via `ret` may break stack alignment before internal `call system`
- `win+1` preserves alignment for stable `system("cat flag.txt")`

---

## Reliability / Probability

The exploit uses a **2-byte partial RIP overwrite** under PIE.

- saved return address belongs to `main` (`...1330` offset region)
- low 16 bits are changed to `0x11AA`
- high bytes stay unchanged

Because PIE randomizes base and we only control 16 bits, this is probabilistic (observed around 1/16). The script handles this with retries:

- `ATTEMPTS=50` is usually enough
- script reconnects/restarts per attempt

Observed runs:

- Local solved at attempt 11
- Remote solved at attempt 15

---

## Solver Usage

### Local

```bash
python3 solve.py LOCAL ATTEMPTS=50
```

### Remote

```bash
python3 solve.py REMOTE ATTEMPTS=50
```

Default target in script:

- Host: `34.123.57.171`
- Port: `42059`

---

## GDB Workflow (Recommended)

### Useful breakpoints

```gdb
set disassembly-flavor intel
set pagination off
set disable-randomization off

b *challenge+0xc6      # near read setup/call path
b *challenge+0xe1      # after read / around You said flow
b *challenge+0x100     # before strcpy path
b *challenge+0x12f     # canary check block
b *win+1
run
```

### Inspect stack frame quickly

```gdb
x/40gx $rbp-0x50
p/x *(unsigned long long*)($rbp-0x20)   # src ptr local
p/x *(unsigned long long*)($rbp-0x8)    # canary
```

### Pwntools + GDB helper snippet

```python
io = gdb.debug([elf.path], gdbscript='''
set disassembly-flavor intel
b *challenge+0x100
b *win+1
c
''')
```

---

## Why This Challenge Is Nice

It forces a realistic chain instead of a single primitive:

- disclosure bug + stack pointer reasoning
- canary reconstruction
- careful stack hygiene for later rounds
- ABI/alignment detail (`win+1`)
- probabilistic PIE partial-overwrite handling with retries

This is a great example of turning small, constrained primitives into a practical end-to-end exploit.
