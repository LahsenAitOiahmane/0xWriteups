# jollyvm — Reverse Engineering VM License Check (Write-up)

## Challenge summary
The binary `jollyvm` is an ELF64 (x86-64) program that asks for a **52-character license key**. Internally it runs a small **custom virtual machine (VM)** that transforms the user input and compares the result to an embedded 52-byte constant.

Goal: recover an input that passes the check and reveals the flag.

---

## Quick facts
- Platform: Linux ELF64 PIE (works fine under WSL)
- Input: exactly **52 bytes** (newline removed)
- Output:
  - `[+] License valid.` on success
  - `[-] Invalid license key.` otherwise

---

## High-level behavior
The decompiled `main` shows:
1. Print banner + prompt.
2. `fgets()` reads a line.
3. `strcspn(s, "\n")` strips the newline.
4. If length is **not 52**, fail.
5. If length is 52:
   - Copy the 52 bytes into a buffer.
   - Initialize VM state (registers + pointers).
   - Execute **156 VM instructions** from a bytecode table.
   - The VM writes 52 output bytes into a VM “memory” buffer.
   - The program compares these 52 bytes to a constant array at `.rodata+0x20E0`.
   - If all match: success.

The key insight (per the hints): although there’s a lot of VM machinery, **only a small piece of state actually matters for the final compare**.

---

## VM format
The bytecode lives in `.rodata` at `0x2120`.

Each instruction is **6 bytes**:
- `op` (1 byte)
- `a` (1 byte)
- `b` (1 byte)
- `pad` (1 byte)
- `imm` (2 bytes, little endian)

The interpreter uses a jump table at `.rodata+0x2080` for `op <= 0x16` (23 opcodes).

VM state:
- `v26[]` acts as the register file (DWORDs)
- `&v26[24]` is used as a byte-addressable “memory” region
- `v28` contains the 52 input bytes
- `byte_20E0` contains the 52-byte target constant

Important initialization (from `main`):
- `v26[0] = 52`
- `v26[9] = 62263 (0xF337)`

These initial register values matter.

---

## Opcode semantics (as observed)
From your decompilation, the VM implements:

### Arithmetic / bitwise
- `0`: `reg[a] = (int16)imm`
- `1`: `reg[a] = reg[b]`
- `2`: `reg[a] += (int16)imm`
- `3`: `reg[a] += reg[b]`
- `4`: `reg[a] -= (int16)imm`
- `5`: `reg[a] -= reg[b]`
- `6`: `reg[a] ^= reg[b]`
- `7`: `reg[a] |= reg[b]`
- `8`: `reg[a] = reg[b] << imm`
- `9`: `reg[a] = reg[b] >> imm`
- `10`: `reg[a] &= imm`

### Load/store helpers
- `11` (LDBK): `reg[a] = input[reg[b] + (int16)imm]` if index <= 0x33 else 0
- `12` (STBM): `mem[reg[b] + (int16)imm] = reg[a] & 0xFF` if addr <= 0xFF
- `13` (LDBM): `reg[a] = mem[reg[b] + (int16)imm]` if index <= 0x33 else 0
- `14` (LDBC): `reg[a] = const[reg[b] + (int16)imm]` if index <= 0x33 else 0

### Control flow (flag stored in `v12`)
- `15`: `v12 = (reg[a] < (uint32)(int16)imm)`
- `16`: `v12 = (reg[a] == (int16)imm)`
- `17`: `v12 = (reg[a] == reg[b])`
- `18`: `ip = (int16)imm`
- `19`: if `v12` then `ip = (int16)imm` else continue
- `20`: if `!v12` then `ip = (int16)imm` else continue

### Result / exit
- `21`: stage a boolean result value (based on `imm != 0`)
- `22`: halt; if a staged value exists, store it into `v26[89]`, then exit using `v26[89]`

A subtle but critical detail: **jumps assign `ip = imm` directly** (not `imm+1`).
Getting that wrong leads to a “valid” solution for the wrong program.

---

## What the VM is doing logically
The VM takes the 52 input bytes and builds a 52-byte output buffer (written via opcode `12` into `&v26[24]`).

Near the end, it loops:
- `mem[i]` (via opcode `13`)
- `const[i]` (via opcode `14`)
- compares them (opcode `17`)
- fails fast if any mismatch

So the acceptance condition is exactly:

> `VM_transform(input)[0..51] == byte_20E0[0..51]`

---

## Solving approach
The transform only uses operations like XOR, shifts, OR, and masking — which are linear over GF(2) at the bit level (no multiplication, no S-boxes, no modular addition affecting carries in the output bytes).

So we treat the VM as a black box function:

- Input: 416 bits (52 bytes)
- Output: 416 bits

Then we:
1. Run the VM once on all-zero input to get a baseline output.
2. For each input bit position `j` (0..415):
   - flip that one input bit
   - run the VM again
   - record which output bits changed
3. This yields a 416×416 linear system:

$$A x = b$$

Where:
- $x$ is the unknown 416-bit license key
- $b$ is the 416-bit constant target (XORed with the baseline)

4. Solve using Gaussian elimination over GF(2).

This produces a valid 52-character ASCII license key.

---

## Final flag
```
csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}
```

---

## How to verify
### Under WSL
From the workspace folder:

```bash
printf '%s\n' 'csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}' | /mnt/c/Users/sadik/Downloads/jolly/jollyvm
```

Expected:
```
[*] NPLD Tool Suite v2.4.1
Enter license key: [+] License valid.
```

---

## Reference solver
A working solver/emulator is included as:
- `solve_jollyvm.py`

It:
- parses the embedded VM bytecode and constants from the binary
- emulates the VM accurately (including jump + halt semantics)
- solves the linear system over GF(2)
- prints the final key/flag
