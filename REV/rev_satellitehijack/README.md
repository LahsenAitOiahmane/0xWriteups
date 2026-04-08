## 1️⃣ Title & Metadata

- Challenge: Satellite Hijack
- Category: Reverse Engineering
- Difficulty: Hard
- Platform / CTF: Hack The Box (HTB)
- Author: L27Sen
- Date: 2026-01-04
- Environment: Windows host + WSL (Linux userland)

---

## 2️⃣ Challenge Description

Provided (from the session context):

- A reverse engineering challenge named “Satellite Hijack”.
- Attachments: `satellite` and `library.so`.
- Goal context: “get the flag `HTB{...}`”.

Constraints (from the session instructions):

- Every executed command or script output must be appended to `outputs.txt`.

---

## 3️⃣ Goal / Objective

Recover the valid flag in the `HTB{...}` format by reversing the provided binaries and validating the result against the challenge program.

---

## 4️⃣ Initial Analysis & Reconnaissance

### File identification

From `outputs_full.txt`:

```text
./satellite:  ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=10cc2ba53a9cb7ac49b751f3b210286665ca0386, for GNU/Linux 3.2.0, not stripped
./library.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=392d868b5f763513c8ad2838cd8476875f1f14ea, stripped
```

Key takeaways:

- 64-bit Linux (x86-64) target.
- `satellite` is PIE.
- `library.so` is stripped (symbols removed), so reversing relies more on disassembly + behavior.

### Hashing

From `outputs_full.txt`:

```text
6f07d3f664f5bb1962f0069a9315dc5ffd6a1a3830db10e1dfe71d2813334e1b  ./satellite
4127782d0b1973a6b8acb9ff3ce8a63c8b23aa625d92de33ec58850d5d1833c5  ./library.so
```

### Dependencies

From `outputs_full.txt` (`ldd`):

```text
== LDD (satellite) ==
	linux-vdso.so.1 (0x00007fff5091c000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007c43dba00000)
	./library.so (0x00007c43dbce1000)
	/lib64/ld-linux-x86-64.so.2 (0x00007c43dbcf3000)
```

Important observation: `satellite` explicitly depends on `./library.so`.

### ELF metadata / protections

From `outputs_full.txt` (`readelf` dynamic section):

```text
0x000000006ffffffb (FLAGS_1)            Flags: PIE
```

Other protection details (NX, RELRO, canary, etc.): Not provided (no `checksec` output in the logs).

### Quick strings triage

From `outputs_full.txt` (`triage.sh`):

- `satellite` exposes UI/behavior strings:
  - `READY TO TRANSMIT`
  - `ERROR READING DATA`
  - `Sending `%s``
  - `send_satellite_message`

- `library.so` imports suspicious capabilities:
  - `getenv`, `mmap`, `memcpy`, `memfrob`

This strongly suggests:

- The main program takes user input (“transmit”).
- The shared library does something environment-controlled (`getenv`).
- There is likely packed/obfuscated code (`memfrob` is a classic XOR 0x2a helper).

---

## 5️⃣ Attack Surface Identification

The meaningful “attack surface” for reversing is the program-controlled input flow and any hidden feature gates.

### 1) User input path

From `outputs_full.txt`, the `main` function reads user input and later prints `Sending ...`.

A critical detail is visible in the disassembly of `main`:

```text
1211: bf 01 00 00 00        mov    edi,0x1
1216: e8 55 fe ff ff        call   1070 <read@plt>
```

This indicates `read(1, ...)` (FD=1) rather than `read(0, ...)` (stdin).

### 2) Environment variable gate in `library.so`

From `outputs_full.txt` disassembly of `send_satellite_message`:

- It builds a string in a local stack buffer.
- It decrements each character (`sub eax, 0x1`) in a loop.
- It then calls `getenv()`.

```text
2624: 83 e8 01              sub    eax,0x1
...
2645: e8 e6 e9 ff ff        call   1030 <getenv@plt>
264a: 48 85 c0              test   rax,rax
264d: 74 0a                 je     2659
264f: ...
2654: e8 8a fd ff ff        call   23e3
```

Additionally, `triage.sh` captured these obfuscated fragments in `library.so` strings:

```text
TBU`QSPEH
`FOWJSPOH
SPONFOU
```

Decrementing each byte by 1 yields the environment variable name:

- `TBU`QSPEH` → `SAT_PROD_ENV`
- ``FOWJSPOH` → `_ENVIRONM`
- `SPONFOU` → `RONMENT`

So the complete gate is:

- `SAT_PROD_ENVIRONMENT`

---

## 6️⃣ Deep Technical Analysis

### A) Why the binary spammed “ERROR READING DATA”

Because `satellite` reads from FD=1, it behaves differently depending on whether FD=1 is connected to a TTY/PTY.

Evidence from `outputs_full.txt`:

- Running normally produces repeated failures:

```text
| READY TO TRANSMIT |
> ERROR READING DATA
```

- Running under a pseudo-terminal (PTY) allows input to be “read” and processed:

```text
> test
Sending `test`
```

This is why a PTY-based runner (`run_satellite_pty.py`) was used for reliable interaction.

### B) Locating the hidden logic

The analysis focused on the shared library because:

- `satellite` imports `send_satellite_message` from `./library.so`.
- `library.so` contains `getenv` + `memfrob` + `mmap`, which commonly indicates an unpack/decrypt loader.
- The function `send_satellite_message` explicitly checks `SAT_PROD_ENVIRONMENT` and conditionally calls deeper logic (call target at `0x23e3` in the disassembly).

### C) Extracting and decrypting the embedded payload

A 0x1000-byte blob was extracted from `library.so` and XOR-decrypted with key `0x2a`.

This is implemented in `extract_payload.py` and logged in `outputs.txt`:

```text
Wrote payload_dec.bin (4096 bytes), xor key=0x2a, from library.so offset 0x11a9
Interesting ASCII strings in decrypted payload:
HTB{u
```

Key technical facts (all from logs / script):

- File offset: `0x11a9`
- Size: `0x1000`
- XOR key: `0x2a`
- Output: `payload_dec.bin`

### D) Finding the verifier and reconstructing the flag

`find_flag.py` was used to locate the `HTB{` marker inside the decrypted payload.

From `outputs.txt`:

```text
Found 'HTB{' at offset 0x4b (75)
```

The disassembly around the check (from `outputs.txt`) shows:

1) It searches for the dword `0x7b425448` which is `"HTB{"` in little-endian.

```text
48: 81 7b fc 48 54 42 7b   cmp DWORD PTR [rbx-0x4],0x7b425448
```

2) The verifier function (called at `0x8c`) loads a byte array (“key”) onto the stack via immediates.

```text
8c: movabs rax,0x37593076307b356c
96: movabs rdx,0x3a7c3e753f665666
...
aa: movabs rax,0x784c7c214f3a7c3e
b4: movabs rdx,0x663b2c6a246f21
```

3) It validates 0x1c (28) bytes with an XOR-with-index rule:

```text
d7: 0f b6 14 07           movzx edx,BYTE PTR [rdi+rax*1]   ; input[i]
db: 32 14 08              xor   dl,BYTE PTR [rax+rcx*1]    ; input[i] XOR key[i]
...
e2: 48 39 c2              cmp   rdx,rax                    ; == i ?
...
f0: 48 83 f8 1c           cmp   rax,0x1c                   ; 28 bytes
```

So the condition is:

- `input[i] XOR key[i] == i` for `i = 0..27`

Rearranging:

- `input[i] = key[i] XOR i`

The derived bytes were logged directly in `outputs.txt`:

```text
== DERIVED FLAG BYTES ==
b'l4y3r5_0n_l4y3r5_0n_l4y3r5!}'
== DERIVED FLAG ASCII ==
l4y3r5_0n_l4y3r5_0n_l4y3r5!}
```

This string already contains the closing brace, so the final flag is simply:

- `HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}`

---

## 7️⃣ Vulnerability / Weakness Explanation

This challenge does not present a memory corruption bug in the provided logs; instead, the “weakness” enabling the solve is a reversible, low-entropy verification scheme.

- Type: Weak obfuscation / reversible verification
- Root cause:
  - The verifier checks `input[i] XOR key[i] == i`, which is trivially invertible.
  - The “protected” code is only XOR-obfuscated (via `memfrob`/XOR `0x2a`), which is not cryptography.
- Why exploitable (for solving):
  - Once the key bytes are recovered from the decrypted payload, the correct input is computed directly with `input[i] = key[i] XOR i`.

---

## 8️⃣ Exploitation Strategy

1) Identify what the program depends on.
   - `satellite` loads `./library.so`.

2) Identify hidden feature gates.
   - `send_satellite_message` checks `SAT_PROD_ENVIRONMENT` (derived by decrementing obfuscated bytes).

3) Handle the I/O gotcha.
   - `satellite` reads from FD=1, so interact through a PTY to avoid infinite `ERROR READING DATA` loops.

4) Extract and decrypt the embedded payload.
   - Pull 0x1000 bytes from `library.so` at offset `0x11a9`.
   - XOR with `0x2a` to get `payload_dec.bin`.

5) Reverse the validation logic.
   - Find the `HTB{` marker and analyze the check.
   - Invert the XOR-with-index rule to compute the exact flag.

6) Validate by running the challenge binary with the derived flag.

---

## 9️⃣ Exploit Implementation

This solve is fully reproducible with the included helper scripts.

### Step 1: Static triage

Run (WSL):

```bash
bash triage.sh
```

This collects strings, symbols, and relevant disassembly (see `outputs_full.txt`).

### Step 2: Decrypt the embedded payload

Run (WSL):

```bash
python3 extract_payload.py
```

Expected log (from `outputs.txt`):

```text
Wrote payload_dec.bin (4096 bytes), xor key=0x2a, from library.so offset 0x11a9
```

Implementation highlight (from `extract_payload.py`):

```python
START = 0x11A9
SIZE = 0x1000
KEY = 0x2A
...
chunk = bytearray(b[START:START+SIZE])
for i in range(len(chunk)):
    chunk[i] ^= KEY
```

### Step 3: Locate the `HTB{` marker and inspect bytes

Run (WSL):

```bash
python3 find_flag.py
```

Expected log (from `outputs.txt`):

```text
Found 'HTB{' at offset 0x4b (75)
```

### Step 4: Reliable interaction using a PTY

Run (WSL):

```bash
python3 run_satellite_pty.py
```

This uses `pty.fork()` to provide the program a pseudo-terminal so the FD=1 read works as observed in logs.

---

## 🔟 Flag Retrieval

The flag was validated by sending it to the running binary under a PTY.

From `outputs.txt`:

```text
| READY TO TRANSMIT |
> HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}
Sending `HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}`
```

Flag:

```text
HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}
```

---

## 1️⃣1️⃣ Mitigation / Lessons Learned (Optional but Professional)

If this were production code (not a CTF), the following would be appropriate hardening actions:

- Avoid reversible “XOR-with-index” checks for secrets; use a proper cryptographic verification (e.g., MAC) instead.
- Avoid XOR-only “encryption” (`memfrob` / XOR `0x2a`) for protected logic or secrets.
- Avoid RWX mappings and self-modifying code patterns (`mmap` + decrypt + execute) unless absolutely required.
- Remove environment-variable backdoors and hidden feature gates.
- Fix I/O correctness: read user input from FD=0 (stdin), not FD=1 (stdout).

---

## 1️⃣2️⃣ Conclusion

This challenge combined an unusual I/O behavior (reading from FD=1), an environment-variable gated code path, and a simple XOR-obfuscated payload.

After extracting and XOR-decrypting the embedded payload, the flag was recovered by inverting a straightforward verifier equation and then validated by successfully transmitting it to the program.
