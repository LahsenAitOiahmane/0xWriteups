# FlagCasino — Reverse Engineering Write-Up

## 1) Title & Metadata

- Challenge: FlagCasino
- Category: Reverse Engineering
- Platform: Hack The Box (HTB)
- Author: L27Sen
- Date: 2026-01-04

---

## 2) Challenge Description

> FlagCasino
> The team stumbles into a long-abandoned casino. As you enter, the lights and music whir to life, and a staff of robots begin moving around and offering games, while skeletons of prewar patrons are slumped at slot machines. A robotic dealer waves you over and promises great wealth if you can win - can you beat the house and gather funds for the mission?

Attachments:
- `casino`

---

## 3) Goal / Objective

Recover the flag in the format `HTB{...}` by reversing the provided `casino` binary and determining the exact input that passes all checks.

---

## 4) Initial Analysis & Reconnaissance

### Identify the provided artifact

On Windows, the file appears as a single artifact named `casino`:

```powershell
Get-Item .\casino | Format-List *
```

Output (excerpt):

```text
Name   : casino
Length : 17064
```

Using WSL to identify the file type:

```bash
file casino; ls -l casino
```

Output:

```text
casino: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ac3d9d8a2c65ca7a0cb88af07efaec8c991c315d, for GNU/Linux 3.2.0, not stripped
-rwxrwxrwx 1 l27sen l27sen 17064 Jan  4 20:08 casino
```

Key observations:
- 64-bit Linux ELF (x86-64)
- PIE enabled (position independent)
- Dynamically linked against glibc
- Not stripped (symbols are present), which is helpful for reversing

### Run once to observe behavior

```bash
./casino
```

Output (excerpt):

```text
[*** PLEASE PLACE YOUR BETS ***]
> 123456789
[ * INCORRECT * ]
[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]
```

So the binary prompts for input and terminates immediately if a check fails.

### Quick string and symbol reconnaissance

`strings` reveals libc calls and useful labels:

```bash
strings -n 4 casino | head -n 200
```

Notable strings/symbols:
- `srand`, `rand`, `__isoc99_scanf`, `printf`, `puts`
- labels like `main` and `check`

`nm` confirms there is a global symbol named `check`:

```bash
nm -n casino | head -n 100
```

Output (excerpt):

```text
0000000000001185 T main
0000000000004080 D check
```

---

## 5) Attack Surface Identification

The only attacker-controlled input is what we type at the prompt.

From the observed behavior and the presence of `scanf(" %c")`, the program reads a character per round. This suggests:
- the “bet” is not parsed as a full integer
- instead, individual bytes/characters are used as inputs

The presence of `srand`/`rand` strongly suggests a randomness-based check. If the PRNG is seeded from user-controlled input, then the “random” values can be made deterministic.

---

## 6) Deep Technical Analysis

### Disassembling `main`

Disassembling `main` shows the core validation loop:

```bash
objdump -d -Mintel casino --start-address=0x1185 --stop-address=0x1280
```

Key excerpt (simplified from the disassembly):

- reads one character with `scanf(" %c")`
- seeds PRNG with that character via `srand()`
- calls `rand()` once
- compares the result with `check[i]`
- repeats for 29 rounds (`i` from 0 to 0x1c)

From the disassembly (important instructions):

```text
call   __isoc99_scanf
...
movsx  eax, BYTE PTR [rbp-0x5]   ; sign-extend input char
mov    edi, eax
call   srand
call   rand
...
lea    rdx, [rip+0x2e63]         ; &check
mov    edx, DWORD PTR [rdx + rcx]
cmp    eax, edx
jne    incorrect
```

### Confirming input format and loop count

Dumping `.rodata` confirms the scan format is `" %c"` (single char) and the prompt is `"> ":

```bash
objdump -s -j .rodata casino | sed -n '1,120p'
```

Output (excerpt):

```text
... 
003e2000 20256300  ETS ***].> . %c.
...
```

### Extracting the `check[]` table

The `check` symbol is located at virtual address `0x4080`:

```bash
nm -n casino | head -n 100
```

And `.data` begins at VA `0x4060`:

```bash
readelf -S casino | egrep ' \.data|\.text|\.rodata'
```

Output:

```text
[24] .data PROGBITS 0000000000004060 00003060
```

So the file offset for `check` is:

- `check_va - data_va + data_file_offset`
- `0x4080 - 0x4060 + 0x3060 = 0x3080`

Dumping `.data` shows a 29-element table starting at `0x4080`:

```bash
objdump -s -j .data casino
```

Output (excerpt):

```text
4080 be284b24 0578f70a 17fc0d11 a1c3af07
4090 33c5fe6a a259d64e b0d4c533 b8826528
40a0 20373843 fc145a05 9f5f1919 20373843
...
40f0 2abce922
```

### Reconstructing the program logic (pseudo-code)

```c
for (i = 0; i <= 0x1c; i++) {
    printf("> ");
    scanf(" %c", &c);

    srand((int8_t)c);       // sign-extended char
    r = rand();             // first PRNG output

    if (r != check[i]) {
        puts("[ * INCORRECT * ]");
        puts("[ *** ACTIVATING SECURITY SYSTEM - PLEASE VACATE *** ]");
        exit(-2);
    }

    puts("[ * CORRECT *]");
}

puts("[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]");
```

Important detail:
- The input is treated as a signed byte (`int8_t`) and then passed to `srand()`.

---

## 7) Vulnerability / Weakness Explanation

**Weakness:** Predictable PRNG usage with attacker-controlled seed.

The program uses:
- `srand(user_input_byte)`
- immediately followed by a single `rand()`

This turns each round into: “find a byte `c` such that `rand()` seeded with `c` equals `check[i]`.”

Because the seed space is only 256 possible values (a single byte), each round is trivially brute-forced offline. PIE/ASLR do not help here because the weakness is purely logical/cryptographic (predictable randomness), not memory corruption.

---

## 8) Exploitation Strategy

1. Extract the embedded `check[]` array from the binary.
2. For each target value `check[i]`, brute-force all 256 possible byte values `c`.
3. For each candidate byte, run `srand(c)` and compute the first `rand()`.
4. The byte that matches is the correct input for that position.
5. Concatenate the 29 recovered bytes to form the full input string (the flag).

This works reliably because:
- the PRNG algorithm is deterministic
- the program uses only the first `rand()` output per seed
- the seed space is extremely small (1 byte)

---

## 9) Exploit Implementation

Below is the exact Python approach used in WSL to recover the flag:

```bash
python3 - <<'PY'
import ctypes, struct
from pathlib import Path

p = Path('casino')
data = p.read_bytes()

# Computed from readelf/nm:
# .data file offset = 0x3060
# check VA = 0x4080, .data VA = 0x4060
# => check file offset = 0x3060 + (0x4080 - 0x4060) = 0x3080
off = 0x3080

# 29 dwords = 29 * 4 = 0x74 bytes
n = 0x74
check_bytes = data[off:off+n]
checks = list(struct.unpack('<' + 'I'*(n//4), check_bytes))

print('count', len(checks))
print('checks', [hex(x) for x in checks])

libc = ctypes.CDLL('libc.so.6')
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int

def first_rand(seed_u32: int) -> int:
    libc.srand(ctypes.c_uint(seed_u32))
    return libc.rand()

sol_bytes = []
for i, target in enumerate(checks):
    found = None
    for b in range(256):
        # emulate (int8_t)c sign extension in the binary
        seed = b if b < 128 else b - 256
        seed_u32 = seed & 0xffffffff

        if first_rand(seed_u32) == target:
            found = b
            break

    if found is None:
        raise SystemExit(f'no byte for index {i} target {target:#x}')

    sol_bytes.append(found)

s = bytes(sol_bytes)
print('solution bytes:', s)
print('as latin1:', s.decode('latin1'))
PY
```

Output:

```text
solution bytes: b'HTB{r4nd_1s_v3ry_pr3d1ct4bl3}'
as latin1: HTB{r4nd_1s_v3ry_pr3d1ct4bl3}
```

---

## 10) Flag Retrieval

Recovered flag:

```text
HTB{r4nd_1s_v3ry_pr3d1ct4bl3}
```

Verification by piping the flag into the program:

```bash
printf 'HTB{r4nd_1s_v3ry_pr3d1ct4bl3}' | ./casino
```

Output (excerpt):

```text
[*** PLEASE PLACE YOUR BETS ***]
> [ * CORRECT *]
[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]
```

(Note: the binary actually checks 29 characters/rounds; the provided capture shows the beginning of the successful run.)

---

## 11) Mitigation / Lessons Learned

If this were real application logic, recommended fixes would be:
- Do not use `rand()` for security decisions.
- Do not seed PRNG from attacker-controlled data.
- If unpredictability is required, use a cryptographically secure RNG.
- Never use “randomness checks” as a substitute for proper secret verification.

---

## 12) Conclusion

This challenge is solved by recognizing that the program’s “casino randomness” is fully deterministic and controlled by a 1-byte seed. Extracting the `check[]` targets and brute-forcing the seed per round reconstructs the exact 29-character input, which is the flag.
