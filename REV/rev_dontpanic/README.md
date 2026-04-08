# Don't Panic! — Reverse Engineering Write-Up

## 1️⃣ Title & Metadata

- Challenge: Don't Panic!
- Category: Reverse Engineering
- Difficulty: Not provided
- CTF / Platform: Hack The Box (HTB)
- Author: L27Sen
- Date: 2026-01-04

---

## 2️⃣ Challenge Description

> You've cut a deal with the Brotherhood; if you can locate and retrieve their stolen weapons cache, they'll provide you with the kerosene needed for your makeshift explosives for the underground tunnel excavation. The team has tracked the unique energy signature of the weapons to a small vault, currently being occupied by a gang of raiders who infiltrated the outpost by impersonating commonwealth traders. Using experimental stealth technology, you've slipped by the guards and arrive at the inner sanctum. Now, you must find a way past the highly sensitive heat-signature detection robot. Can you disable the security robot without setting off the alarm?

Provided files:
- `dontpanic`

Constraints:
- Remote service: Not provided
- Time limit: Not provided
- Brute force restrictions: Not provided

---

## 3️⃣ Goal / Objective

- Extract the flag in the format `HTB{...}`.
- Solve the input validation required to "disable the security robot" without triggering the panic/alarm path.

---

## 4️⃣ Initial Analysis & Reconnaissance

### File type and basic properties

The binary is a Linux ELF and includes debug information:

```bash
file ./dontpanic
```

Observed output:

```text
./dontpanic: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=042993addd88b36857a8c09d28b3630059a04fc8, for GNU/Linux 3.2.0, with debug_info, not stripped
```

### First runtime observation

Running the program without providing input triggers the panic path:

```bash
./dontpanic
```

Observed output:

```text
🤖💬 < Have you got a message for me? > 🗨️ 🤖: 😱😱😱 You made me panic! 😱😱😱
```

### Strings and symbols

A quick `strings` pass shows the program is a Rust binary (many `std::panic`/runtime strings) and includes the message:

```text
You made me panic!
```

Symbols of interest (via `nm -C`) include:

```text
0000000000009060 t src::check_flag
0000000000009230 t src::main
```

### Protections

- `checksec`: Not provided (tool output was empty/not available in the captured logs).
- From `file`, the binary is PIE (`pie executable`).

---

## 5️⃣ Attack Surface Identification

The primary attacker-controlled surface is standard input:

- The program asks: "Have you got a message for me?"
- Changing the input changes the observed behavior:
  - No input / wrong input → panic message
  - Correct input → success message (see Flag Retrieval)

No network endpoints, file parsing, or cryptographic primitives were identified in the provided outputs.

---

## 6️⃣ Deep Technical Analysis

### High-level control flow

The core logic is implemented in `src::check_flag`.

From the disassembly (captured in `outputs.txt`), `src::check_flag`:

1. Asserts the input length is exactly `0x1f` (31) bytes:

```text
91c4:       mov    QWORD PTR [rsp+0x8],0x1f
91cd:       cmp    rsi,0x1f
```

2. Builds a table of 31 function pointers on the stack (at `[rsp+0x10]`, `[rsp+0x18]`, ...). Example entries:

```text
9074:       mov    QWORD PTR [rsp+0x10],rax
9080:       mov    QWORD PTR [rsp+0x18],rax
...
91b8:       mov    QWORD PTR [rsp+0x100],rax
```

3. Loops over each input byte and calls the corresponding function pointer:

```text
91e4:       movzx  edi,BYTE PTR [rbx+rax*1]
91e8:       call   QWORD PTR [rsp+rax*8+0x10]
```

### Per-character validation stubs

Each function pointer points to a small Rust `FnOnce::call_once` stub that compares the provided byte in `dil` against a constant:

```text
8e01:       cmp    dil,0x7b
```

The captured stub constants include values for characters like:

- `0x48` (`H`)
- `0x54` (`T`)
- `0x42` (`B`)
- `0x7b` (`{`)
- `0x7d` (`}`)

This design means the expected input can be recovered statically by:

1. Reading the order of function pointers stored in `src::check_flag`.
2. Mapping each referenced stub address to its `cmp dil, 0x??` immediate.

---

## 7️⃣ Vulnerability / Weakness Explanation

Type:
- **Weak obfuscation / hardcoded secret in validation logic**

Why it exists:
- The program validates the "flag" by checking each character against hardcoded byte constants.
- Function pointers add indirection, but they do not hide the constants from static analysis.

Why it is exploitable:
- Because the binary is **not stripped** and the per-byte comparisons are visible in disassembly, the expected input can be reconstructed without guessing or brute force.

---

## 8️⃣ Exploitation Strategy

Strategy overview:

1. Disassemble the binary and locate `src::check_flag`.
2. Confirm the fixed input length requirement (`0x1f` bytes).
3. Extract the function-pointer table order (31 entries).
4. For each referenced stub, extract the immediate constant used in `cmp dil, 0x??`.
5. Concatenate the bytes in table order to obtain the exact expected message (the flag).

This is reliable because both the pointer table and comparison immediates are static.

---

## 9️⃣ Exploit Implementation

Script used:
- `scripts/solve.py`

What it does (high level):
- Runs `objdump -d` on the target binary.
- Parses:
  - the mangled `src::check_flag` symbol to recover the 31 function pointers
  - the `FnOnce::call_once` stubs to recover each required byte
- Reconstructs and prints the expected 31-byte string.

Run it from WSL in the challenge directory:

```bash
python3 scripts/solve.py ./dontpanic
```

Example observed output (from the actual solve run):

```text
stubs_found 20
slots_written 31
expected HTB{d0nt_p4n1c_c4tch_the_3rror}
hex 4854427b64306e745f70346e31635f63347463685f7468655f3372726f727d
```

---

## 🔟 Flag Retrieval

Recovered flag:

```text
HTB{d0nt_p4n1c_c4tch_the_3rror}
```

Runtime confirmation with the recovered input:

```bash
printf 'HTB{d0nt_p4n1c_c4tch_the_3rror}' | ./dontpanic
```

Observed output:

```text
🤖💬 < Have you got a message for me? > 🗨️ 🤖: 😌😌😌 All is well 😌😌😌
```

---

## 1️⃣1️⃣ Mitigation / Lessons Learned (Optional but Professional)

- Avoid storing secrets (flags/keys) as direct comparison constants in the client binary.
- If validation must exist locally, use a construction that does not allow straightforward recovery from static disassembly (e.g., server-side validation, or at minimum a one-way transformation with a secret not embedded in the binary).
- Strip symbols and remove debug info for release builds when appropriate.

---

## 1️⃣2️⃣ Conclusion

- The binary implements a 31-byte fixed-length check in `src::check_flag` using a function-pointer table.
- Each character is validated by a stub containing `cmp dil, 0x??`, making the expected input fully recoverable via static analysis.
- Reconstructing the table order plus constants yields the flag: `HTB{d0nt_p4n1c_c4tch_the_3rror}`.
