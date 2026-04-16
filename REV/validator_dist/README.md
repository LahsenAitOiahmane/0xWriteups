# Validator
**Category:** Reverse Engineering  
**Difficulty:** Medium

## TL;DR
The binary is heavily control-flow-obfuscated but not stripped. The key checker function (**`zWqDapvkXfHB`**) validates one input byte at a time by index and returns `1` only for the correct byte. By breaking at **`main`** in GDB and brute-forcing `zWqDapvkXfHB(candidate, index)` for each index, we reconstruct the full flag deterministically.

## Tools Used
- `file`
- `checksec`
- `strings`
- `objdump`
- `radare2`
- `ltrace`
- `strace`
- `gdb`

---

## Description
`validator` is a 64-bit ELF that asks for a flag and prints either:
- `Sorry, that's not it.`
- `Congratulations! You found the correct flag.`

The objective is to recover the exact expected flag string.  
While the binary uses aggressive obfuscation (flattened dispatch and opaque predicates), its symbol table is intact, enabling targeted dynamic extraction.

---

## Static Analysis

### 1) Binary Recon
Using `file` and `checksec`:
- **ELF 64-bit LSB PIE**, dynamically linked, **not stripped**
- **NX enabled**
- **PIE enabled**
- **Partial RELRO**
- **No stack canary**

### 2) Interesting Strings and Imports
`strings` and symbol inspection showed:
- Runtime-resolved libc symbols via `dlopen`/`dlsym`
- A noisy decoy string: `ERROR: ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_...`
- Obfuscated symbol names, but meaningful anchor points still visible:
  - **`main`** at **`0x2b00`**
  - **`hIKCTDqsfNLU`** at **`0x1ac0`**
  - **`zWqDapvkXfHB`** at **`0x3440`**
  - **`wstLsACQERer`** at **`0x4740`**
  - **`___siphash`** at **`0x82a0`**

### 3) Decompilation/Disassembly Findings
Disassembly (`objdump`/`radare2`) showed:
- **Flattened control flow**: many indirect jumps through state variables.
- **Opaque arithmetic predicates** to hide real branches.
- `main` performs:
  1. Prompt/read input.
  2. Strip newline.
  3. Iterate over each character.
  4. Call **`zWqDapvkXfHB(input_char, index)`**.
  5. Fail if any call returns 0.

This made `zWqDapvkXfHB` the highest-value target.

---

## Dynamic Analysis

### 1) Runtime Behavior
Running the binary with sample input:
```bash
./validator
Enter the secret flag: test
Sorry, that's not it.
```

### 2) API Resolution Trace
`ltrace` confirmed dynamic symbol lookup:
- `dlopen(NULL, ...)`
- `dlsym(..., "printf")`
- `dlsym(..., "fgets")`
- `dlsym(..., "strcspn")`
- `dlsym(..., "stdin")`
- `dlsym(..., "strlen")`

### 3) Debugger-Driven Validation Oracle
At a breakpoint in **`main`**, calling:
```gdb
(int)zWqDapvkXfHB(candidate_byte, index)
```
returns:
- **`1`** for the correct byte at that index
- **`0`** otherwise

This provides a perfect oracle for byte-by-byte reconstruction.

---

## The "Aha!" Moment
The challenge is not a memory corruption bug; it is an obfuscated validation routine.  
The core logic flaw is architectural: although control flow is obfuscated, the checker is still callable as a normal function. Once we treat **`zWqDapvkXfHB`** as an oracle, obfuscation becomes irrelevant, and the flag is recoverable by exhaustive search over 256 byte values per position.

---

## Exploitation / Solution

### Step-by-step
1. Identify `main` and candidate checker function (`zWqDapvkXfHB`).
2. Break at `main` in GDB (ensures relocations are resolved).
3. For each index `i` in expected flag length:
   - Evaluate `zWqDapvkXfHB(c, i)` for `c in [0..255]`.
   - Keep the byte where return value is `1`.
4. Concatenate recovered bytes.
5. Submit recovered string to binary for confirmation.

### Final Solve Script
```python
#!/usr/bin/env python3
import pathlib
import re
import subprocess
import tempfile
import textwrap

BIN = "./validator"
FLAG_LEN = 68

def main() -> None:
    with tempfile.TemporaryDirectory() as td_raw:
        td = pathlib.Path(td_raw)
        input_file = td / "in.txt"
        gdb_file = td / "solve.gdb"

        input_file.write_text("A" * 80 + "\n", encoding="ascii")

        gdb_script = textwrap.dedent(f"""
            set pagination off
            set confirm off
            set disable-randomization on
            break main
            run < {input_file}
            python
            import gdb
            chars = []
            for idx in range({FLAG_LEN}):
                found = None
                for c in range(256):
                    r = int(gdb.parse_and_eval(f'(int)zWqDapvkXfHB({{c}},{{idx}})'))
                    if r == 1:
                        found = c
                        break
                if found is None:
                    raise RuntimeError(f"No valid byte found at index {{idx}}")
                chars.append(found)
            print("RESULT_STR=" + ''.join(chr(x) for x in chars))
            end
            quit
        """).strip() + "\n"

        gdb_file.write_text(gdb_script, encoding="ascii")

        output = subprocess.check_output(
            ["gdb", "-q", BIN, "-x", str(gdb_file)],
            stderr=subprocess.STDOUT,
            text=True
        )

        m = re.search(r"RESULT_STR=(.+)", output)
        if not m:
            raise RuntimeError("Failed to parse result from GDB output")

        flag = m.group(1).strip()
        print(flag)

if __name__ == "__main__":
    main()
```

---

## Flag
```text
VBD{I_kn0w_y0u_w0uld_us3_Opus_hehe_eafa09ad1898e0bcf9c0225076632225}
```
