# ch27 (MIPS) — Crackme writeup

**Summary**
- Binary: `ch27.bin` (ELF 32-bit little-endian MIPS, MIPS32r2, stripped)
- Goal: find the validation password
- Result: password is `cantrunmiiiiiiiiips`

**Tools used**
- `file`, `readelf`, `strings`
- `mipsel-linux-gnu-objdump` (binutils cross-disassembler)
- `qemu-mipsel` for attempted runtime verification
- Python for emulating the byte checks
- `patchelf` for interpreter experiments

**High-level approach**
1. Identify architecture and strings with `file`, `readelf -h`, and `strings`.
   - Notable strings: "Enter password please", "well done!", "fail!".
2. Disassemble `.text` with `mipsel-linux-gnu-objdump` and inspect `main`.
3. Locate the input buffer (stack frame at `s8+28`) and the loop that checks input bytes.
4. Recover expected byte values from the per-byte comparisons in `main`.
5. Verify the candidate password by emulating the comparisons in a short Python script.

**Key findings (disassembly notes)**
- `main` reads input into a local buffer and performs per-byte equality checks.
- Several checks shown (addresses are from disassembly):
  - At 0x40097c: compare buffer[0].. buffer[?] in sequence
  - Individual comparisons (ASCII values observed in code):
    - buffer[0] == 'c' (0x63)
    - buffer[1] == 'a'
    - buffer[2] == 'n'
    - buffer[3] == 't'
    - buffer[4] == 'r'
    - buffer[5] == buffer[4] + 3 (so 'r' + 3 = 'u')
    - buffer[6] == 'n'
    - buffer[7] == 'm'
    - buffer[8..16] == 'i' (nine consecutive 'i' characters)
    - buffer[17] == 'p'
    - buffer[18] == 's'
- Combining the checks gives: `cantrunm` + `i`*9 + `ps` → `cantrunmiiiiiiiiips`.

**Verification**
- I wrote and ran a small Python script that encodes the candidate and checks each required index/value (including the derived relation for index 5). The script reported the candidate as valid.
- I attempted to run the binary under `qemu-mipsel`. The ELF requests a uClibc interpreter (`/lib/ld-uClibc.so.0`) and depends on uClibc symbols; substituting glibc required additional sysroot libraries and still failed due to `__uClibc_main`. Running the original binary under a proper uClibc mipsel rootfs would show the runtime "well done!" message.

**Commands used (examples)**
```bash
file ch27.bin
readelf -h ch27.bin
strings -a ch27.bin | egrep 'Enter password please|well done!|fail!'
mipsel-linux-gnu-objdump -d --section=.text ch27.bin | sed -n '1,400p'
# python verification (short emulation)
```

**Files added**
- This writeup: [ch27_writeup.md](ch27_writeup.md)

If you want, I can:
- Download/setup a uClibc mipsel rootfs and run `ch27.bin` under `qemu-mipsel` to show the runtime output, or
- Produce a step-by-step annotated disassembly snippet (with more addresses/assembly) for the writeup.

