Challenge: ch32.bin (ELF x86_64, Go)

Goal: find the validation password.

Tools used
- WSL: `file`, `strings`, `readelf`, `objdump`, `xxd`, `echo`/`printf` to test program

Steps
1. Identify binary type and symbols:
   - `file ch32.bin` → Go 64-bit, statically linked with debug info.
   - `readelf -s ch32.bin` to find `main` and `main.main` addresses.
2. Disassemble `main.main` to locate the comparison/validation logic:
   - `objdump -d ch32.bin` and search for `<main.main>`.
   - In `main.main` the code calls `bytes.Compare` (compare user input vs constant).
   - The compare uses a pointer loaded from a static address (e.g. `mov 0x4312e(%rip),%rax` → resolves to `main.statictmp_2` at virtual addr `0x4d6040`).
3. Compute file offset and dump the static bytes:
   - Map vaddr→file offset using the `.rodata` segment base (example calculation shown below). Then dump with `xxd` or read via a small script.
   - Example: file offset for `0x4d6040` was `0x000d6040` in this file; `xxd -s 0xd6040 -l 14 ch32.bin` shows the 14 bytes.
4. Decode the 14-byte constant to ASCII and verify by running the program:
   - The bytes decode to: `ImLovingGoLand` (14 chars).
   - Verify: `printf 'ImLovingGoLand\n' | ./ch32.bin` → program prints the acceptance message.

Key commands (examples used)
- file ch32.bin
- readelf -s ch32.bin | egrep 'main\.|main$'
- objdump -d ch32.bin | sed -n '/<main.main>:/,/^$/p'
- xxd -s 0xd6040 -l 14 ch32.bin   # dump the static 14 bytes (offset computed from vaddr)
- printf 'ImLovingGoLand\n' | ./ch32.bin

Solution
- Validation password: ImLovingGoLand

Notes
- The important idea: locate the `bytes.Compare` usage in `main.main`, find which static memory contains the comparison target, dump it, and use it as the password.
- I verified the password by piping it to the binary which returned the validation message.
