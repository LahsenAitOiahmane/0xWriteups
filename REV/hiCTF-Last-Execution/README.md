# Last Execution — hiCTF (Reverse Engineering)

**Category:** REV
**Event:** hiCTF
**Flag:** `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}`

## Summary
`last_execution.img` is an **EXE9CORE** container: a 24-segment table driving a
custom **8-byte-instruction virtual machine**. The flag is sealed inside a
**SEAL-256** region (`WILL_SEAL`) and only revealed once the VM is executed
correctly.

## The traps (the PRIMER lies)
The challenge ships a "PRIMER" that deliberately misleads. The real semantics are:

- Dispatch index = `op + (pc>>3) + AUX`  *(PRIMER claims `pc>>4`)*
- Page ROT chain uses **ROL 17**, not 19
- Table row rotation: `rr[i] = rr[i-1]*17 + B + i*13`  *(PRIMER claims `i*11`)*
- `EXEC_LIMIT` loop R12 counter **resets at R0 (=3)** → effectively mod 3,
  period **786432**

## Solution
1. `vmcore.py` implements the VM (segment loader, LDRR rotated-row reads, dispatch).
2. `seal_try.py` implements **SEAL-256** decryption.
3. `final_will.py` reproduces the full run and opens `WILL_SEAL` to print the flag.
   Supporting scripts (`scanC.py`, `exe9.py`, `chain9.py`, `full9.py`, `dis9.py`,
   `accept.py`, `audit.py`, `forced.py`, `limit_probe*.py`, `other_paths.py`,
   `scan_all.py`, `trace_limit.py`, `per.py`, `alltry.py`, `selftest9.py`) explore
   individual segments and the limit loop.

## Run
```bash
python3 final_will.py
```

## Files
- `last_execution.img` — the VM image
- `last-execution.zip` — original challenge archive
- `vmcore.py`, `seal_try.py`, `final_will.py`, … — full solve toolchain
