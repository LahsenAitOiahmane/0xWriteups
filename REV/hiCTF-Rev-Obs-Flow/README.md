# Rev Obs Flow — hiCTF (Reverse Engineering)

**Category:** REV
**Event:** hiCTF
**Flag:** `hiCTF{` + 40 chars + `}`  *(recovered at runtime by `emulate.py`)*

## Summary
`rev-obs-flow` is an x86-64 ELF that validates a `hiCTF{...}` flag through an
obfuscated **state-machine dispatcher**. The control flow is intentionally
tangled — each handler computes a "next-state" value that does not cleanly lead
to the decrypt path under normal analysis — and a final hash comparison guards
the printed flag.

## Solution — Unicorn emulation
Rather than untangling the dispatcher statically, we emulate the binary with
**Unicorn** (`emulate.py`):

- Map the `PT_LOAD` segments and a fake stack; stub the PLT imports
  (`printf`, `puts`, `strlen`, `fgets`, `fflush`, `strncmp`).
- Feed a fake input of the known shape `hiCTF{` + 40 chars + `}`.
- A code hook **forces the correct next-state chain** through the decrypt
  handler (`0x38a5f41c`), bypassing the anti-analysis transitions.
- The success `printf("%s", ...)` reveals the decrypted flag; the hook also
  dumps the output buffer and the dispatcher path for verification.

## Run
```bash
pip install unicorn pyelftools
python3 emulate.py
```
`disasm.txt` is the extracted disassembly used to locate the dispatcher and
handler addresses.

## Files
- `rev-obs-flow.bin` — extracted challenge binary
- `rev-obs-flow.zip` — original challenge archive
- `emulate.py` — Unicorn solve script
- `disasm.txt` — disassembly
