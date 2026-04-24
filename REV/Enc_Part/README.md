# Writeup

## Overview
The executable uses a small MSVC CRT stub that quickly jumps into a set of runtime-decrypted validation blocks. Static inspection shows almost no readable strings and only thin wrapper functions. The real checks are AES-NI encrypted in the .data section and are decrypted and executed at runtime.

Key points:
- The program validates argv[1].
- Input length is enforced to 0x16 (22) characters.
- Several encrypted code blobs each verify a subset of characters.

## Recon
- File: 64-bit PE console executable.
- Imports: VirtualAlloc, VirtualProtect, VirtualFree, IsDebuggerPresent, CRT.
- No flag strings in plaintext.

The entry stub calls a CRT startup function, which then invokes the program logic in a separate function (main-like). That function calls a sequence of helpers that allocate memory, decrypt code, execute it, and free it.

## High-Level Flow
1. Initialize CRT.
2. Invoke main-like routine.
3. Allocate memory and decrypt validation blobs from .data.
4. Execute decrypted blocks to check argv[1] character-by-character.
5. Exit on failure.

## Encryption/Decryption Logic
The core decryptor uses AES-NI instructions. Each 16-byte block is processed with a key derived from the block index (0, 1, 2, ...), replicated across the key bytes.

Pseudocode for one block:
```c
key = repeat_byte(block_index);
round0 = aeskeygenassist(key, 0x00);
round1 = aeskeygenassist(key, 0x10);
state = load16(cipher);
state ^= round1;
state = aesdeclast(state, round0);
store16(plain);
```

This means static analysis is misleading: the real logic is hidden until these blocks are decrypted in memory.

## Blob Extraction
A small helper was used to dump and decrypt the blobs directly from the PE file.

- Source: [decrypt_blobs.c](decrypt_blobs.c)
- Output folder: [decrypted/](decrypted/)

Reproduce:
```bash
gcc -maes -O2 -o decrypt_blobs decrypt_blobs.c
./decrypt_blobs partialencryption.exe
```

Decrypted blobs:
- [decrypted/blob_4140.bin](decrypted/blob_4140.bin)
- [decrypted/blob_42e0.bin](decrypted/blob_42e0.bin)
- [decrypted/blob_44c0.bin](decrypted/blob_44c0.bin)
- [decrypted/blob_4730.bin](decrypted/blob_4730.bin)

## Constraint Recovery
Each decrypted blob consists of a repeated pattern:
- Load argv[1][index]
- Compare to a constant byte
- OR a failure flag if mismatch

By disassembling those blobs, the following characters are enforced:
- blob_4140: index 0..3 and 21 -> HTB{ and }
- blob_42e0: index 4..9 -> W3iRd_
- blob_44c0: index 10..17 -> RUnT1m3_
- blob_4730: index 18..20 -> DEC

## Flag
```
HTB{W3iRd_RUnT1m3_DEC}
```

## Notes
- The "partial encryption" theme is literal: only the validator is encrypted, not the loader.
- A normal static pass only reveals wrapper logic and CRT scaffolding; the real work happens in the decrypted buffers.
