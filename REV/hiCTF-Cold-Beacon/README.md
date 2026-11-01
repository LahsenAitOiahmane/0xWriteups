# Cold Beacon — hiCTF (Reverse Engineering)

**Category:** REV
**Event:** hiCTF
**Flag:** `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}`
**Unlock key:** `C0ldB34c0n::unl0ck::7a3f` (24 bytes)

## Summary
Cold Beacon is a **Nim-compiled ELF** that hides a config-derived flag behind a
key-unlock gate. The flag is not stored in plaintext — it is decrypted only
after the correct 24-byte unlock key survives a byte-arithmetic gate and seeds a
keystream.

## Solution
1. **Key gate** — 21 byte-arithmetic rules evaluated at `0x405fa0..`. Each rule
   transforms the candidate key; only the correct 24-byte key (`C0ldB34c0n::unl0ck::7a3f`)
   survives all checks.
2. **KDF** — `SHA256(key)` seeds an **MGF1**-style counter-mode expansion to
   **47 bytes** of keystream.
3. **Decrypt + verify** — that keystream decrypts an embedded config blob. The
   check `SHA256(config) == 0x405e20` confirms the recovered config is correct,
   which reveals the flag.

## Files
- `cold-beacon` — the challenge binary (Nim ELF)
- `cold-beacon.zip` — original challenge archive
