# timeless Write-up

## Challenge
- Name: timeless
- Category: Reverse Engineering
- Points: 484
- Local artifact: `timeless`
- Remote service: `challs.insec.club 40005`

## Summary
This binary has two parts:
1. A hidden transform check that compares 48 output bytes against a static target.
2. A runtime gate: all five internal registers must be zero before transform is allowed.

Trying option 1 directly with random registers triggers:

```text
Internal memory error.
```

So solving needs both a valid payload and register-state control.

## Reverse Engineering Highlights

### Menu / Control Flow
- `main` initializes 5 registers with `rand() % 255` after `srand(time(NULL))`.
- Option 2 rerolls exactly one selected register with the next `rand() % 255` value.
- Option 1 calls `transform(...)` and compares 48 bytes to `target`.

### Transform Gate
Inside `transform`, the first check is effectively:

```c
if (regs[0] || regs[1] || regs[2] || regs[3] || regs[4]) {
    puts("Internal memory error.");
    exit(1);
}
```

So all registers must be zero at call time.

### Payload Recovery
The data section contains:
- `target` (48 bytes)
- `keys` (256 x 48 bytes)

The transform can be modeled as a carry-constrained linear system over 256 input bits. Solving it yields a fixed 32-byte payload:

```text
d8a5d981d8aad98ed8ad20d98ad98ed8a720d8b3d990d985d992d8b3d990d985
```

## Exploitation Strategy (Remote)
1. Connect and parse `INITIAL REGS` (hex bytes).
2. Reconstruct `srand(time)` seed by brute-forcing timestamp window and matching first 5 outputs of `rand() % 255`.
3. Predict future RNG values exactly.
4. Send many option-2 commands to reroll non-zero registers until all five become zero.
5. Send option 1, then send the recovered binary payload.
6. Read flag.

## Solve Script
Included `solve.py` automates all the above.

Run:

```bash
python3 solve.py
```

Expected final flag:

```text
INSEC{bAD_S33d_1S_ThE_LEADEr_C4UsE_of_Br0keN_prNg}
```

## Flag
`INSEC{bAD_S33d_1S_ThE_LEADEr_C4UsE_of_Br0keN_prNg}`
