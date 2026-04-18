# pwnjail Writeup (INSEC CTF - Misc 379)

## Challenge Information
- Challenge: pwnjail
- Category: Misc
- Points: 379
- Author: siegward
- Remote: challs.insec.club 40001
- Provided file: pwnjail.py
- Flag format: INSEC{...}

## TL;DR
The challenge is a stateful Caesar-shift jail with 12 rotating offsets. During oath verification, failed inputs are passed through a restricted eval path that leaks a success/failure oracle. That oracle is enough to recover all 12 initial offsets. Once offsets are known, we can inverse-encode the required oath lines, enter the assembler stage, and abuse GNU assembler directives (specifically .incbin) to read the flag file and recover the flag from the printed shellcode hex.

Flag:

INSEC{44nd_N0OW_mmY_w4tch_has_END3Ddd}

## Source Analysis
The core behavior from pwnjail.py is:

1. A global list OFFSETS of length 12 is randomly initialized with values in [0, 25].
2. Every user input is transformed character-by-character:
   - Only printable ASCII (32..126) is shifted.
   - Shift is modulo 95 printable chars.
   - For character index i, offset index is i % 12.
   - After each transformed character, OFFSETS[idx] increments modulo 26.
3. In stage 1, transformed input is compared against six hardcoded oath lines.
4. If oath check fails, transformed input is validated against regex [A-Za-z0-9+\-*/. ~]+ and evaluated with eval(..., {"__builtins__": {}}, {}).
   - If eval succeeds, server prints None.
   - Otherwise, it prints An error occured.
5. After all oath lines are accepted, stage 2 asks for asm_input and runs:
   - asm(transformed_shellcode, arch='amd64', os='linux')
   - On success it prints hex bytes.

Important point: OFFSETS is stateful and keeps evolving across all requests within one connection.

## Vulnerability Chain

### 1) Eval success/failure oracle leaks shift behavior
Even with empty builtins, eval gives a reliable one-bit oracle:
- None means transformed expression parsed and evaluated successfully.
- An error occured means parse/runtime failure.

By carefully crafting transformed expressions that are valid only for specific output characters (digits in this solve), we can infer offsets.

### 2) Recovering all 12 initial offsets
For each index j in 0..11:
- Send 26 probe inputs.
- Probe k has length j+1.
- Positions < j are chosen so their transformed outputs are always 1, neutralizing unknowns with already-recovered offsets and the +k drift.
- Position j uses input 0.
- Record whether response is None.

For a candidate offset c, predict whether shift(0, (c+k) % 26) is a digit for each k in 0..25. The correct c is the only one matching the observed 26-bit oracle pattern.

This yields all initial offsets deterministically.

### 3) Oath bypass via inverse transform
Once initial offsets are known, compute each outgoing character x such that transform(x) equals the target oath character, while updating local offset state exactly as the server does.

Send all six encoded oath lines in order to reach asm_input.

### 4) File exfiltration in assembler stage
The assembler accepts directives. Payload:

.incbin "flag.txt"

If file exists, assembler outputs raw bytes as machine code, and challenge prints them in hex. Decode bytes and regex-search INSEC\{...\}.

## Exploit Implementation Notes
The solve script is in solution.py and includes:
- Prompt-safe byte reading (important because prompts do not always end with newline).
- Correct prompt precedence (asm_input> before >) to avoid suffix confusion.
- Reconnect-per-path behavior so a failed .incbin compile (which exits server) does not kill the whole solve run.
- Automatic extraction of INSEC{...} from decoded hex blob.

## Reproduction
From the challenge directory:

```bash
python3 solution.py --mode remote --host challs.insec.club --port 40001
```

Example successful output:

```text
Recovered offsets: [12, 14, 11, 5, 18, 2, 9, 7, 21, 21, 13, 18]
Reached asm_input stage; trying flag.txt
INSEC{44nd_N0OW_mmY_w4tch_has_END3Ddd}
```

## Why This Works
The service tries to hide the oath behind randomized state, but then exposes enough structure through:
- Deterministic per-char offset updates.
- A stable eval oracle in the failure path.
- A powerful assembler interface that allows direct file inclusion.

Combining these three gives full break of the intended flow.

## Hardening Recommendations
1. Remove eval entirely from untrusted input paths.
2. Do not provide side-channel differences between parse success and failure.
3. Isolate assembly input from filesystem, or disable assembler directives like .incbin.
4. Reset state aggressively or make verification stateless and one-shot.
5. Return uniform error responses and timing for all invalid attempts.
