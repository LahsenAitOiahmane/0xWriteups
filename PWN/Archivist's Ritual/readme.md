# Archivist's Ritual (pwn) - Professional Writeup

## Challenge Information
- Category: pwn
- Binary: `archivist`
- Target: `nc 34.123.57.171 41035`
- Flag format: `NSC{...}`

---

## TL;DR
This challenge is solved by **file descriptor hijacking**, not memory corruption.

The program:
1. Opens `secret_scroll.txt` on startup (gets some fd like 3/4/5/6 depending on runtime layout).
2. Lets us close one of fds 0..3 using a controllable rune.
3. Lets us open arbitrary paths except those containing the string `secret`.
4. Reads "oracle input" from fd 0 and prints it back.

By closing stdin (fd 0) first, then opening `/proc/self/fd/<secret_fd>`, the newly opened file lands on fd 0. The oracle then reads the secret scroll and prints the flag.

---

## Recon

### 1) Binary properties
Using `file` and `pwn checksec`:
- 64-bit ELF (amd64)
- PIE enabled
- NX enabled
- Partial RELRO
- No canary
- Not stripped

None of these mitigations matter for this solve path because we do not need ROP or code execution.

### 2) Menu behavior (reversed from disassembly)
The menu has four options:

1. Invoke prophecy
2. Seal channel
3. Summon scroll
4. Exit

Important internals:
- `control_fd = dup(0)` at startup.
- `open("secret_scroll.txt", O_RDONLY)` at startup (program exits if this fails).
- `read_int()` and `read_str()` read from `control_fd` (not directly from stdin).

---

## Vulnerability Analysis

### Primitive A: Controlled close on low fds
Option 2 computes the fd to close as:

```c
close_target = (user_rune ^ 0x1337) & 0x3;
close(close_target);
```

So we can close exactly one of fds `0..3`.

Choose `rune = 3`:

```text
(3 ^ 0x1337) & 3 = 0
```

This closes `fd 0` (stdin).

### Primitive B: Arbitrary open with weak blacklist
Option 3 reads a path and blocks only if path contains the substring `"secret"`.
Otherwise it calls `open(path, O_RDONLY)` and prints the returned fd.

### Primitive C: Oracle reads from fd 0
Option 1 does:
- `read(0, buf, 0x100)`
- `printf("Vision: %s\n", buf)`

If fd 0 is redirected to the secret scroll, option 1 prints it.

---

## Exploit Strategy

### Phase 1: Close stdin
Use option 2 with rune 3 to close fd 0.

### Phase 2: Re-open fd 0 as a handle to secret file
Use option 3 with path:

```text
/proc/self/fd/N
```

where `N` is the inherited descriptor that already points to `secret_scroll.txt`.

Because fd 0 is the lowest available descriptor, successful `open()` returns fd 0.
The program even confirms this with:

```text
The scroll appears on channel 0
```

### Phase 3: Trigger oracle read
Use option 1. The oracle now reads from fd 0 (which is the secret scroll), and prints:

```text
Vision: NSC{...}
```

### Finding the correct `N`
On the provided remote instance, `N = 6` was reliable.
To keep exploit robust, brute-force a small range (`3..20`) and pick the first candidate that yields `channel 0` plus a flag regex match.

---

## Important Implementation Detail
`read_str()` uses raw `read()` and does not strip newlines.

If you send path with `sendline()`, the trailing `\n` can break `open("/proc/self/fd/N\n")`.
Use `send()` / `sendafter()` for the path payload.

---

## Exploit Script
A complete exploit script is included in this directory:

- `exploit.py`

### Usage

```bash
python3 exploit.py
```

Fast path with known descriptor:

```bash
python3 exploit.py --fd 6
```

---

## Remote Result
Recovered flag:

```text
NSC{7a5f7d481ce0402732a6966a53d19ff2}
```

Note: raw oracle output may include an extra trailing `}` due to `%s` printing beyond intended bytes when no hard null terminator is enforced. The exploit parses the exact `NSC{...}` token via regex.

---

## Root Cause Summary
The challenge combines three design flaws:
1. A controllable low-fd close primitive.
2. Path open primitive with blacklist-only filtering.
3. Sensitive read path bound to fd 0.

Together, they enable descriptor-level data exfiltration through `/proc/self/fd/*` without any memory corruption.

---

## Hardening Recommendations
1. Replace blacklist checks with allowlists (or disallow `/proc` traversal entirely).
2. Do not allow user-controlled `close()` on low process fds.
3. Keep secret file content in memory and close descriptor immediately after read.
4. Use `fgets`/bounded parsing and enforce null termination before `%s` prints.
5. Separate control channel and data channel robustly (avoid mutable global input fd assumptions).
