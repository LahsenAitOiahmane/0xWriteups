# LootStash — Reverse Engineering Write-Up

## 1. Title & Metadata

- **Challenge:** LootStash
- **Category:** Reverse Engineering
- **Difficulty:** Not provided
- **CTF / Platform:** Hack The Box (HTB)
- **Author:** L27Sen
- **Date:** 2026-01-04

---

## 2. Challenge Description

> A giant stash of powerful weapons and gear have been dropped into the arena - but there's one item you have in mind. Can you filter through the stack to get to the one thing you really need?

**Provided files:**

- `stash` (Linux executable)

**Constraints:** Not provided

---

## 3. Goal / Objective

- Recover the flag in the format `HTB{...}` from the provided artifact.

---

## 4. Initial Analysis & Reconnaissance

This challenge provides a single binary (`stash`). The first step is to determine the file type, architecture, and whether symbols are available.

### File identification

```bash
$ file stash
stash: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=817b1311ae44bdc6ed8a9b563159616844e59c64, for GNU/Linux 3.2.0, not stripped
```

Key observations:

- **ELF 64-bit**, **x86-64**.
- **PIE executable** (position-independent).
- **Dynamically linked**.
- **Not stripped** → symbol information is likely present, which usually makes static analysis easier.

### Integrity (hash)

```bash
$ sha256sum stash
2de89e7ea8347d190dbd9314f8a8f5680678abe03e520a530ecd87c29fb99c72  stash
```

### Quick triage with `strings`

A standard early step in RE is scanning for embedded strings that might contain prompts, file paths, or even the flag.

```bash
$ strings -a stash | egrep -i 'HTB\{|flag|loot|stash|weapon|gear|wrong|correct|enter|input|usage|congrats|success|fail'
HTB{n33dl3_1n_a_l00t_stack}
Diving into the stash - let's see what we can find.
gear
```

At this point, the flag appears directly in plaintext, but we still validate behavior by running the program.

### Symbol reconnaissance

Because the binary is not stripped, inspecting symbols helps confirm entrypoints and imported functions:

```bash
$ nm -D stash | head -n 80
                 U __libc_start_main@GLIBC_2.34
                 U printf@GLIBC_2.2.5
                 U putchar@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
                 U rand@GLIBC_2.2.5
                 U setvbuf@GLIBC_2.2.5
                 U sleep@GLIBC_2.2.5
                 U srand@GLIBC_2.2.5
0000000000007858 B stdout@GLIBC_2.2.5
                 U time@GLIBC_2.2.5
```

This indicates the program likely:

- Uses libc printing (`puts`, `printf`, `putchar`).
- Uses pseudo-randomness (`srand`, `rand`) seeded by time (`time`).
- Has timing/UX behavior (`sleep`).

And the non-dynamic symbols include `main`:

```bash
$ nm -n stash | head -n 120
00000000000021a9 T main
```

---

## 5. Attack Surface Identification

This challenge is a **local, offline** reverse engineering task; there is no network service.

Observed attack surface (from available outputs):

- **Program output**: the binary prints a “stash” animation and a resulting loot string.
- **Randomness source**: imports `time`, `srand`, `rand` suggest randomized selection of loot.

User input:

- **Not provided**. (The captured runs show the program produces output even when stdin is empty or when a line is provided, but no prompt for input is shown in the captured output.)

---

## 6. Deep Technical Analysis

The core technical finding, supported by captured tool output, is that the flag is embedded as a plaintext string inside the binary.

### Embedded flag string

The filtered `strings` output reveals the flag directly:

```text
HTB{n33dl3_1n_a_l00t_stack}
```

### Runtime behavior validation

To ensure the flag is not a decoy and to understand the program’s behavior, the binary was executed.

```bash
$ ./stash </dev/null
Diving into the stash - let's see what we can find.
.....
You got: 'Moonshard, Bead of Misery'. Now run, before anyone tries to steal it!
```

And with a sample line provided on stdin:

```bash
$ printf 'test\n' | ./stash
Diving into the stash - let's see what we can find.
...
You got: 'Dementia, Ravager of the Dead'. Now run, before anyone tries to steal it!
```

Based on the imports (`time`, `srand`, `rand`) and the observed varying output strings, the binary appears to randomly pick an item name and prints it after a short “dot” animation.

No additional flag-reveal path is required in the captured runs; the solution is achieved via static extraction.

---

## 7. Vulnerability / Weakness Explanation

**Type:** Information disclosure (flag left in plaintext inside the distributed binary)

**Why it exists:** The flag string is included as a direct, readable constant in the compiled artifact.

**Why it is exploitable:** Any analyst can extract the flag using basic static triage (e.g., `strings`) without needing to defeat anti-debugging, unpacking, or complex control-flow logic.

---

## 8. Exploitation Strategy

Strategy is minimal and fully deterministic:

1. Identify the artifact as a local Linux ELF.
2. Perform a strings sweep filtered for `HTB{`.
3. Confirm the discovered string matches the required flag format.
4. (Optional) Run the binary to understand what it does and ensure the flag is not obtained from runtime-only sources.

---

## 9. Exploit Implementation

No exploit code is required.

Reproduction command used:

```bash
strings -a stash | egrep -i 'HTB\{'
```

---

## 10. Flag Retrieval

From the verified `strings` output:

```text
HTB{n33dl3_1n_a_l00t_stack}
```

---

## 11. Mitigation / Lessons Learned (Optional but Professional)

- Avoid embedding secrets directly in client-side artifacts (binaries, scripts, front-end bundles).
- If a challenge requires runtime logic to reveal a secret, store the secret in a derived form (e.g., computed at runtime from transformations) rather than a plaintext constant.
- For real software: never ship credentials/keys/tokens in compiled releases; use secure secret distribution and server-side checks.

---

## 12. Conclusion

- The binary is a 64-bit Linux PIE executable and is not stripped.
- The flag is recoverable through basic static analysis because it is embedded as a plaintext string.
- This challenge primarily tests disciplined initial triage and methodology rather than complex decompilation.
