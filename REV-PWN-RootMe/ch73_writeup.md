# Basic ? crackme - Write-Up

## 1️⃣ Title & Metadata

**Purpose:** Context at a glance 

* **Challenge Name:** Basic ? crackme
* **Category:** Reverse Engineering
* **Difficulty:** Level 2 (implied by "Basic" and complexity)
* **Platform:** Root-Me
* **Author:** L27Sen
* **Date:** 2026-01-21

---

## 2️⃣ Challenge Description

**Purpose:** Set the problem statement exactly as given 

**Description:**

> Don’t be put off by this poor binary.
> Like any crackme, you need to find the key to get past the verification.
> But there may be traps!

**Provided Files:**

* `ch73.bin` (ELF Binary)

**Constraints:**

* Local execution permitted.
* Anti-debugging techniques hinted ("traps"). 



---

## 3️⃣ Goal / Objective

**Purpose:** Define what “success” means 

The objective is to analyze the binary's verification logic to extract the correct input (password) that triggers the success message "C'est correct !". The flag is the valid password itself. 

---

## 4️⃣ Initial Analysis & Reconnaissance

**Purpose:** Show your thinking like a professional 

I began by inspecting the file type and basic properties to understand the architecture and potential protections. 

### File Inspection

Using `file` and `checksec`:

```bash
$ file ch73.bin
ch73.bin: ELF 64-bit LSB shared object, x86-64, dynamically linked

$ checksec --file=ch73.bin
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

### Observations

* **Architecture:** 64-bit ELF (x86-64).
* 
**Protections:** Stack canaries are enabled, which might complicate buffer overflow attempts, but this is a crackme, so we focus on logic. 


* **Strings:** Running `strings` revealed interesting prompts:
* `Key: `
* `C'est correct !`
* `Essaie encore !`
* `/lib64/ld-linux-x86-64.so.2`



---

## 5️⃣ Attack Surface Identification

**Purpose:** Explain *where* the bug could be 

The primary attack surface is the user input mechanism in the `main` function.

* **User Input:** The program prints "Key: " and uses `scanf` with `%s` to read a string into a local buffer.
* **Verification Logic:** This input is passed to a function named `check`.
* 
**Data References:** The `check` function references a global byte array named `key`. 



---

## 6️⃣ Deep Technical Analysis

**Purpose:** Core of the write-up (most important section) 

I loaded the binary into IDA/Ghidra to analyze the control flow.

### The Naive Approach (The Trap)

Initially, I went straight to the verification function, `check` (at offset `0x120B`). It performs a simple XOR operation against a hardcoded key.

**Decompiled `check` logic (simplified):**

```c
// s is the user input
// key is a global array at 0x4048
for (int i = 0; i < strlen(s); i++) {
    // XOR input char with key byte (modulo 8)
    s[i] = s[i] ^ key[i % 8];
}

// Compare result with target hash
if ( *(long long*)s == 0x0A377AD570465FDF9 ) {
    puts("C'est correct !");
}

```

The static key at `0x4048` (Data Section) was:
`A8 96 4F 7F 3E 94 0A 95`

I attempted to solve it by XORing the target value (`0x0A377AD570465FDF9`) with this static key.

* **Attempt:** `0xF9 ^ 0xA8 = 0x51 ('Q')` ...
* **Result:** `Q{...` -> This looked incorrect and did not work.

### The Real Logic (Constructor Analysis)

Realizing the static key was a decoy, I looked for code that might modify the key before `main` runs. I checked the `.init_array`, which contains pointers to functions executed at startup.

I found a function `__do_global_ctors_aux` (offset `0x1189`) containing a `ptrace` call.

**Constructor Logic (Anti-Debug):** 

```c
// Syscall 101 is ptrace
// arg1 = 0 (PTRACE_TRACEME)
long result = ptrace(PTRACE_TRACEME, 0, 0, 0);

if (result == -1) {
    // Debugger detected!
    // Skip key modification
    return; 
} else {
    // No debugger attached (Normal execution)
    // Modify the key
    uint64_t *key_ptr = &key;
    uint64_t mask = 0x0119011901190119;
    
    // XOR the static key with the mask
    *key_ptr = *key_ptr ^ mask;
}

```

**The Trap Explained:**

* If you run this in a debugger (like GDB), `ptrace` fails (returns -1). The key **remains** `A8 96...` (the wrong key).
* If you run it normally, `ptrace` succeeds. The key is **modified** by the XOR mask `0x0119011901190119`.

This explains why my initial static calculation failed—I needed the **runtime key**. 

---

## 7️⃣ Vulnerability / Weakness Explanation

**Purpose:** State the bug explicitly 

The vulnerability is a **Hardcoded Cryptographic Secret** obfuscated by a simple **Anti-Debugging** check.

* **Type:** Client-side Trust / Reversible Logic.
* **Why it exists:** The author relied on `ptrace` to serve a different key to debuggers, assuming the attacker would blindly trust the dynamic analysis state.
* **Why it is exploitable:** The "secret" runtime key is deterministically calculated from values present in the binary (Static Key + Mask). We can statically replicate the logic without needing to bypass `ptrace` dynamically. 



---

## 8️⃣ Exploitation Strategy

**Purpose:** Explain how you turn the bug into a win 

My strategy is to emulate the "normal" execution path statically to recover the correct password:

1. **Extract the Static Key:** Read the 8 bytes from `.data` (`0x4048`).
2. **Extract the Mask:** Read the 8-byte mask from the `__do_global_ctors_aux` function.
3. **Calculate Runtime Key:** XOR the Static Key with the Mask to get the key used during normal execution.
4. **Decrypt the Flag:** The `check` function XORs the Input with the Key to match the Target. Therefore, `Flag = Target ^ RuntimeKey`. 



---

## 9️⃣ Exploit Implementation

**Purpose:** Show the practical execution 

I wrote a Python script to perform the XOR calculations and recover the flag.

```python
#!/usr/bin/env python3
import struct

# Step 1: Define the data extracted from the binary
# Target value hardcoded in 'check' (Little Endian: F9 FD 65 04 57 AD 77 A3)
target_val = 0x0A377AD570465FDF9
target_bytes = struct.pack('<Q', target_val)

# Static key found in .data section (A8 96 4F 7F 3E 94 0A 95)
static_key = [0xA8, 0x96, 0x4F, 0x7F, 0x3E, 0x94, 0x0A, 0x95]

# Mask applied in constructor if ptrace succeeds (19 01 19 01 19 01 19 01)
mask_val = 0x0119011901190119
mask_bytes = struct.pack('<Q', mask_val)

print("[*] Calculating Runtime Key...")

# Step 2: Calculate the Runtime Key (Static Key ^ Mask)
runtime_key = []
for k, m in zip(static_key, mask_bytes):
    runtime_key.append(k ^ m)

print(f"[*] Static Key:  {bytes(static_key).hex()}")
print(f"[*] Mask:        {mask_bytes.hex()}")
print(f"[*] Runtime Key: {bytes(runtime_key).hex()}")

# Step 3: Decrypt the Flag (Target ^ Runtime Key)
flag = []
for t, k in zip(target_bytes, runtime_key):
    flag.append(chr(t ^ k))

final_flag = ''.join(flag)
print(f"\n[+] Flag Recovered: {final_flag}")

```



---

## 🔟 Flag Retrieval

**Purpose:** Show success clearly 

Running the exploit script produced the correct password.

**Output:**

```
[*] Calculating Runtime Key...
[*] Static Key:  a8964f7f3e940a95
[*] Mask:        1901190119011901
[*] Runtime Key: b197567e27951394

[+] Flag Recovered: Hj3zp8d7

```

**Verification:**

```bash
$ ./ch73.bin
Key: Hj3zp8d7
C'est correct !

```

**Flag:**
`Hj3zp8d7`

---

## 1️⃣1️⃣ Mitigation / Lessons Learned

**Purpose:** Show security maturity 

* **Anti-Debugging is Delay, Not Security:** Checks like `ptrace` are trivial to bypass (e.g., `LD_PRELOAD`, binary patching, or static analysis). They should not be used to hide core cryptographic secrets.
* **Client-Side Validation:** In a real-world scenario, password verification should occur on the server (hashing) rather than comparing against a reversible value in the client binary.
* **Obfuscation:** While the constructor trick caused a momentary diversion, the logic remained clear. Stronger obfuscation (control flow flattening, virtualization) would be required to make this difficult. 



---

## 1️⃣2️⃣ Conclusion

**Purpose:** Wrap up cleanly 

This challenge demonstrated a classic anti-debugging technique where the environment (being debugged vs. running normally) alters the program's internal state. By analyzing the constructors (`.init_array`) and statically reconstructing the XOR logic, I successfully recovered the runtime key and the flag `Hj3zp8d7` without needing to dynamically bypass the `ptrace` check.