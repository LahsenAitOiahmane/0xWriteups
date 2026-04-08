# BITSCTF: Ghost Compiler

**Category:** Reverse Engineering
**Objective:** Recover the hidden `BITSCTF{...}` flag from a custom C compiler binary.

## Challenge Overview

We are provided with a Linux ELF binary named `ghost_compiler` and a `README.md`. The README claims this is a "safe to use C compiler" that is as fast as `gcc` and instructs us to compile a standard "Hello World" program. Our goal is to extract the flag hidden within the compiler's execution flow.

## Initial Triage & Static Analysis

Opening the binary in IDA Pro reveals a standard ELF64 executable. The `main` function (located at `0x165F`) handles the file inputs and executes a sequence of three distinct subroutines before passing the file off to standard `gcc`.

Here is the breakdown of the execution flow:

### 1. The Signature Search (`sub_1349`)

The compiler first opens the input `.c` file and scans it for a specific 64-byte payload. The magic signature it looks for is hardcoded in the `.data` section at `byte_4020`:
`9A A5 22 E8 1E FA 91 90 1B ...`

If it finds this exact byte sequence, it flags the file for further processing.

### 2. The File Hashing (`sub_14B5`)

Once the payload is found, the binary reads the rest of the file (explicitly skipping the 64-byte payload) and computes an FNV-1a hash of the contents.

After hashing the file, it XORs the resulting hash with a hardcoded magic constant:
`Hash ^ 0xCAFEBABE00000000`

This operation generates a 64-bit dynamic key that will be used in the next step.

### 3. Decryption & Execution (`sub_1583`)

This function attempts to decrypt the 64-byte payload using the 64-bit key generated in the previous step. The decryption routine works bit-by-bit:

1. It XORs the ciphertext byte with the lowest byte of the 64-bit key.
2. It performs a bitwise right-rotate (`ROR 1`) on the 64-bit key to prepare it for the next byte.
3. It checks if the first 8 decrypted bytes match the string `BITSCTF{`.

If the check passes, the binary zeroes out the 64-byte payload, writes out a clean version of the `.c` file, and executes `system("gcc ...")` to compile it. This makes it act like a legitimate compiler while hiding its payload mechanism.

## The Vulnerability

At first glance, it looks like we need to find a valid `.c` file that hashes to the exact value required to generate the correct decryption key. However, the cryptography implementation has a fatal flaw.

Because of how the rolling key is generated via `ROR 1`, two consecutive ciphertext bytes share heavily overlapping key bits. Since standard ASCII characters (like our flag) are 7-bit (meaning the Most Significant Bit is always `0`), we don't actually need the 64-bit key. We can deduce the next plaintext byte entirely from the relationship between the previous plaintext byte and the current ciphertext bytes.

The relationship can be defined by this formula:


Where  is the Plaintext,  is the Ciphertext, and  is the index.

## The Exploit

Since we already know the payload starts with `BITSCTF{`, we have our starting plaintext byte:  (`0x42`). We also have the full ciphertext array hardcoded in `.data`.

We can write a quick Python script to cascade through the bytes and recover the entire flag:

```python
# The hardcoded ciphertext from .data:byte_4020
ct = [
    0x9A, 0xA5, 0x22, 0xE8, 0x1E, 0xFA, 0x91, 0x90, 
    0x1B, 0x8E, 0xB3, 0x5E, 0x5A, 0x2A, 0xF9, 0xF5, 
    0x10, 0xEE, 0x6C, 0x42, 0x72, 0x54, 0x76, 0xB1, 
    0xAD, 0x86, 0x2F, 0x5C, 0xAF, 0x3D, 0x53, 0x61, 
    0xFC, 0xA7, 0x16, 0xEE, 0xE8, 0x99, 0x04, 0x8B, 
    0xBF, 0xDE, 0x05, 0x8B, 0x2E, 0x53, 0x17, 0x8B, 
    0x45, 0xA2, 0x51, 0x28, 0x14, 0x8A, 0x45, 0xA2, 
    0x51, 0x28, 0x14, 0x0A, 0x85, 0xC2, 0x61, 0xB0
]

# We know the flag format starts with 'B'
flag = ['B']

for i in range(len(ct) - 1):
    # Apply the mathematical vulnerability
    p_next = (ct[i+1] & 0x7F) ^ ((ct[i] ^ ord(flag[i])) >> 1)
    
    # Break if we hit null-padding
    if p_next == 0:
        break
        
    flag.append(chr(p_next))

print("".join(flag))

```

Running this script yields the decrypted string.

**Flag:** `BITSCTF{n4n0m1t3s_4nd_s3lf_d3struct_0ur0b0r0s}`
