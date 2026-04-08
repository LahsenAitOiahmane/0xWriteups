# El Diablo — BITSCTF Rev Writeup

## Challenge
> **El Diablo**  
> I bought this program but I lost the license file...

**Flag format:** `BITSCTF{...}`

---

## TL;DR
The binary implements a small VM. Your “license file” is not a serial number — it’s a **hex-encoded byte array** that the VM uses as a repeating XOR key to decrypt/print the flag.

Recovered flag:

```
BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

---

## 1) Recon
Start with basic identification:

```bash
file challenge
checksec --file=challenge
```

Observations:
- 64-bit Linux ELF, **PIE**, **stripped**
- NX, Canary, Full RELRO enabled (not important for reversing)

Strings already reveal a lot:

```bash
strings -a -n 4 challenge | grep -i -E 'license|flag|PRINT_FLAG_CHAR|GET_LICENSE_BYTE|MYVERYREALLDRM'
```

Interesting hits:
- `Usage: ./challenge <license file path>`
- `LICENSE-`
- `GET_LICENSE_BYTE[...]`
- `PRINT_FLAG_CHAR`
- `MYVERYREALLDRM`

This strongly suggests: “license” is parsed, then a VM executes “program bytes”, with debug toggles controlled by env vars.

---

## 2) License file format
Running with no args prints usage:

```bash
./challenge
```

The binary loads the given file and checks for a header prefix:
- **License must start with** `LICENSE-`
- After that, the program reads pairs of hex chars using `sscanf("%02x")`

So the license payload is:

```
LICENSE-<hex bytes...>\n
```

Example (10 bytes):

```
LICENSE-deadbeefcafebabe1122
```

---

## 3) VM behavior and the “PRINT_FLAG_CHAR” trick
The VM includes an opcode handler that prints a character from a register. That handler checks an environment variable named **`PRINT_FLAG_CHAR`**.

So for reversing, always run with:

```bash
PRINT_FLAG_CHAR=1 ./challenge <license>
```

This causes the VM to output the (decrypted) bytes it computes.

---

## 4) Key insight: output length and dependency pattern
Use a minimal license:

```bash
printf 'LICENSE-\n' > lic0.txt
PRINT_FLAG_CHAR=1 ./challenge lic0.txt
```

You’ll see 46 garbage bytes printed after:

```
The flag lies here somewhere...
```

Call that 46-byte output **ciphertext** `C`.

Next, test how changing one license byte affects output. Flipping license byte 0 changes output bytes at indices:

- 0, 10, 20, 30, 40

Flipping license byte 1 changes:

- 1, 11, 21, 31, 41

…and so on. This is exactly what you’d expect if:

- The license is a **10-byte repeating key**, and
- The printed bytes are **XORed** with that repeating key.

So we can model:

$$P[i] = C[i] \oplus K[i \bmod 10]$$

Where:
- `P` is plaintext (the flag)
- `C` is the bytes printed when license is all zeros
- `K` is the repeating 10-byte key coming from the license payload

---

## 5) Recovering the flag
Because the flag starts with a known prefix `BITSCTF{`, we can derive most of the key immediately:

For `i = 0..7`:

$$K[i] = C[i] \oplus \text{ord}(\text{prefix}[i])$$

With the key schedule confirmed (period = 10), only 2 key bytes (K[8], K[9]) remain unknown. Brute force is tiny (65536) and can be filtered by ASCII/format constraints.

Resulting plaintext (unique, clean-looking candidate):

```
BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

---

## 6) Final license and verification
The recovered 10-byte repeating XOR key (license payload) is:

```
99f5671124d520d5f63c
```

So the working license file is:

```text
LICENSE-99f5671124d520d5f63c
```

In this repo, it’s already saved as:
- [license_good.txt](license_good.txt)

Verify:

```bash
PRINT_FLAG_CHAR=1 ./challenge license_good.txt
```

Expected output ends with:

```
BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

---

## Flag
`BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}`
