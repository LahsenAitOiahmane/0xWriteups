# Breaking BITSCTF Cryptography: Lattices and Super DES

This write-up covers the analysis, theory, and exploitation of two cryptography challenges from BITSCTF: **Lattices Wreck Everything** and **Super DES**. We explore the deep mathematics involved, the methodology adopted to recover the flags, and the real-world implications of these vulnerabilities.

---

## Challenge 1: Lattices Wreck Everything
**Category:** Cryptography | **Points:** 50
**Premise:** Intercepted debug data from a faulty hardware security module (HSM) leaked partial parameters from a Falcon signature scheme connection.

### The Theory: NTRU Lattices and LWE
The Falcon signature scheme is built on an NTRU lattice foundation. The challenge setup involved reading a file, `challenge_data.json`, containing a set of parameters resembling a standard Learning With Errors (LWE) instance: $b = f \cdot A + e \pmod{q}$, where $q = 12289$, polynomial dimension $N = 512$, $b = 0$, $A$ represents a structural circulant matrix derived from public keys, and the private key components are the polynomials $f$ and $g$ (where $e = -g$).

Crucially, the "faulty HSM" leaked $436$ exact coefficients out of the $512$ coefficients belonging to the secret key polynomial $f$. This perfectly mapped out to a **Partial Key Exposure Attack**, leaving precisely $76$ coefficients unknown. 

Because we hold the identity $f \cdot A \equiv g \pmod{q}$, we can split $f$ into $f_{known} + f_{unknown}$.
By isolating the unknowns, we obtain:
$f_{unknown} \cdot A \equiv g - f_{known} \cdot A \pmod{q}$

If we denote the known constant vector $V = (-f_{known} \cdot A) \pmod{q}$, the relation becomes:
$f_{unknown} \cdot A - k \cdot q - V = g$

Since $f$ and $g$ are generated with very small coefficients (constrained norm bounds), the vector combination $(f_{unknown}, g)$ is extremely short. This mathematically reduces to finding the Shortest/Closest Vector inside a lattice!

### The Attack: Kannan's Embedding
To solve this **Closest Vector Problem (CVP)**, we adopted Kannan's Embedding Technique. We constructed a block matrix $M$ aligning the identity matrix for the variables $f_{unknown}$, the subset of matrix $A$ (as $A'$), modulo bounds $q$, and the constant translation vector $V$ bounded by a tuning weight $W$.

**The Pitfall of Scale:**
Initially, mapping all $N = 512$ equations against $76$ variables created a massive $589 \times 589$ lattice. While mathematically sound, algorithms like LLL and even BKZ completely choked due to precision decay or hung infinitely trying to map rational floating points back to shortest-vector integers across 589 dimensions. 

*How did we fix it?* We decimated the system. We realized the LWE system is vastly overdetermined! We only strictly needed a slight margin above $76$ equations to geometrically guarantee a unique shortest vector. 
By slicing the system cleanly down to only $m_{prime} = 85$ equations, our lattice shrank to a swift $162 \times 162$ dimension constraint. We pushed it through SageMath using `BKZ(block_size=15)` which perfectly reconstructed the missing piece in mere seconds.

With the master $f$ polynomial restored, we generated the true shared symmetric hashing key, XORed the ciphertext, and reclaimed the flag.

**FLAG:** `BITSCTF{h1nts_4r3_p0w3rfu1_4nd_f4lc0ns_4r3_f4st}`

### Real-World Relevance & Fix
Lattice-based encryption heavily underpins Post-Quantum Cryptography (PQC). However, side-channel attacks on poorly isolated HSM memories or faulty debug APIs frequently leak fractions of ring polynomials. If an attacker recovers even a minor portion of the polynomial, the remaining state space algebraically collapses.
**The Fix:** Hardware deployments of algorithms like Falcon/Kyber must operate in strictly constant time. Memory masking and aggressive blinders must be introduced to obfuscate polynomial evaluations, and most importantly—all raw parameter debugging features must be completely striped from production compilation.

---

## Challenge 2: Super DES
**Category:** Cryptography | **Points:** 50
**Premise:** "I heard triple des is deprecated, so I made my own."

### The Theory: Triple DES and Semi-Weak Keys
The challenge hosted a remote server letting us play with a custom block cipher protocol running three DES encryption stages sequentially depending on the mode the user selected. The server auto-generated a secure 8-byte session key `k1` but boldly allowed the user to dictate the specific values of `k2` and `k3`. The only explicit guardrail was a check blocking $k_2 == k_3$.
The "ultra secure" mode 1 operated via: $C = E_{k_1}(E_{k_2}(E_{k_3}(P)))$.

The core structural weakness here stems directly from the classic symmetric **DES Key Schedule**. DES possesses a set of mathematically paired **Semi-Weak Keys** (e.g. key pairs $K_{A}$ and $K_{B}$). These pairs share symmetrical subkeys such that doing two sequential encryptions with the paired keys universally cancels itself out back to the original plaintext: 
$E_{K_{A}}(E_{K_{B}}(P)) = P$

### The Attack: The Padding Oracle Paradox
We fed the server a notorious semi-weak pair: 
- `k2` = `011F011F010E010E`
- `k3` = `1F011F010E010E01`

Because of this property, the complex $E_{k_1}(E_{k_2}(E_{k_3}(P)))$ cipher visually decomposed! The $k_2$ and $k_3$ layers neutralized each other, turning the encryption oracle directly into $E_{k_1}(P)$ representing standard single DES encryption. We used this capability to encrypt the secret flag using the ultra secure mechanism.

Now equipped with the encrypted flag ciphertext, we manipulated the second mode `ultra_secure_v2`, programmed as: 
$C = D_{k_1}(E_{k_2}(E_{k_3}(P)))$

Applying the exact same semi-weak keys, it reverted this pipeline into a direct $D_{k_1}(P)$ decryption oracle. But we hit a small snag—any plaintext fed to the oracle was wrapped in `PKCS#7` padding before processing. 
If we feed our retrieved full-block flag ciphertext $C_{flag}$ into the server, the server first pads it (adding an extra 8 bytes of standard padding block) and then applies ECB mode block decryption. 
Because ECB isolates every 8-byte block independently, the execution flow looked like this:
$D_{k_1}(C_{flag}\ ||\ \text{padding block}) = D_{k_1}(C_{flag})\ ||\ D_{k_1}(\text{padding block})$

The server output exactly what we needed: the **original flag plaintext**, trailed closely behind by eight bytes of decrypted padding gibberish. We trimmed the final 8 junk bytes, decoded the hex, and stripped the original payload padding to reveal the prize.

**FLAG:** `BITSCTF{5up3r_d35_1z_n07_53cur3}`

### Real-World Relevance & Fix
The core cryptographic failure stems from a "roll your own crypto" mindset built on deprecated standards. DES key schedules are fully susceptible to semi-weak pairs yielding completely broken entropy. Coupled with ECB mode encryptions, which lack any semantic security (allowing padding extensions and block shuffling), the integrity of any pipeline is nonexistent.
**The Fix:** Modern secure transmission never uses raw Triple DES, much less allows untrusted clients to control internal symmetric stage keys. Production systems must implement highly secure authenticated encryption schemes (AEAD) like **AES-GCM** or **ChaCha20-Poly1305**, which eliminate both weak cryptographic schedules and malleable ECB padding exploits simultaneously.
