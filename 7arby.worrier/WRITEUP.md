# 7arby Write-Up

**Category:** `Cryptography` **Difficulty:** `Medium` **Author:** `L27Sen` **Date:** `2026-02-08` 
**CTF:** `GCDSTE-ENSA-Marrakech`

## Description
>**Darija:**
> "Wahed menhom key, wahed menhom tkharbi9. Challenge howa tferra9 binathom. L'code source m3ammar pièges bach y-tester wach faham wella gha kat-copyé."\
>**English:** 
>"One of them is the key, one of them is trash. The challenge is to distinguish between them. The source code is full of traps to test if you understand the theory or if you're just copying."

## Definitions To look At: 
- Elliptic Curve Isogenies 
- Torsion Subgroups attacks 
- Learning With Errors (LWE) on Elliptic Curves 
- Weil Pairing 
- SageMath

## Hints

- **Hint 1: The "Observation" Hint (After 4 hours)"** Don't assume this is a standard copy-paste job. Look closely at the vuln.sage source code: are you sure which torsion group holds the secret, and which one holds the noise?" 

- **Hint 2: The "Mathematical" Hint (After 6 hours)"** The 'annihilation' trick only works if you multiply by the order of the group you want to destroy. Check your cofactor: are you trying to kill $3^{134}$ noise in a world where the noise lives in $2^{217}$?" 

- **Hint 3: The "Technical" Hint (After 8 hours)"** If your Weil Pairings are returning errors or weird values, check your MOD. The secret scalars $\mu$ were generated in the $3$-power torsion subgroup this time. Your solver needs to project everything to the 'clean' $3^{134}$ space first." 

## Things to Know Before Reading

Before diving into the code, you need to visualize the "playground" where this math happens.

- **The Playground (Finite Fields):** Instead of working with real numbers ($\mathbb{R}$), we work with integers modulo a giant prime $p$. Everything "wraps around" like a clock. We use $GF(p^2)$ to create a 2D-like field (complex numbers but for integers).

- **The Clock (Elliptic Curves):** An Elliptic Curve is a set of points $(x, y)$ that satisfy an equation like $y^2 = x^3 + x$. The "magic" is that you can "add" two points together to get a third point on the curve. This forms a Group.

- **Torsion Points (The Divisions):** If a point $P$ added to itself $n$ times gives the "zero" point, we say $P$ is an $n$-torsion point. Think of this like dividing a circle into $n$ equal slices.

- **Isogenies (The Map):** An isogeny $\phi$ is a special function that maps points from one curve to another while preserving the "addition" logic. In our case, it acts exactly like a Linear Transformation (a matrix).


## Real-World Implementation
This challenge is a simplified version of Post-Quantum Cryptography (PQC).

- **SIDH (Supersingular Isogeny Diffie-Hellman):** This was a real candidate for protecting the internet against future quantum computers. It relied on the difficulty of finding the map between two curves.

- **The "Castryck-Decru" Attack:** In 2022, researchers found that if you reveal certain "extra points" (like the torsion bases in your script), the secret map can be recovered in minutes on a laptop.

- **LWE (Learning With Errors):** The idea of adding noise to hide a secret is used in many other modern encryptions (like Kyber, which is used by Google and Cloudflare today). Your script is a "broken" version of this, where the noise doesn't cover all dimensions.

---
## TL;DR
The instance leaks many noisy samples `Ys[i] = phi(Xs[i]) + K_i`.
Unlike the original challenge, here **`K_i` is pure 2-power torsion** ($2^{n_2}$). The signal (the isogeny relationship) is preserved on the **3-power torsion** ($3^{n_3}$).

Multiplying everything by the cofactor `cof = 2^n2` kills the noise and turns the samples into clean 3-power torsion pairs:
`cof * Ys[i] = phi(cof * Xs[i])`.

On `E[3^n3]`, the isogeny is a `Z/(3^n3)`-linear map, so in torsion coordinates, it acts as a 2x2 matrix `M`. Weil pairings reduce torsion coordinates to two 1D discrete logs, letting us recover `M` from two independent samples. We then recover the secret scalars `(mu0, mu1)` (which are modulo `3^n3`) to decrypt the flag.

## Files
- `vuln.sage`: Challenge generator (Note the swapped logic!)
- `output.txt`: Public instance (contains `P1, Q1, Xs[i], Ys[i], X, Y, flag`)
- `solve.sage`: Final solver
---

## Attack Walkthrough

### 1) Parse the instance
Read `P1, Q1, Xs[i], Ys[i], X, Y, flag` from `output.txt`.

### 2) Reconstruct curves and points
Work over `F = GF(p^2)` with `p = 2^n2 * 3^n3 - 1` and `i^2 = -1`.
* `E0` is fixed: `y^2 = x^3 + x`.
* `E1` is recovered from the two public points `P1, Q1` by solving `y^2 = x^3 + a*x + b`.

### 3) Project to 3^n3 torsion (The "Swap" Step)
The crucial difference in this patch is the noise domain. The noise `K` lives in `E[2^n2]`.
To kill it, we set `cof = 2^n2`.

For every sample and the final target pair:
```python
Xs2[i] = cof * Xs[i]
Ys2[i] = cof * Ys[i]
X2     = cof * X
Y2     = cof * Y
```

Since `K_i` has order `2^n2`, `cof * K_i = 0`. Thus, `Ys2[i] = phi(Xs2[i])` becomes a clean relationship on the `3^n3` torsion.

### 4) Convert torsion points into Z/(3^n3) coordinates

Set `MOD = 3^n3`.
Choose a basis for each **3-power** torsion subgroup:

* On `E0`: `(R2, S2) = E0.torsion_basis(MOD)`
* On `E1`: `(P1, Q1)` is already a basis for `E1[MOD]` (given in `output.txt`).

Use Weil Pairing to map points to coordinates `(a,b)` via Discrete Logarithms (DLP). Since the order is smooth (), DLP is trivial.

### 5) Recover the isogeny’s linear map `M`

For each clean pair `(Xs2[i], Ys2[i])`, compute torsion coordinates:

* `CX[i] = (a_i, b_i)` on `E0`
* `CY[i] = (c_i, d_i)` on `E1`

Since `phi` is linear on the torsion, `(c_i, d_i)^T = M * (a_i, b_i)^T`.
Pick two samples `i, j` such that the input matrix is invertible mod `3^n3`:

```python
V = [[a_i, a_j],
     [b_i, b_j]]
W = [[c_i, c_j],
     [d_i, d_j]]
M = W * V^{-1}   (over Z/(3^n3))
```

*Note: Invertible here means `det(V) % 3 != 0`.*

### 6) Recover `(mu0, mu1)`

The challenge relation is: `Y = phi(X) + (mu0*P1 + mu1*Q1) + Noise`.
Multiply by `cof`:
`Y2 = phi(X2) + cof * (mu0*P1 + mu1*Q1)`

Steps:

1. Compute `phi(X2)` using our recovered matrix `M`.
2. Subtract: `T = Y2 - phi(X2)`.
3. Solve DLP for `T` in basis `(P1, Q1)` to get coords `(t0, t1)`.
4. We now have: `t0 = cof * mu0 (mod MOD)` and `t1 = cof * mu1 (mod MOD)`.
5. Multiply by `inverse(cof, MOD)` to isolate `mu0, mu1`.

### 7) Decrypt the flag

Derive key: `SHA256(str((mu0, mu1)))`.
Decrypt AES-CTR to get the flag.

---

## Solver Code: `solve.sage`

```python
#!/usr/bin/env sage
from sage.all import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# =============================================================================
# 1. CONFIGURATION & PARSING
# =============================================================================
n2=217
n3=134
m = 256
p = 2^n2 * 3^n3 - 1
F.<i> = GF((p,2), modulus=[1,0,1])

# --- OPTION B CONFIGURATION ---
MOD = 3^n3   # We are solving for the flag in the 3-torsion group
cof = 2^n2   # We multiply by 2^n2 to kill the noise

def parse_point(expr):
    return sage_eval(expr, locals={'i': i})

Xs_coords, Ys_coords = [], []
P1_coords = Q1_coords = X_coords = Y_coords = flag_hex = None

print('[*] Parsing output.txt...')
try:
    with open('output.txt','r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith('P1 = '): P1_coords = parse_point(line.split('=')[1])
            elif line.startswith('Q1 = '): Q1_coords = parse_point(line.split('=')[1])
            elif line.startswith('Xs['): Xs_coords.append(parse_point(line.split('=')[1]))
            elif line.startswith('Ys['): Ys_coords.append(parse_point(line.split('=')[1]))
            elif line.startswith('X = '): X_coords = parse_point(line.split('=')[1])
            elif line.startswith('Y = '): Y_coords = parse_point(line.split('=')[1])
            elif line.startswith('flag = '): flag_hex = line.split('=')[1].strip().strip("'")
except FileNotFoundError:
    print("[-] output.txt not found.")
    exit()

# =============================================================================
# 2. CURVE & POINT RECONSTRUCTION
# =============================================================================
print('[*] Reconstructing curves and points...')
E0 = EllipticCurve(F, [1,0])
Xs = [E0(c) for c in Xs_coords]
X_target = E0(X_coords)

# Recover E1 parameters
x1, y1 = P1_coords
x2, y2 = Q1_coords
num = (y1^2 - y2^2) - (x1^3 - x2^3)
a = num / (x1 - x2)
b = y1^2 - x1^3 - a*x1
E1 = EllipticCurve(F, [a,b])

P1 = E1(P1_coords)
Q1 = E1(Q1_coords)
Ys = [E1(c) for c in Ys_coords]
Y_target = E1(Y_coords)

P1.set_order(MOD)
Q1.set_order(MOD)

# =============================================================================
# 3. ATTACK: LINEAR MAP RECOVERY
# =============================================================================
print(f'[*] Projecting to 3^{n3} torsion (killing 2^{n2} noise)...')

# Project everything to the 3-torsion.
Xs2 = [cof * P for P in Xs]
Ys2 = [cof * P for P in Ys]
X2  = cof * X_target
Y2  = cof * Y_target

# Define Bases for DLP
R2, S2 = E0.torsion_basis(MOD)
w0 = R2.weil_pairing(S2, MOD)
w1 = P1.weil_pairing(Q1, MOD)

from sage.groups.generic import discrete_log

print('[*] Computing Discrete Logs...')

def dl_E0(P):
    a = discrete_log(P.weil_pairing(S2, MOD), w0, ord=MOD)
    b = discrete_log(R2.weil_pairing(P, MOD), w0, ord=MOD)
    return int(a), int(b)

def dl_E1(P):
    c = discrete_log(P.weil_pairing(Q1, MOD), w1, ord=MOD)
    d = discrete_log(P1.weil_pairing(P, MOD), w1, ord=MOD)
    return int(c), int(d)

# Collect samples
CX = [dl_E0(P) for P in Xs2]
CY = [dl_E1(P) for P in Ys2]

print('[*] Solving for Isogeny Matrix M...')
Z = Zmod(MOD)
Mmat = None

for i in range(m):
    a1, b1 = CX[i]
    for j in range(i+1, m):
        a2, b2 = CX[j]
        det = (a1*b2 - b1*a2) % MOD
        # [CRITICAL] Check invertibility mod 3, not mod 2!
        if det % 3 != 0:
            V = matrix(Z, [[a1, a2],[b1, b2]])
            W = matrix(Z, [[CY[i][0], CY[j][0]],[CY[i][1], CY[j][1]]])
            Mmat = W * V.inverse()
            break
    if Mmat is not None:
        break

if Mmat is None:
    print("[-] Failed to find independent vectors.")
    exit()

print('[+] Linear map recovered.')

# =============================================================================
# 4. RECOVER SECRET SCALARS & DECRYPT
# =============================================================================
A, B = dl_E0(X2)
C, D = Mmat * vector(Z, [A, B])
C, D = int(C.lift()), int(D.lift())

phiX2 = C * P1 + D * Q1
T = Y2 - phiX2

t0, t1 = dl_E1(T)

invcof = inverse_mod(Integer(cof), Integer(MOD))
mu0 = (Integer(t0) * invcof) % MOD
mu1 = (Integer(t1) * invcof) % MOD

print(f"[*] Recovered mu = ({mu0}, {mu1})")

key = SHA256.new(str((mu0,mu1)).encode()).digest()
aes = AES.new(key, AES.MODE_CTR, nonce=b'')

if flag_hex:
    try:
        pt = bytes.fromhex(flag_hex)
        flag = aes.decrypt(pt)
        print('\n' + '='*40)
        print(f'FLAG: {flag.decode()}')
        print('='*40 + '\n')
    except Exception as e:
        print(f'[-] Decryption failed: {e}')

```

## Output

```bash
[*] Parsing output.txt...
[*] Reconstructing curves and points...
[*] Projecting to 3^n3 torsion (killing 2^n2 noise)...
[*] Computing Discrete Logs (Input & Output)...
[*] Solving for Isogeny Matrix M...
[+] Linear map recovered.
[+] Map verification successful.
[*] Recovered mu = (6815709061258494223915883341479870028978468413645971154346620084, 385118252194151230875544303904654671805820717987007999898295746)

========================================
FLAG: GCDxJIT{Wa9il4_Ch1_H4j4_M4hiyach_Ch1_P4r4m3t3r_D4rh4_B1y4_Hhhhhhh_9a4x2h4k}
========================================
```
