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

# [FIX] Explicitly define P1, Q1 as points on E1
P1 = E1(P1_coords)
Q1 = E1(Q1_coords)
Ys = [E1(c) for c in Ys_coords]
Y_target = E1(Y_coords)

# Set orders for cleaner arithmetic checks (optional but good practice)
P1.set_order(MOD)
Q1.set_order(MOD)

# =============================================================================
# 3. ATTACK: LINEAR MAP RECOVERY (No Subset Sum!)
# =============================================================================
print('[*] Projecting to 3^n3 torsion (killing 2^n2 noise)...')

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

print('[*] Computing Discrete Logs (Input & Output)...')

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

# We need two independent vectors in CX to form a basis
for i in range(m):
    a1, b1 = CX[i]
    for j in range(i+1, m):
        a2, b2 = CX[j]
        det = (a1*b2 - b1*a2) % MOD
        if det % 3 != 0:
            V = matrix(Z, [[a1, a2],[b1, b2]])
            W = matrix(Z, [[CY[i][0], CY[j][0]],[CY[i][1], CY[j][1]]])
            Mmat = W * V.inverse()
            break
    if Mmat is not None:
        break

if Mmat is None:
    print("[-] Failed to find independent vectors. Challenge generation might be degenerate.")
    exit()

print('[+] Linear map recovered.')

errors = 0
for k in range(min(10, m)):
    chk = Mmat * vector(Z, CX[k])
    if chk[0] != CY[k][0] or chk[1] != CY[k][1]:
        errors += 1
if errors == 0:
    print('[+] Map verification successful.')
else:
    print('[-] Map verification failed!')
    exit()

# =============================================================================
# 4. RECOVER SECRET SCALARS
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

# =============================================================================
# 5. DECRYPT
# =============================================================================
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
