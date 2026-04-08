#!/usr/bin/env sage
proof.all(False)
n2=217
n3=134
m = 256
p = 2^n2 * 3^n3 - 1
F.<i> = GF((p,2), modulus=[1,0,1])
f = "GCDXJIT{"
E0 = EllipticCurve(F, [1,0])
E0.set_order((p+1)^2)
l = "Ch1_Tkh4rbi9a_M4tkh3rbi9a_Hen4y4"
from sage.groups.generic import has_order
def indep(pt1, pt2, o):
    return has_order(pt1.weil_pairing(pt2, o), o, '*')
def coprime(o):
    while True:
        set_random_seed()
        u,v = (randrange(o) for _ in 'uv')
        if gcd(u,v).is_one():
            return u,v
g = "}"
import random, string, base64, codecs
def make_alt_id(length=8):
    return (''.join(random.choice(string.digits if i % 2 == 0 else string.ascii_letters.lower()) for i in range(length)), "".join([chr(((ord(x)-65+13)%26+65) if 65<=ord(x)<=90 else ((ord(x)-97+13)%26+97) if 97<=ord(x)<=122 else ord(x)) for x in "".join([chr(__import__('operator').xor(int(x, 16), 42)) for x in ['0x70', '0x19', '0x44', '0x52', '0x1a', '0x50', '0x50', '0x50', '0x50', '0x75', '0x1d', '0x48', '0x4f', '0x1a', '0x45', '0x1e', '0x4d', '0x4d', '0x4d', '0x4d', '0x4d', '0x75', '0x72', '0x1b', '0x18', '0x1b', '0x18', '0x1b', '0x75', '0x1f', '0x45', '0x58', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x19', '0x75', '0x1d', '0x5a', '0x13', '0x46', '0x13', '0x5b', '0x19', '0x4b']])]))                                                                                                                                                                                                                                                                                                                                                                                            # Here is The Flag check it out!!!!
base64_id = make_alt_id(8)
R0,S0 = E0.torsion_basis(2^n2)
k1,k2 = coprime(2^n2)
G0 = k1 * R0 + k2 * S0
a, la = base64_id
while True:
    set_random_seed()
    H0 = sum(randrange(2^n2) * T for T in (R0,S0))
    if indep(H0, G0, 2^n2):
        break
G0.set_order(2^n2)
φ = E0.isogeny(G0)
E1 = φ.codomain()
fla=f+la
φH0 = φ(H0)
R1,S1 = E1.torsion_basis(2^n2)
while True:
    k3,k4 = coprime(2^n2)
    G1 = k3 * R1 + k4 * S1
    if indep(G1, φH0, 2^n2):
        break
G1.set_order(2^n2)
ψ = E1.isogeny(G1)
flla=f+l+a
E2 = ψ.codomain()
set_random_seed()
P1,Q1 = E1.torsion_basis(3^n3)
print(f'P1 = {P1.xy()}')
print(f'Q1 = {Q1.xy()}')
Xs, Ys = [], []
for _ in range(m):
    set_random_seed()
    Xs.append(E0.random_point())
    K = (choice((1,2)) + 2*randrange(2^(n2-1))) * G1
    Ys.append(φ(Xs[-1]) + K)
    print(f'Xs[{len(Xs)-1:3}] = {Xs[-1].xy()}')
    print(f'Ys[{len(Ys)-1:3}] = {Ys[-1].xy()}')
set_random_seed()
fllag=flla+g
µ = tuple(randrange(3^n3) for _ in '12')
X = E0.zero()
Y = µ[0] * P1 + µ[1] * Q1
for curX,curY in zip(Xs,Ys):
    set_random_seed()
    if randrange(2):
        X += curX
        Y += curY
print(f'X = {X.xy()}')
print(f'Y = {Y.xy()}')
from Crypto.Hash import SHA256
key = SHA256.new(str(µ).encode()).digest()
from Crypto.Cipher import AES
flag=fla+g
aes = AES.new(key, AES.MODE_CTR, nonce=b'')
print(f'flag = {aes.encrypt(fllag.encode()).hex()!r}')
#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
print(f'[*] flag = {flag}', 'Done. H4anta 1mpr1m1n4 L1k Ch4ll2ng2! 1wa 4rra Ma3end3k hhhh')