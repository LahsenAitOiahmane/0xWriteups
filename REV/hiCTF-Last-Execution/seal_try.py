import struct, hashlib
d = open('last-exec/last_execution.img', 'rb').read()
M64 = (1 << 64) - 1
def be64(b): return struct.unpack('>Q', b)[0]
def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64
K = 0x9E3779B97F4A7C15
TABLE_SEED = be64(d[24:32])

def rr_chain(off, size, sid):
    nrows = size // 64
    rrs = [(TABLE_SEED ^ ((sid * 0x1BF5) & M64)) % 64]
    for i in range(1, nrows):
        B = d[off + (i - 1) * 64]
        rrs.append((rrs[i-1] * 17 + B + i * 13) % 64)
    return rrs

def logical_rows(off, size, sid, count):
    rrs = rr_chain(off, size, sid)
    out = []
    for i in range(count):
        st = d[off + i*64: off + i*64 + 64]
        r = rrs[i]
        out.append((st[-r:] + st[:-r]) if r else st)
    return out

D = b''.join(logical_rows(0x2300, 0x40000, 11, 4))
perm = list(range(256))
for i in range(255, 0, -1):
    j = D[i] % (i + 1)
    perm[i], perm[j] = perm[j], perm[i]
SBOX = perm
INV = [0]*256
for i, v in enumerate(SBOX): INV[v] = i
P  = [0x00,0x05,0x0A,0x0F,0x04,0x09,0x0E,0x03,0x08,0x0D,0x02,0x07,0x0C,0x01,0x06,0x0B]
IP = [0x00,0x0D,0x0A,0x07,0x04,0x01,0x0E,0x0B,0x08,0x05,0x02,0x0F,0x0C,0x09,0x06,0x03]

def key_schedule(key):
    x = [be64(key[i*8:(i+1)*8]) for i in range(4)]
    RK = []
    for i in range(1, 18):
        for j in range(4):
            t = (x[j] + x[(j+1) % 4] + (K * (4*(i-1)+j+1))) & M64
            t ^= (x[(j+3) % 4] >> 7)
            x[j] = rol(t, 13)
        RK.append(struct.pack('>QQ', x[0] ^ x[2], x[1] ^ x[3]))
    return RK

def dec_block(st, RK):
    st = bytes(a ^ b for a, b in zip(st, RK[16]))
    for r in range(15, -1, -1):
        st = bytes(st[IP[t]] for t in range(16))
        st = bytes(INV[b] for b in st)
        st = bytes(a ^ b for a, b in zip(st, RK[r]))
    return st

def open_seal(off, size, key):
    raw = d[off:off+size]
    shifts = list(raw[:16]); ct = raw[16:]
    L = len(ct)//16
    RK = key_schedule(key)
    mat = [[0]*16 for _ in range(L)]
    for r in range(L):
        for c in range(16):
            mat[r][c] = ct[((r + shifts[c]) % L)*16 + c]
    out = b''
    for r in range(L):
        out += dec_block(bytes(mat[r]), RK)
    return out

def try_state(label, R):
    key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', v) for v in R) + b'LASTEXEC').digest()
    for name, off, size in (('WILL_SEAL', 0x462b2, 0x50), ('TEST_SEAL_1', 0x46302, 0x30),
                            ('TEST_SEAL_2', 0x46332, 0x30), ('TEST_SEAL_3', 0x46362, 0x30),
                            ('TEST_SEAL_4', 0x46392, 0x30)):
        pt = open_seal(off, size, key)
        pad = pt[-1]
        ok = pt.endswith(bytes([pad])*pad) and 1 <= pad <= 16
        txt = pt[:-pad] if ok else pt
        printable = sum(1 for b in txt if 32 <= b < 127 or b in (9, 10, 13)) / max(1, len(txt))
        if printable > 0.8:
            print(f'  [{label}] {name}: {txt!r}  (pad_ok={ok}, printable={printable:.2f})')
    return key

cands = {
 'after_MAIN':   [0x98861cb7731352ad, 0x4e2c337774a54429, 0x6c40eb1b8fb4ab18, 0x1664864e5836e8f1],
 'after_FOLD_A': [0x137f59634502d166, 0x45acdb733aa4a8b9, 0x5ba585b0b8b5dcce, 0x2b043994055c50b9],
 'after_FOLD_B': [0x422ed4a107d78bd2, 0x012eb84f00bf448f, 0x5f82c0716be579c6, 0x6f707a4168d7f818],
 'telemetry':    [0x30677DF2A112FFFB, 0xFF975FD2B1F14576, 0xABEC2195F731C083, 0x9C3FB793EED6DA86],
}
for label, R in cands.items():
    print('==', label)
    try_state(label, R)
