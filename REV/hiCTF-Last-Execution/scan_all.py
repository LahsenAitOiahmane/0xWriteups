import struct, hashlib, sys
from vmcore import run, SEGS, RAW, be64, K
import seal_try
from seal_try import key_schedule, dec_block

def open_seal(off, size, key, rotoff):
    raw = RAW[off:off+size]
    ct = raw[16:]; L = len(ct)//16
    RK = key_schedule(key)
    out = b''
    for r in range(L):
        out += dec_block(bytes(ct[((r+rotoff) % L)*16 + c] for c in range(16)), RK)
    return out

def check(R, label, off=0x462b2, size=0x50):
    key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', R[i]) for i in range(1, 5)) + b'LASTEXEC').digest()
    for ro in range(4):
        pt = open_seal(off, size, key, ro)
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad):
            t = pt[:-pad]
            pr = sum(1 for b in t if 32 <= b < 127 or b in (9, 10, 13))/max(1, len(t))
            if pr > 0.75:
                print('  HIT', label, 'rot', ro, 'printable', round(pr, 2), t)
                return t
    return None

if __name__ == '__main__':
    print('scanning row-rotation coefficient C and initial rotate n1...')
    for n1 in (17, 19):
        for C in range(64):
            try:
                links, R, st = run(C, n1=n1, max_steps=3000000)
            except Exception as e:
                continue
            if st != 'END':
                continue
            ids = [l[1] for l in links]
            r = check(R, f'n1={n1} C={C} links={ids}')
            if r:
                print('*** FOUND n1', n1, 'C', C, 'links', ids)
                print('    R1..R4', [hex(R[i]) for i in range(1, 5)])
    print('scan done')
