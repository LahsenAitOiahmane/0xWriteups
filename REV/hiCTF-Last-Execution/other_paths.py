import struct, hashlib
import accept
import seal_try
from seal_try import key_schedule, dec_block

d = open('last-exec/last_execution.img', 'rb').read()
SEALS = (('WILL_SEAL', 0x462b2, 0x50), ('TEST_SEAL_1', 0x46302, 0x30),
         ('TEST_SEAL_2', 0x46332, 0x30), ('TEST_SEAL_3', 0x46362, 0x30),
         ('TEST_SEAL_4', 0x46392, 0x30))

def open_seal(off, size, key, rotoff):
    raw = d[off:off+size]
    ct = raw[16:]; L = len(ct)//16
    RK = key_schedule(key)
    out = b''
    for r in range(L):
        out += dec_block(bytes(ct[((r+rotoff) % L)*16 + c] for c in range(16)), RK)
    return out

def try_state(R, label):
    key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', R[i]) for i in range(1, 5)) + b'LASTEXEC').digest()
    for sname, off, size in SEALS:
        L = (size-16)//16
        for ro in range(L):
            pt = open_seal(off, size, key, ro)
            pad = pt[-1]
            if 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad):
                t = pt[:-pad]
                pr = sum(1 for b in t if 32 <= b < 127 or b in (9,10,13))/max(1, len(t))
                print(f'  {label} {sname} rot={ro} pad_ok=True printable={pr:.2f} -> {t!r}')

if __name__ == '__main__':
    for sid, nm in ((40, 'ACCEPT_LEGACY'), (41, 'SCRATCH'), (6, 'EXEC_SELFTEST')):
        try:
            links, R, st = accept.run_from(sid)
            print(nm, st, [l[1] for l in links])
            print('  R1..R4', [hex(R[i]) for i in range(1, 5)], 'R15', hex(R[15]))
            try_state(R, nm)
        except Exception as e:
            print(nm, 'FAULT', e)
