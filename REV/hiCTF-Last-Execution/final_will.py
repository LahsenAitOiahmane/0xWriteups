import struct, hashlib
from vmcore import run
import seal_try
from seal_try import key_schedule, dec_block

d = open('last-exec/last_execution.img', 'rb').read()

links, R, st = run(13)
print('chain :', ' -> '.join(str(l[1]) for l in links))
print('status:', st)
print('R1..R4:', [hex(R[i]) for i in range(1, 5)])
print('R15   :', hex(R[15]))

tele = [0x30677DF2A112FFFB, 0xFF975FD2B1F14576, 0xABEC2195F731C083, 0x9C3FB793EED6DA86]
print('telemetry diff vs real:')
for i in range(4):
    a, b = R[i+1], tele[i]
    print(f'  R{i+1}: real={a:016x} tele={b:016x} xor={(a^b):016x}')

key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', R[i]) for i in range(1, 5)) + b'LASTEXEC').digest()
print('key   :', key.hex())

def open_seal(off, size, key, rotoff):
    raw = d[off:off+size]
    ct = raw[16:]; L = len(ct)//16
    RK = key_schedule(key)
    out = b''
    for r in range(L):
        out += dec_block(bytes(ct[((r+rotoff) % L)*16 + c] for c in range(16)), RK)
    return out

raw = d[0x462b2:0x462b2+0x50]
shifts = raw[:16]; L = (len(raw)-16)//16
print('shifts:', list(shifts), 'L =', L, '-> rotoff', shifts[0] % L)
pt = open_seal(0x462b2, 0x50, key, shifts[0] % L)
pad = pt[-1]
ok = 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad)
print('pad   :', pad, 'valid', ok)
print('WILL  :', pt[:-pad].decode())
