import struct, sys
sys.path.insert(0, '.')
from exe9 import *

def dis(segid, n=0x200):
    seg = BYID[segid]
    rots = rot_chain(seg)
    out = []
    for pc in range(0, seg["size"], 8):
        a = seg['off'] + pc
        raw = be64(bytes(IMG[a:a+8]))
        word = rol(raw, rots[pc >> 8])
        op = (word >> 56) & 0xff
        rd = (word >> 48) & 0xff
        ra = (word >> 40) & 0xff
        rb = (word >> 32) & 0xff
        imm = word & 0xffffffff
        idx = (op + ((pc >> 3) + seg['aux'])) & 0xff
        mn = DISP.get(idx)
        fb = ''
        if mn is None:
            mn = PSH[idx % 8]; rd &= 15; ra &= 15; rb &= 15; fb = '*'
        out.append((pc, mn + fb, rd, ra, rb, imm))
    return out

for segid in [int(x) for x in sys.argv[1:]] or [5]:
    print('=' * 10, BYID[segid]['name'], hex(BYID[segid]['off']), 'aux', hex(BYID[segid]['aux']))
    for pc, mn, rd, ra, rb, imm in dis(segid):
        print(f'{pc:03x}  {mn:5s} rd={rd:2d} ra={ra:2d} rb={rb:2d} imm={imm:#010x} ({imm if imm<2**31 else imm-2**32})')
