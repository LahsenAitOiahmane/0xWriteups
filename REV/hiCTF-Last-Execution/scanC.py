import struct, sys
M64 = (1 << 64) - 1
def be64(b): return struct.unpack('>Q', b)[0]
def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64
def ror(x, n):
    n %= 64
    return ((x >> n) | (x << (64 - n))) & M64
def sext32(v): return v - (1 << 32) if v & 0x80000000 else v

RAW = open('last-exec/last_execution.img', 'rb').read()
N = struct.unpack('>I', RAW[12:16])[0]
EXEC_SEED = be64(RAW[16:24]); TABLE_SEED = be64(RAW[24:32]); ENTRY = struct.unpack('>I', RAW[32:36])[0]
SEGS = {}
for i in range(N):
    b = 0x100 + 0x40 * i
    sid, typ = struct.unpack('>II', RAW[b:b+8])
    off = be64(RAW[b+8:b+16]); size = be64(RAW[b+16:b+24])
    fl, aux, crc = struct.unpack('>III', RAW[b+24:b+36])
    name = RAW[b+36:b+52].split(b'\x00')[0].decode()
    SEGS[sid] = dict(id=sid, type=typ, off=off, size=size, flags=fl, aux=aux, name=name)
K = 0x9E3779B97F4A7C15; XX = 0xA5A5A5A5A5A5A5A5
DISP = {0x03:'NOP',0x0A:'JNZ',0x0B:'LI',0x12:'JMP',0x16:'LUI',0x1D:'TRAP',0x21:'ORI',
        0x2D:'MOV',0x38:'ADD',0x42:'ADDI',0x4C:'SUB',0x55:'AND',0x5F:'OR',0x6A:'XOR',
        0x73:'XORI',0x7E:'MUL',0x87:'ROL',0x8F:'HALT',0x91:'ROR',0x9C:'SHL',0xA5:'SHR',
        0xB0:'NOT',0xBA:'LDW',0xC3:'LDB',0xC9:'ANDI',0xCE:'STW',0xD7:'STB',0xE2:'LDRR',
        0xEC:'CMP',0xF5:'JZ'}
PSH = ['NOP','XOR','ADD','MOV','ROL','SHR','AND','SUB']

def simulate(C, maxseg=3, verbose=False):
    IMG = bytearray(RAW)
    RRS = {}
    for sid, s in SEGS.items():
        if s['type'] == 3:
            nrows = s['size'] // 64
            rrs = [(TABLE_SEED ^ ((sid * 0x1BF5) & M64)) % 64]
            for i in range(1, nrows):
                B = IMG[s['off'] + (i - 1) * 64]
                rrs.append((rrs[i-1] * 17 + B + i * C) % 64)
            RRS[sid] = rrs
    def ldrr(phys):
        for s in SEGS.values():
            if s['type'] == 3 and s['off'] <= phys < s['off'] + s['size']:
                rb_ = s['off'] + ((phys - s['off']) & ~63)
                k = phys - rb_
                i = (rb_ - s['off']) // 64
                st = bytes(IMG[rb_:rb_+64]); r = RRS[s['id']][i]
                lg = (st[-r:] + st[:-r]) if r else st
                return be64(lg[k:k+8])
        raise Exception('LDRR %#x' % phys)
    def writable(ad):
        for s in SEGS.values():
            if s['off'] <= ad < s['off'] + s['size']:
                return bool(s['flags'] & 1)
        return False
    R = [0]*16; Z = [0]
    seg = SEGS[ENTRY]; pc = 0
    def rots_of(seg):
        m = rol((EXEC_SEED ^ ((seg['id'] * K) & M64)) & M64, 17)
        out = []
        for p in range((seg['size'] + 255)//256):
            if p > 0:
                base = seg['off'] + (p-1)*256
                w = be64(bytes(IMG[base:base+8]))
                m = rol(((m ^ w ^ XX) * K) & M64, 31)
            out.append(m % 64)
        return out
    rots = rots_of(seg)
    links = []
    for step in range(3000000):
        a = seg['off'] + pc
        word = rol(be64(bytes(IMG[a:a+8])), rots[pc >> 8])
        op = (word >> 56) & 0xff; rd = (word >> 48) & 0xff
        ra = (word >> 40) & 0xff; rb = (word >> 32) & 0xff; imm = word & 0xffffffff
        idx = (op + ((pc >> 3) + seg['aux'])) & 0xff
        mn = DISP.get(idx)
        if mn is None:
            mn = PSH[idx % 8]; rd &= 15; ra &= 15; rb &= 15
        if mn == 'NOP': pc += 8
        elif mn == 'LI': R[rd] = imm; pc += 8
        elif mn == 'LUI': R[rd] = (imm << 32) & M64; pc += 8
        elif mn == 'ORI': R[rd] |= imm; pc += 8
        elif mn == 'MOV': R[rd] = R[ra]; pc += 8
        elif mn == 'ADD': R[rd] = (R[ra] + R[rb]) & M64; pc += 8
        elif mn == 'SUB': R[rd] = (R[ra] - R[rb]) & M64; pc += 8
        elif mn == 'AND': R[rd] = R[ra] & R[rb]; pc += 8
        elif mn == 'OR':  R[rd] = R[ra] | R[rb]; pc += 8
        elif mn == 'XOR': R[rd] = R[ra] ^ R[rb]; pc += 8
        elif mn == 'MUL': R[rd] = (R[ra] * R[rb]) & M64; pc += 8
        elif mn == 'ADDI': R[rd] = (R[ra] + sext32(imm)) & M64; pc += 8
        elif mn == 'ANDI': R[rd] = R[ra] & imm; pc += 8
        elif mn == 'XORI': R[rd] = R[ra] ^ imm; pc += 8
        elif mn == 'ROL': R[rd] = rol(R[ra], imm % 64); pc += 8
        elif mn == 'ROR': R[rd] = ror(R[ra], imm % 64); pc += 8
        elif mn == 'SHL': R[rd] = (R[ra] << (imm % 64)) & M64; pc += 8
        elif mn == 'SHR': R[rd] = R[ra] >> (imm % 64); pc += 8
        elif mn == 'NOT': R[rd] = R[ra] ^ M64; pc += 8
        elif mn == 'LDW':
            ad = (R[ra] + sext32(imm)) & M64; R[rd] = be64(bytes(IMG[ad:ad+8])); pc += 8
        elif mn == 'LDB':
            ad = (R[ra] + sext32(imm)) & M64; R[rd] = IMG[ad]; pc += 8
        elif mn == 'STW':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad): raise Exception('WP')
            IMG[ad:ad+8] = struct.pack('>Q', R[rd]); pc += 8
        elif mn == 'STB':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad): raise Exception('WP')
            IMG[ad] = R[rd] & 0xff; pc += 8
        elif mn == 'LDRR':
            R[rd] = ldrr((R[ra] + sext32(imm)) & M64); pc += 8
        elif mn == 'CMP': Z[0] = 1 if R[ra] == R[rb] else 0; pc += 8
        elif mn == 'JMP': pc = (pc + 8 + sext32(imm)) & M64
        elif mn == 'JZ': pc = (pc + 8 + sext32(imm)) & M64 if Z[0] else pc + 8
        elif mn == 'JNZ': pc = (pc + 8 + sext32(imm)) & M64 if not Z[0] else pc + 8
        elif mn == 'HALT':
            nid = (imm ^ (R[1] & 0xffffffff)) & 0xffffffff
            links.append((seg['name'], nid))
            if nid == 0xffffffff or nid not in SEGS or SEGS[nid]['type'] != 1:
                return links, R
            if len(links) >= maxseg:
                return links, R
            seg = SEGS[nid]; rots = rots_of(seg); pc = 0
        elif mn == 'TRAP':
            links.append((seg['name'], 'TRAP')); return links, R
    return links, R

for C in range(0, 64):
    try:
        links, R = simulate(C, maxseg=3)
    except Exception as e:
        continue
    ids = [l[1] for l in links]
    if ids[:3] == [2, 3, 4]:
        print('C =', C, 'links', links, 'R1', hex(R[1]))
print('scan done')
