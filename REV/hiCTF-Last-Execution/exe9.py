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

IMG = bytearray(open('last-exec/last_execution.img', 'rb').read())
N = struct.unpack('>I', IMG[12:16])[0]
EXEC_SEED = be64(IMG[16:24])
TABLE_SEED = be64(IMG[24:32])
ENTRY = struct.unpack('>I', IMG[32:36])[0]

SEGS = {}
for i in range(N):
    b = 0x100 + 0x40 * i
    sid, typ = struct.unpack('>II', IMG[b:b+8])
    off = be64(IMG[b+8:b+16]); size = be64(IMG[b+16:b+24])
    fl, aux, crc = struct.unpack('>III', IMG[b+24:b+36])
    name = IMG[b+36:b+52].split(b'\x00')[0].decode()
    SEGS[sid] = dict(id=sid, type=typ, off=off, size=size, flags=fl, aux=aux, name=name)
BYID = SEGS
K = 0x9E3779B97F4A7C15
XX = 0xA5A5A5A5A5A5A5A5

def rot_chain(seg):
    m = rol((EXEC_SEED ^ ((seg['id'] * K) & M64)) & M64, 17)
    npages = (seg['size'] + 255) // 256
    rots = []
    for p in range(npages):
        if p > 0:
            base = seg['off'] + (p - 1) * 256
            w = be64(bytes(IMG[base:base+8]))
            m = rol(((m ^ w ^ XX) * K) & M64, 31)
        rots.append(m % 64)
    return rots

DISP = {0x03:'NOP',0x0A:'JNZ',0x0B:'LI',0x12:'JMP',0x16:'LUI',0x1D:'TRAP',0x21:'ORI',
        0x2D:'MOV',0x38:'ADD',0x42:'ADDI',0x4C:'SUB',0x55:'AND',0x5F:'OR',0x6A:'XOR',
        0x73:'XORI',0x7E:'MUL',0x87:'ROL',0x8F:'HALT',0x91:'ROR',0x9C:'SHL',0xA5:'SHR',
        0xB0:'NOT',0xBA:'LDW',0xC3:'LDB',0xC9:'ANDI',0xCE:'STW',0xD7:'STB',0xE2:'LDRR',
        0xEC:'CMP',0xF5:'JZ'}
PSH = ['NOP','XOR','ADD','MOV','ROL','SHR','AND','SUB']

def rr_chain(seg):
    nrows = seg['size'] // 64
    rrs = [(TABLE_SEED ^ ((seg['id'] * 0x1BF5) & M64)) % 64]
    for i in range(1, nrows):
        B = IMG[seg['off'] + (i - 1) * 64]
        rrs.append((rrs[i-1] * 17 + B + i * 13) % 64)
    return rrs

RRS = {sid: rr_chain(s) for sid, s in SEGS.items() if s['type'] == 3}

def ldrr_value(phys):
    for s in SEGS.values():
        if s['type'] == 3 and s['off'] <= phys < s['off'] + s['size']:
            row_base = s['off'] + ((phys - s['off']) & ~63)
            k = phys - row_base
            i = (row_base - s['off']) // 64
            stored = bytes(IMG[row_base:row_base+64])
            r = RRS[s['id']][i]
            logical = (stored[-r:] + stored[:-r]) if r else stored
            return be64(logical[k:k+8])
    raise Exception('LDRR outside TBL %#x' % phys)

def writable(ad):
    for s in SEGS.values():
        if s['off'] <= ad < s['off'] + s['size']:
            return bool(s['flags'] & 1)
    return False

R = [0] * 16
Z = [0]
pc = [0]
cur = [ENTRY]
trace = []
log = []

def run(maxsteps=500000, verbose=False):
    steps = 0
    seg = BYID[cur[0]]
    rots = rot_chain(seg)
    while steps < maxsteps:
        steps += 1
        a = seg['off'] + pc[0]
        raw = be64(bytes(IMG[a:a+8]))
        r = rots[pc[0] >> 8]
        word = rol(raw, r)
        op = (word >> 56) & 0xff
        rd = (word >> 48) & 0xff
        ra = (word >> 40) & 0xff
        rb = (word >> 32) & 0xff
        imm = word & 0xffffffff
        idx = (op + ((pc[0] >> 3) + seg['aux'])) & 0xff
        mn = DISP.get(idx)
        if mn is None:
            mn = PSH[idx % 8]
            rd &= 15; ra &= 15; rb &= 15
        if verbose:
            trace.append((seg['name'], pc[0], mn, rd, ra, rb, imm))
        if rd > 15 or ra > 15 or rb > 15:
            raise Exception('bad reg at %s pc=%#x %s %d %d %d' % (seg['name'], pc[0], mn, rd, ra, rb))
        if mn == 'NOP': pc[0] += 8
        elif mn == 'LI': R[rd] = imm; pc[0] += 8
        elif mn == 'LUI': R[rd] = (imm << 32) & M64; pc[0] += 8
        elif mn == 'ORI': R[rd] |= imm; pc[0] += 8
        elif mn == 'MOV': R[rd] = R[ra]; pc[0] += 8
        elif mn == 'ADD': R[rd] = (R[ra] + R[rb]) & M64; pc[0] += 8
        elif mn == 'SUB': R[rd] = (R[ra] - R[rb]) & M64; pc[0] += 8
        elif mn == 'AND': R[rd] = R[ra] & R[rb]; pc[0] += 8
        elif mn == 'OR':  R[rd] = R[ra] | R[rb]; pc[0] += 8
        elif mn == 'XOR': R[rd] = R[ra] ^ R[rb]; pc[0] += 8
        elif mn == 'MUL': R[rd] = (R[ra] * R[rb]) & M64; pc[0] += 8
        elif mn == 'ADDI': R[rd] = (R[ra] + sext32(imm)) & M64; pc[0] += 8
        elif mn == 'ANDI': R[rd] = R[ra] & imm; pc[0] += 8
        elif mn == 'XORI': R[rd] = R[ra] ^ imm; pc[0] += 8
        elif mn == 'ROL': R[rd] = rol(R[ra], imm % 64); pc[0] += 8
        elif mn == 'ROR': R[rd] = ror(R[ra], imm % 64); pc[0] += 8
        elif mn == 'SHL': R[rd] = (R[ra] << (imm % 64)) & M64; pc[0] += 8
        elif mn == 'SHR': R[rd] = R[ra] >> (imm % 64); pc[0] += 8
        elif mn == 'NOT': R[rd] = R[ra] ^ M64; pc[0] += 8
        elif mn == 'LDW':
            ad = (R[ra] + sext32(imm)) & M64
            R[rd] = be64(bytes(IMG[ad:ad+8])); pc[0] += 8
        elif mn == 'LDB':
            ad = (R[ra] + sext32(imm)) & M64
            R[rd] = IMG[ad]; pc[0] += 8
        elif mn == 'STW':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad):
                raise Exception('WRITEPROT addr=%#x in %s' % (ad, seg['name']))
            IMG[ad:ad+8] = struct.pack('>Q', R[rd]); pc[0] += 8
        elif mn == 'STB':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad):
                raise Exception('WRITEPROT addr=%#x in %s' % (ad, seg['name']))
            IMG[ad] = R[rd] & 0xff; pc[0] += 8
        elif mn == 'LDRR':
            R[rd] = ldrr_value((R[ra] + sext32(imm)) & M64); pc[0] += 8
        elif mn == 'CMP': Z[0] = 1 if R[ra] == R[rb] else 0; pc[0] += 8
        elif mn == 'JMP': pc[0] = (pc[0] + 8 + sext32(imm)) & M64
        elif mn == 'JZ':
            pc[0] = (pc[0] + 8 + sext32(imm)) & M64 if Z[0] else pc[0] + 8
        elif mn == 'JNZ':
            pc[0] = (pc[0] + 8 + sext32(imm)) & M64 if not Z[0] else pc[0] + 8
        elif mn == 'HALT':
            nid = (imm ^ (R[1] & 0xffffffff)) & 0xffffffff
            log.append('HALT %s pc=%#x imm=%#x R1lo=%#x next=%#x' % (seg['name'], pc[0], imm, R[1] & 0xffffffff, nid))
            if nid == 0xffffffff:
                return 'END', steps
            if nid not in BYID or BYID[nid]['type'] != 1:
                raise Exception('BADLINK %#x' % nid)
            cur[0] = nid
            seg = BYID[nid]
            rots = rot_chain(seg)
            pc[0] = 0
        elif mn == 'TRAP':
            raise Exception('TRAP %s pc=%#x imm=%#x' % (seg['name'], pc[0], imm))
        else:
            raise Exception('unimpl ' + mn)
    return 'MAXSTEPS', steps

try:
    res, steps = run(verbose=True)
    print('result', res, 'steps', steps)
except Exception as ex:
    print('FAULT:', ex)
for l in log:
    print(l)
print('R1..R4 =', [hex(x) for x in R[1:5]])
print('R15 =', hex(R[15]))
