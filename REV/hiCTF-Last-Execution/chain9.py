import struct, hashlib
import scanC
from scanC import simulate, SEGS, RAW, be64

states = []
import exe9

# rerun capturing states at each halt by monkeypatching: simpler to re-implement inline
# We reuse simulate() but it returns final R only; instead run step-limited per segment.

M64 = (1 << 64) - 1
def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64
def ror(x, n):
    n %= 64
    return ((x >> n) | (x << (64 - n))) & M64
def sext32(v): return v - (1 << 32) if v & 0x80000000 else v
K = 0x9E3779B97F4A7C15; XX = 0xA5A5A5A5A5A5A5A5
EXEC_SEED = be64(RAW[16:24]); TABLE_SEED = be64(RAW[24:32])
DISP = scanC.DISP; PSH = scanC.PSH

def run_chain(max_steps=4000000, C=13):
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
    R = [0]*16; Z = [0]
    seg = SEGS[1]; pc = 0; rots = rots_of(seg)
    states = []
    for step in range(max_steps):
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
            if not writable(ad): raise Exception('WP %#x' % ad)
            IMG[ad:ad+8] = struct.pack('>Q', R[rd]); pc += 8
        elif mn == 'STB':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad): raise Exception('WP %#x' % ad)
            IMG[ad] = R[rd] & 0xff; pc += 8
        elif mn == 'LDRR':
            R[rd] = ldrr((R[ra] + sext32(imm)) & M64); pc += 8
        elif mn == 'CMP': Z[0] = 1 if R[ra] == R[rb] else 0; pc += 8
        elif mn == 'JMP': pc = (pc + 8 + sext32(imm)) & M64
        elif mn == 'JZ': pc = (pc + 8 + sext32(imm)) & M64 if Z[0] else pc + 8
        elif mn == 'JNZ': pc = (pc + 8 + sext32(imm)) & M64 if not Z[0] else pc + 8
        elif mn == 'HALT':
            nid = (imm ^ (R[1] & 0xffffffff)) & 0xffffffff
            states.append((seg['name'], nid, list(R), step))
            if nid == 0xffffffff or nid not in SEGS or SEGS[nid]['type'] != 1:
                return states, R
            seg = SEGS[nid]; rots = rots_of(seg); pc = 0
        elif mn == 'TRAP':
            states.append((seg['name'], 'TRAP', list(R), step)); return states, R
    return states, R

if __name__ == '__main__':
    states, R = run_chain()
    for name, nid, RR, step in states:
        print(f'{name:14s} next={nid} step={step} R1..R4=' + ' '.join(hex(x) for x in RR[1:5]))
