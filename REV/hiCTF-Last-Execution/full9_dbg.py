import struct, hashlib
from chain9 import run_chain, SEGS, RAW, be64, rol, ror, sext32, DISP, PSH, K, XX, EXEC_SEED, TABLE_SEED, M64
import chain9

PERIOD = 262144
R12DELTA = 131080

def step(R6, R8, R5, R12):
    R7 = ((R6 & 0x3ffff) * 0x19660d + 0x3c6ef35f) & 0x3ffff
    R10 = R6 ^ (R6 & 0x3ffff)
    R6 = R10 | R7
    R11 = rol(R6, 27) ^ R6
    R8 = (R8 + R11) & M64
    R8 = (R8 + (((R12 << 15) | R5) & M64)) & M64
    R11 = (R5 + 0x4001) & M64
    R5 = R11 & 0x7fff
    if (R11 >> 15) != 0:
        R12 = (R12 + 1) & M64
    return R6, R8, R5, R12

def run_full(max_steps=8000000):
    IMG = bytearray(RAW)
    RRS = {}
    for sid, s in SEGS.items():
        if s['type'] == 3:
            nrows = s['size'] // 64
            rrs = [(TABLE_SEED ^ ((sid * 0x1BF5) & M64)) % 64]
            for i in range(1, nrows):
                B = IMG[s['off'] + (i - 1) * 64]
                rrs.append((rrs[i-1] * 17 + B + i * 13) % 64)
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
    links = []
    for stepi in range(max_steps):
        if seg['id'] == 5 and pc == 0xb8:
            N = R[9]
            R6, R8, R5, R12 = R[6], R[8], R[5], R[12]
            # measure one period
            s0 = (R6, R8, R5, R12)
            for _ in range(PERIOD):
                R6, R8, R5, R12 = step(R6, R8, R5, R12)
            delta1 = (R8 - s0[1]) & M64
            assert (R6, R5) == (s0[0], s0[2]) and R12 == s0[3] + R12DELTA
            M = N // PERIOD
            rem = N % PERIOD
            # R12_0 = s0[3]
            base = (pow(2, 15, 1 << 64) * PERIOD) % (1 << 64)
            tot = 0
            tot = (tot + M * delta1) % (1 << 64)
            tot = (tot + (base * R12DELTA % (1 << 64)) * (M * (M - 1) // 2)) % (1 << 64)
            R8 = (s0[1] + tot) % (1 << 64)
            R12 = (s0[3] + M * R12DELTA) % (1 << 64)
            R6, R5 = s0[0], s0[2]
            for _ in range(rem):
                R6, R8, R5, R12 = step(R6, R8, R5, R12)
            R[6], R[8], R[5], R[12], R[9] = R6, R8, R5, R12, 0
            pc = 0x188
            links.append(('EXEC_LIMIT_loop', N))
            continue
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
            print('STW', hex(ad), hex(R[rd]), seg['name'], hex(pc)); IMG[ad:ad+8] = struct.pack('>Q', R[rd]); pc += 8
        elif mn == 'STB':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad): raise Exception('WP %#x' % ad)
            print('STB', hex(ad), hex(R[rd]&0xff), seg['name'], hex(pc)); IMG[ad] = R[rd] & 0xff; pc += 8
        elif mn == 'LDRR':
            R[rd] = ldrr((R[ra] + sext32(imm)) & M64); pc += 8
        elif mn == 'CMP': Z[0] = 1 if R[ra] == R[rb] else 0; pc += 8
        elif mn == 'JMP': pc = (pc + 8 + sext32(imm)) & M64
        elif mn == 'JZ': pc = (pc + 8 + sext32(imm)) & M64 if Z[0] else pc + 8
        elif mn == 'JNZ': pc = (pc + 8 + sext32(imm)) & M64 if not Z[0] else pc + 8
        elif mn == 'HALT':
            nid = (imm ^ (R[1] & 0xffffffff)) & 0xffffffff
            links.append((seg['name'], nid, list(R)))
            print('HALT', seg['name'], '-> next', nid, 'R1..R4', [hex(R[i]) for i in range(1, 5)])
            if nid == 0xffffffff:
                return links, R, 'END'
            if nid not in SEGS or SEGS[nid]['type'] != 1:
                return links, R, 'BADLINK'
            seg = SEGS[nid]; rots = rots_of(seg); pc = 0
        elif mn == 'TRAP':
            links.append((seg['name'], 'TRAP', list(R)))
            return links, R, 'TRAP'
    return links, R, 'MAXSTEPS'

if __name__ == '__main__':
    links, R, st = run_full()
    print('status', st)
    print('R15', hex(R[15]))
    print('final R1..R4', [hex(R[i]) for i in range(1, 5)])
    key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', R[i]) for i in range(1, 5)) + b'LASTEXEC').digest()
    print('key', key.hex())
    import seal_try
    for name, off, size in (('WILL_SEAL', 0x462b2, 0x50), ('TEST_SEAL_1', 0x46302, 0x30),
                            ('TEST_SEAL_2', 0x46332, 0x30), ('TEST_SEAL_3', 0x46362, 0x30),
                            ('TEST_SEAL_4', 0x46392, 0x30)):
        pt = seal_try.open_seal(off, size, key)
        pad = pt[-1]
        ok = pt.endswith(bytes([pad])*pad) and 1 <= pad <= 16
        print(name, '->', pt[:-pad] if ok else pt)
