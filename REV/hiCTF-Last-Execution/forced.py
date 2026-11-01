import struct, hashlib
import vmcore
from vmcore import *
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

def test(R, label):
    key = hashlib.sha256(b'LASTEXEC' + b''.join(struct.pack('>Q', R[i]) for i in range(1, 5)) + b'LASTEXEC').digest()
    for ro in range(4):
        pt = open_seal(0x462b2, 0x50, key, ro)
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad):
            t = pt[:-pad]
            pr = sum(1 for b in t if 32 <= b < 127 or b in (9, 10, 13))/max(1, len(t))
            print('   pad-ok', label, ro, round(pr, 2), t[:70])
            if pr > 0.75:
                print('*** HIT', label, ro, t)
                return True
    return False

def run_forced(force_map, max_steps=3000000, n1=17, C=13):
    """force_map: dict (segname, observed_next) -> forced_next, applied once each"""
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
                k = phys - rb_; i = (rb_ - s['off']) // 64
                st = bytes(IMG[rb_:rb_+64]); r = RRS[s['id']][i]
                lg = (st[-r:] + st[:-r]) if r else st
                return be64(lg[k:k+8])
        raise Exception('LDRR')
    def writable(ad):
        for s in SEGS.values():
            if s['off'] <= ad < s['off'] + s['size']:
                return bool(s['flags'] & 1)
        return False
    def rots_of(seg):
        m = rol((EXEC_SEED ^ ((seg['id'] * K) & M64)) & M64, n1)
        out = []
        for p in range((seg['size'] + 255)//256):
            if p > 0:
                base = seg['off'] + (p-1)*256
                m = rol(((m ^ be64(RAW[base:base+8]) ^ XX) * K) & M64, 31)
            out.append(m % 64)
        return out
    R = [0]*16; Z = [0]
    seg = SEGS[ENTRY]; pc = 0; rots = rots_of(seg)
    links = []
    used = set()
    for _ in range(max_steps):
        if seg['id'] == 5 and pc == 0xb8:
            N = R[9]
            R6, R8, R5, R12 = R[6], R[8], R[5], R[12]
            s0 = (R6, R8, R5, R12)
            for _ in range(PERIOD):
                R6, R8, R5, R12 = step(R6, R8, R5, R12)
            d1 = (R8 - s0[1]) & M64
            M = N // PERIOD; rem = N % PERIOD
            base = (1 << 15) * PERIOD
            tot = (M * d1) % (1 << 64)
            tot = (tot + (base * R12DELTA % (1 << 64)) * (M * (M - 1) // 2)) % (1 << 64)
            R8 = (s0[1] + tot) & M64
            R12 = (s0[3] + M * R12DELTA) & M64
            R6, R5 = s0[0], s0[2]
            for _ in range(rem):
                R6, R8, R5, R12 = step(R6, R8, R5, R12)
            R[6], R[8], R[5], R[12], R[9] = R6, R8, R5, R12, 0
            pc = 0x188
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
            k = (seg['name'], nid)
            if k in force_map and k not in used:
                used.add(k); nid = force_map[k]
            links.append((seg['name'], nid))
            if nid == 0xffffffff:
                return links, list(R), 'END'
            if nid not in SEGS or SEGS[nid]['type'] != 1:
                return links, list(R), 'BADLINK'
            seg = SEGS[nid]; rots = rots_of(seg); pc = 0
        elif mn == 'TRAP':
            return links, list(R), 'TRAP'
    return links, list(R), 'MAXSTEPS'

if __name__ == '__main__':
    variants = {
        'natural': {},
        'skip_limit_once': {('EXEC_FOLD_B', 5): 4},
        'skip_limit_always': {('EXEC_FOLD_B', 5): 4, ('EXEC_FINAL', 5): 4},
    }
    for name, fm in variants.items():
        try:
            links, R, st = run_forced(fm)
        except Exception as e:
            print(name, 'FAULT', e); continue
        print(name, st, [l[1] for l in links], [hex(R[i]) for i in range(1, 5)], 'R15', hex(R[15]))
        test(R, name)
