import hashlib, struct, importlib, sys
import exe9
from exe9 import *

# reset state and run EXEC_SELFTEST standalone
def selftest():
    for i in range(16):
        R[i] = 0
    Z[0] = 0
    seg = BYID[6]
    pc[0] = 0
    rots = rot_chain(seg)
    steps = 0
    while steps < 2000000:
        steps += 1
        a = seg['off'] + pc[0]
        raw = be64(bytes(IMG[a:a+8]))
        word = rol(raw, rots[pc[0] >> 8])
        op = (word >> 56) & 0xff
        rd = (word >> 48) & 0xff
        ra = (word >> 40) & 0xff
        rb = (word >> 32) & 0xff
        imm = word & 0xffffffff
        idx = (op + ((pc[0] >> 3) + seg['aux'])) & 0xff
        mn = DISP.get(idx)
        if mn is None:
            mn = PSH[idx % 8]; rd &= 15; ra &= 15; rb &= 15
        if mn == 'HALT':
            return steps
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
            if not writable(ad): raise Exception('WRITEPROT %#x' % ad)
            IMG[ad:ad+8] = struct.pack('>Q', R[rd]); pc[0] += 8
        elif mn == 'STB':
            ad = (R[ra] + sext32(imm)) & M64
            if not writable(ad): raise Exception('WRITEPROT %#x' % ad)
            IMG[ad] = R[rd] & 0xff; pc[0] += 8
        elif mn == 'LDRR':
            R[rd] = ldrr_value((R[ra] + sext32(imm)) & M64); pc[0] += 8
        elif mn == 'CMP': Z[0] = 1 if R[ra] == R[rb] else 0; pc[0] += 8
        elif mn == 'JMP': pc[0] = (pc[0] + 8 + sext32(imm)) & M64
        elif mn == 'JZ': pc[0] = (pc[0] + 8 + sext32(imm)) & M64 if Z[0] else pc[0] + 8
        elif mn == 'JNZ': pc[0] = (pc[0] + 8 + sext32(imm)) & M64 if not Z[0] else pc[0] + 8
        elif mn == 'TRAP': raise Exception('TRAP')
        else: raise Exception('unimpl ' + mn)
    return -1

st = selftest()
h = hashlib.sha256(b''.join(struct.pack('>Q', R[i]) for i in range(1, 5))).hexdigest()
print('steps', st)
print('R1..R4', [hex(R[i]) for i in range(1, 5)])
print('commitment got ', h)
print('commitment want', '0b6d8d4770eac443de6b9b73340a4a262117d9da42e6ced9411ebda286bbbcf2')
print('MATCH', h == '0b6d8d4770eac443de6b9b73340a4a262117d9da42e6ced9411ebda286bbbcf2')
