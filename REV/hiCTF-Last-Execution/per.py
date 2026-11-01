M64 = (1 << 64) - 1

def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64

def step(R6, R8, R5, R12):
    R7 = ((R6 & 0x3ffff) * 0x19660d + 0x3c6ef35f) & 0x3ffff
    R11 = R6 & 0x3ffff
    R10 = R6 ^ R11
    R6 = R10 | R7
    R11 = rol(R6, 27) ^ R6
    R8 = (R8 + R11) & M64
    R10 = ((R12 << 15) | R5) & M64
    R8 = (R8 + R10) & M64
    R11 = (R5 + 0x4001) & M64
    R5 = R11 & 0x7fff
    R10 = R11 >> 15
    if R10 != 0:
        R12 = (R12 + 1) & M64
        if R12 == 0:
            R12 = 0
    return R6, R8, R5, R12

R6 = 0x123456789abcdef & 0x3ffff
R8 = 0
R5 = 0x1a5c
R12 = 0
init = (R6, R5)
for i in range(1, 300000):
    R6, R8, R5, R12 = step(R6, R8, R5, R12)
    if (R6, R5) == init:
        print('period found', i, 'R12 delta', R12)
        break
else:
    print('no period in 300k')
