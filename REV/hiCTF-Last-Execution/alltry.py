import struct, hashlib, itertools
import seal_try

states = {
 'MAIN':     [0x98861cb7731352ad, 0x4e2c337774a54429, 0x6c40eb1b8fb4ab18, 0x1664864e5836e8f1],
 'FOLD_A':   [0x137f59634502d166, 0x45acdb733aa4a8b9, 0x5ba585b0b8b5dcce, 0x2b043994055c50b9],
 'FOLD_B':   [0x422ed4a107d78bd2, 0x012eb84f00bf448f, 0x5f82c0716be579c6, 0x6f707a4168d7f818],
 'LIMIT1':   [0x422ed4a11337c0da, 0x012eb84f00bf448f, 0xb87456786f641896, 0x6f707a4168d7f818],
 'FINAL1':   [0x42c1a4a25eed0001, 0x74d5a35de887c321, 0xa031605a73397392, 0xdf98a8bb28feecda],
 'LIMIT2':   [0x42c1a4a21337c0da, 0x74d5a35de887c321, 0xc8dabd185deb2f90, 0xdf98a8bb28feecda],
 'FINAL2':   [0x2ca93b45a112fffb, 0xd4e05a7d0fbc5a07, 0x8bf86d5bfe8632c6, 0x8f59486a748ada83],
 'TELEM':    [0x30677DF2A112FFFB, 0xFF975FD2B1F14576, 0xABEC2195F731C083, 0x9C3FB793EED6DA86],
}

def variants(R):
    be = b''.join(struct.pack('>Q', v) for v in R)
    le = b''.join(struct.pack('<Q', v) for v in R)
    yield 'std', hashlib.sha256(b'LASTEXEC' + be + b'LASTEXEC').digest()
    yield 'le', hashlib.sha256(b'LASTEXEC' + le + b'LASTEXEC').digest()
    yield 'nosuffix', hashlib.sha256(b'LASTEXEC' + be).digest()
    yield 'noprefix', hashlib.sha256(be + b'LASTEXEC').digest()
    yield 'bare', hashlib.sha256(be).digest()

SEALS = (('WILL_SEAL', 0x462b2, 0x50), ('TEST_SEAL_1', 0x46302, 0x30),
         ('TEST_SEAL_2', 0x46332, 0x30), ('TEST_SEAL_3', 0x46362, 0x30),
         ('TEST_SEAL_4', 0x46392, 0x30))

hits = 0
for name, R in states.items():
    for vname, key in variants(R):
        for sname, off, size in SEALS:
            pt = seal_try.open_seal(off, size, key)
            pad = pt[-1]
            ok = 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad)
            if not ok:
                continue
            txt = pt[:-pad]
            printable = sum(1 for b in txt if 32 <= b < 127 or b in (9,10,13)) / max(1, len(txt))
            if printable > 0.9:
                print(f'{name:8s} {vname:9s} {sname:12s} pad_ok={ok} -> {txt!r}')
                hits += 1
print('hits', hits)
