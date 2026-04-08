import sys, struct

class Reader:
    def __init__(self, f, little=True):
        self.f = f
        self.le = little

    def read(self, n):
        b = self.f.read(n)
        if len(b) != n:
            raise EOFError
        return b

    def read_byte(self):
        return struct.unpack('<B' if self.le else '>B', self.read(1))[0]

    def read_int(self, size):
        fmt = {1:'B',2:'H',4:'I',8:'Q'}[size]
        return struct.unpack(('<' if self.le else '>')+fmt, self.read(size))[0]

    def read_number(self, size):
        fmt = 'd' if size==8 else 'f'
        return struct.unpack(('<' if self.le else '>')+fmt, self.read(size))[0]

    def read_size_t(self, size):
        return self.read_int(size)

    def read_lstring(self, sizesz):
        sz = self.read_size_t(sizesz)
        if sz == 0:
            return None
        data = self.read(sz)
        return data[:-1].decode('latin1')

def parse_function(r, intsz, sizesz, numsz, depth=0):
    src = r.read_lstring(sizesz)
    linedefined = r.read_int(intsz)
    lastlinedefined = r.read_int(intsz)
    nups = r.read_byte()
    numparams = r.read_byte()
    is_vararg = r.read_byte()
    maxstacksize = r.read_byte()
    codesz = r.read_int(intsz)
    r.read(4*codesz)
    consts = []
    constsz = r.read_int(intsz)
    for i in range(constsz):
        t = r.read_byte()
        if t == 0:
            consts.append(None)
        elif t == 1:
            b = r.read_byte()
            consts.append(bool(b))
        elif t == 3:
            num = r.read_number(numsz)
            consts.append(num)
        elif t == 4:
            s = r.read_lstring(sizesz)
            consts.append(s)
        else:
            consts.append(('unk', t))
    protosz = r.read_int(intsz)
    protos = []
    for i in range(protosz):
        protos.append(parse_function(r, intsz, sizesz, numsz, depth+1))
    lineinfo_sz = r.read_int(intsz)
    r.read(intsz*lineinfo_sz)
    locsz = r.read_int(intsz)
    for i in range(locsz):
        name = r.read_lstring(sizesz)
        startpc = r.read_int(intsz)
        endpc = r.read_int(intsz)
    upsz = r.read_int(intsz)
    for i in range(upsz):
        name = r.read_lstring(sizesz)
    return {'src':src, 'consts':consts, 'protos':protos}


def main(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic != b'\x1bLua':
            print('Not a Lua chunk')
            return
        version = f.read(1)
        formatb = f.read(1)
        endian = ord(f.read(1))
        little = endian == 1
        intsz = ord(f.read(1))
        sizesz = ord(f.read(1))
        insn_sz = ord(f.read(1))
        numsz = ord(f.read(1))
        numformat = ord(f.read(1))
        r = Reader(f, little)
        prot = parse_function(r, intsz, sizesz, numsz)
        child = prot['protos'][0]
        consts = child['consts']
        # find sequences between 'start_array' and 'end_array'
        arrays = []
        cur = None
        for c in consts:
            if isinstance(c, str) and c == 'start_array':
                cur = []
            elif isinstance(c, str) and c == 'end_array':
                if cur is not None:
                    arrays.append(cur)
                cur = None
            else:
                if cur is not None and isinstance(c, (int, float)):
                    cur.append(int(c) & 0xff)
        # print arrays
        for i,a in enumerate(arrays):
            print('ARRAY', i, len(a), a)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage')
    else:
        main(sys.argv[1])
