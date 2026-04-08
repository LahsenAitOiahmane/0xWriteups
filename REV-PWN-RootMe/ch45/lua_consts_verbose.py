import sys
import struct

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
    # code
    codesz = r.read_int(intsz)
    code = [r.read_int(4) for _ in range(codesz)]
    # constants
    consts = []
    constsz = r.read_int(intsz)
    for i in range(constsz):
        t = r.read_byte()
        if t == 0: # nil
            consts.append(('nil', None))
        elif t == 1: # boolean
            b = r.read_byte()
            consts.append(('bool', bool(b)))
        elif t == 3: # number
            num = r.read_number(numsz)
            consts.append(('number', num))
        elif t == 4: # string
            s = r.read_lstring(sizesz)
            consts.append(('string', s))
        else:
            consts.append(('unk', t))
    # prototypes
    protos = []
    protosz = r.read_int(intsz)
    for i in range(protosz):
        protos.append(parse_function(r, intsz, sizesz, numsz, depth+1))
    # skip lineinfo
    lineinfo_sz = r.read_int(intsz)
    r.read(4*lineinfo_sz)
    # locals
    locsz = r.read_int(intsz)
    for i in range(locsz):
        name = r.read_lstring(sizesz)
        startpc = r.read_int(intsz)
        endpc = r.read_int(intsz)
    # upvalues
    upsz = r.read_int(intsz)
    for i in range(upsz):
        name = r.read_lstring(sizesz)
    return {'src':src, 'linedefined':linedefined, 'consts':consts, 'protos':protos, 'code':code}

def dump(p, prefix=''):
    print(prefix + 'Function source: ' + (p['src'] or ''))
    print(prefix + 'Consts:')
    for i,(t,v) in enumerate(p['consts']):
        print(prefix + f'  [{i}] {t}: {v}')
    print(prefix + 'Protos: ' + str(len(p['protos'])))
    for i,q in enumerate(p['protos']):
        dump(q, prefix+'  ')
        # decode and print code for this proto if present
        code = q.get('code', [])
        if code:
            print(prefix + '  Code ops:')
            OPNAMES = ['MOVE','LOADK','LOADBOOL','LOADNIL','GETUPVAL','GETGLOBAL','GETTABLE','SETGLOBAL','SETUPVAL','SETTABLE','NEWTABLE','SELF','ADD','SUB','MUL','DIV','MOD','POW','UNM','NOT','LEN','CONCAT','JMP','EQ','LT','LE','TEST','TESTSET','CALL','TAILCALL','RETURN','FORLOOP','FORPREP','TFORLOOP','SETLIST','CLOSE','CLOSURE','VARARG']
            for idx,ins in enumerate(code):
                op = ins & 0x3f
                A = (ins>>6) & 0xff
                C = (ins>>14) & 0x1ff
                B = (ins>>23) & 0x1ff
                Bx = (ins>>14) & 0x3ffff
                sBx = Bx - 131071
                opname = OPNAMES[op] if op < len(OPNAMES) else f'OP{op}'
                print(prefix + f'    {idx:04}: {opname} A={A} B={B} C={C} Bx={Bx} sBx={sBx}')


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
        dump(prot)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: lua_consts_verbose.py <chunk>')
    else:
        main(sys.argv[1])
