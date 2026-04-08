import sys, struct

OPNAMES = ['MOVE','LOADK','LOADBOOL','LOADNIL','GETUPVAL','GETGLOBAL','GETTABLE','SETGLOBAL','SETUPVAL','SETTABLE','NEWTABLE','SELF','ADD','SUB','MUL','DIV','MOD','POW','UNM','NOT','LEN','CONCAT','JMP','EQ','LT','LE','TEST','TESTSET','CALL','TAILCALL','RETURN','FORLOOP','FORPREP','TFORLOOP','SETLIST','CLOSE','CLOSURE','VARARG']

class Reader:
    def __init__(self,f,little=True):
        self.f=f; self.le=little
    def read(self,n):
        b=self.f.read(n)
        if len(b)!=n: raise EOFError
        return b
    def read_byte(self): return struct.unpack('<B' if self.le else '>B', self.read(1))[0]
    def read_int(self,size):
        fmt = {1:'B',2:'H',4:'I',8:'Q'}[size]
        return struct.unpack(('<' if self.le else '>')+fmt, self.read(size))[0]
    def read_number(self,size):
        return struct.unpack(('<'+'d' if self.le else '>'+'d')[0], self.read(size))
    def read_lstring(self,sizesz):
        sz = self.read_int(sizesz)
        if sz==0: return None
        data = self.read(sz)
        return data[:-1].decode('latin1')

def parse_function(r,intsz,sizesz,numsz):
    src = r.read_lstring(sizesz)
    r.read(intsz*2)
    r.read(4)
    r.read(1); r.read(1); r.read(1); r.read(1)
    codesz = r.read_int(intsz)
    code = [r.read_int(4) for _ in range(codesz)]
    constsz = r.read_int(intsz)
    for i in range(constsz):
        t = r.read_byte()
        if t==0: pass
        elif t==1: r.read(1)
        elif t==3: r.read(numsz)
        elif t==4: _ = r.read_lstring(sizesz)
    protosz = r.read_int(intsz)
    protos = []
    for _ in range(protosz): protos.append(parse_function(r,intsz,sizesz,numsz))
    return code, protos

def decode(insn):
    op = insn & 0x3F
    A = (insn>>6) & 0xFF
    C = (insn>>14) & 0x1FF
    B = (insn>>23) & 0x1FF
    Bx = (insn>>14) & 0x3FFFF
    sBx = Bx - 131071
    return op,A,B,C,Bx,sBx

def main(path):
    with open(path,'rb') as f:
        magic = f.read(4)
        if magic!=b'\x1bLua': print('Not a chunk'); return
        version = f.read(1); formatb=f.read(1); endian = ord(f.read(1)); little = endian==1
        intsz=ord(f.read(1)); sizesz=ord(f.read(1)); insz=ord(f.read(1)); numsz=ord(f.read(1)); numformat=ord(f.read(1))
        r=Reader(f,little)
        code,protos = parse_function(r,intsz,sizesz,numsz)
        print('Top-level code length:', len(code))
        print('First child protos:', len(protos))
        for i,ins in enumerate(protos[0][0]):
            op,A,B,C,Bx,sBx = decode(ins)
            opname = OPNAMES[op] if op < len(OPNAMES) else f'OP{op}'
            print(f'{i:04}: {opname} {A} {B} {C} Bx={Bx} sBx={sBx}')

if __name__=='__main__':
    if len(sys.argv)<2: print('usage')
    else: main(sys.argv[1])
