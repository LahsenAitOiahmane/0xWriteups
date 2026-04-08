#!/usr/bin/env python3
import struct,sys

path = sys.argv[1]

# reuse logic to extract numeric constants
with open(path,'rb') as f:
    b = f.read()
# find header signature
if b[0:4]!=b'\x1bLua':
    print('not lua')
    sys.exit(1)
# parse header
version = b[4]
formatb = b[5]
endian = b[6]
little = endian==1
intsz = b[7]
sizesz = b[8]
insz = b[9]
numsz = b[10]
# helper
off = 11
import struct
def rd(fmt, size):
    global off
    val = struct.unpack(('<' if little else '>')+fmt, b[off:off+size])[0]
    off += size
    return val

def read_byte():
    global off
    v=b[off]
    off+=1
    return v

def read_int(sz):
    global off
    v=0
    if sz==1:
        v=b[off]
    elif sz==2:
        v=struct.unpack(('<H' if little else '>H'), b[off:off+2])[0]
    elif sz==4:
        v=struct.unpack(('<I' if little else '>I'), b[off:off+4])[0]
    elif sz==8:
        v=struct.unpack(('<Q' if little else '>Q'), b[off:off+8])[0]
    off+=sz
    return v

def read_size_t(sz):
    return read_int(sz)

def read_lstring():
    global off
    sz = read_size_t(sizesz)
    if sz==0:
        return None
    data = b[off:off+sz]
    off += sz
    return data[:-1].decode('latin1')

# parse function proto minimal to get constants

def parse_func():
    global off
    src = read_lstring()
    linedefined = read_int(intsz)
    lastlinedefined = read_int(intsz)
    nups = read_byte()
    numparams = read_byte()
    is_vararg = read_byte()
    maxstack = read_byte()
    # code
    codesz = read_int(intsz)
    off += 4*codesz
    # constants
    consts = []
    constsz = read_int(intsz)
    for i in range(constsz):
        t = read_byte()
        if t==0:
            consts.append(None)
        elif t==1:
            val = read_byte(); consts.append(bool(val))
        elif t==3:
            # number
            if numsz==8:
                val = struct.unpack(('<d' if little else '>d'), b[off:off+8])[0]
            else:
                val = struct.unpack(('<f' if little else '>f'), b[off:off+4])[0]
            off += numsz
            consts.append(val)
        elif t==4:
            s = read_lstring(); consts.append(s)
        else:
            consts.append(('unk',t))
    # skip protos
    protos = []
    protosz = read_int(intsz)
    for i in range(protosz):
        protos.append(parse_func())
    # skip lineinfo
    lineinfo_sz = read_int(intsz)
    off += 4*lineinfo_sz
    # skip locals
    locsz = read_int(intsz)
    for i in range(locsz):
        _ = read_lstring(); off += intsz*2
    # upvalues
    upsz = read_int(intsz)
    for i in range(upsz):
        _ = read_lstring()
    return {'src':src, 'consts':consts, 'protos':protos}

proto = parse_func()
# find child proto constants
child = proto['protos'][0]
consts = child['consts']
# extract numeric constants into two arrays
# from earlier analysis, first array values were at idx 9..29 (23 values)
# second array 31..48 (18 values)
arr1 = [int(x)&0xff for (_,x) in enumerate(consts) if False]
# instead, pick indices
nums = [c for c in consts]
# print indices
#print(nums)
# manually extract
arr1 = [int(nums[i]) & 0xff for i in range(9,30)]
arr2 = [int(nums[i]) & 0xff for i in range(31,49)]
print('arr1 len', len(arr1), arr1)
print('arr2 len', len(arr2), arr2)

# try simple transforms
import string
printable = set(range(32,127))

cands = []

# try xor with rotations
n = len(arr1)
for shift in range(n):
    rot = [arr1[(i+shift)%n] for i in range(n)]
    s = bytes([(a ^ b) & 0xff for a,b in zip(arr2, rot)])
    if all(ch in printable for ch in s):
        cands.append(('xor_rot',shift,s.decode('latin1')))

# try addition
for shift in range(n):
    rot = [arr1[(i+shift)%n] for i in range(n)]
    s = bytes([ (b + a) &0xff for a,b in zip(rot, arr2)])
    if all(ch in printable for ch in s):
        cands.append(('add_rot',shift,s.decode('latin1')))

# try subtraction arr2 - arr1_rot
for shift in range(n):
    rot = [arr1[(i+shift)%n] for i in range(n)]
    s = bytes([ (b - a) &0xff for a,b in zip(rot, arr2)])
    if all(ch in printable for ch in s):
        cands.append(('sub_rot',shift,s.decode('latin1')))

# try arr2 xor (arr1 + k)
for k in range(256):
    tmp = [(x + k)&0xff for x in arr1]
    s = bytes([a ^ b for a,b in zip(arr2, tmp[:len(arr2)])])
    if all(ch in printable for ch in s):
        cands.append(('xor_addk',k,s.decode('latin1')))

print('Candidates:')
for c in cands:
    print(c)


t = [c for c in cands if 'flag' in c[2].lower() or 'pwn' in c[2].lower() or 'facebook' in c[2].lower()]
print('Filtered:', t)
