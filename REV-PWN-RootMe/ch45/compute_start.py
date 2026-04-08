S = [33,1,84,-104,-65,46,-28,-49,15,110,-18,40,-59,-25,0,22,-46,-88,-33,-13,88,-50,129]
E = [99,96,192,201,45,53,73,144,99,1,92,55,22,142,111,89,33,199,78,92,167,155,162]

res = []
for i in range(23):
    idx = i+1
    shift = S[i]
    end = E[i]
    if idx % 2 == 1:
        # odd: start - shift == end -> start = end + shift
        start = end + shift
    else:
        # even: start + shift == end -> start = end - shift
        start = end - shift
    start = start % 256
    res.append(start)

print('bytes:', res)
print('as bytes:', bytes(res))
print('as chars:', ''.join(chr(b) for b in res))

# alternate parity
res2 = []
for i in range(23):
    idx=i+1
    shift=S[i]
    end=E[i]
    if idx%2==1:
        # try start + shift == end -> start = end - shift
        start = end - shift
    else:
        start = end + shift
    start = start % 256
    res2.append(start)
print('alt bytes:', res2)
print('alt chars:', ''.join(chr(b) for b in res2))


def validate(s):
    b = [ord(c) for c in s]
    for i in range(23):
        idx = i+1
        sh = S[i]
        en = E[i]
        if idx % 2 == 1:
            if (b[i] - sh) % 256 != en % 256:
                return False
        else:
            if (b[i] + sh) % 256 != en % 256:
                return False
    return True

cand1 = ''.join(chr(b) for b in res)
cand2 = ''.join(chr(b) for b in res2)
print('validate cand1', validate(cand1))
print('validate cand2', validate(cand2))
