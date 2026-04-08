S = [33,1,84,-104,-65,46,-28,-49,15,110,-18,40,-59,-25,0,22,-46,-88,-33,-13,88,-50,129]
E = [99,96,192,201,45,53,73,144,99,1,92,55,22,142,111,89,33,199,78,92,167,155,162]

S_signed = [x-256 if x>127 else x for x in S]
res3 = []
for i in range(23):
    idx = i+1
    shift = S_signed[i]
    end = E[i]
    if idx % 2 == 1:
        start = end + shift
    else:
        start = end - shift
    res3.append(start % 256)

print('signed-shift bytes:', res3)
print('signed-shift chars:', ''.join(chr(b) for b in res3))

# validate
b = res3
ok = True
for i in range(23):
    idx = i+1
    sh = S_signed[i]
    en = E[i]
    if idx%2==1:
        if (b[i] - sh) % 256 != en % 256:
            ok = False
    else:
        if (b[i] + sh) % 256 != en % 256:
            ok = False
print('validate signed-shift:', ok)
