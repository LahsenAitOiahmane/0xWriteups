start = [132,95,20,49,236,7,45,193,114,147,74,15,219,167,111,67,243,31,45,105,255,205,35]
cand = 'facebooklinkedintwitter'
print('len', len(cand))
print('cand bytes', [ord(c) for c in cand])
print('diffs', [ (ord(c)-start[i]) for i,c in enumerate(cand)])
print('xor', [ ord(c)^start[i] for i,c in enumerate(cand)])
