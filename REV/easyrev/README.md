# easyrev Write-up

## Challenge
- Name: easyrev
- Category: Reverse Engineering
- Points: 100
- Attachment: `easyrev.pyc`

## Summary
The challenge ships a Python bytecode file. Decompiling/disassembling it shows two constant arrays and a simple XOR routine.

## Analysis
Bytecode logic:
1. `xor_array` is a list of encoded bytes.
2. `key` is `[64, 116, 16]`.
3. The program builds a bytearray where:
   - `out[i] = xor_array[i] ^ key[i % 3]`
4. The output bytes are UTF-8 decoded and printed as the flag.

Equivalent expression:

```python
flag = ''.join(chr(xor_array[i] ^ key[i % 3]) for i in range(len(xor_array)))
```

## Solve
Run:

```bash
python3 solve.py
```

Output:

```text
INSEC{nBeDl0u_Chwya_mn_str1Ngs}
```

## Flag
`INSEC{nBeDl0u_Chwya_mn_str1Ngs}`
