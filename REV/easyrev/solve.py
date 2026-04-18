#!/usr/bin/env python3

xor_array = [
    9, 58, 67, 5, 55, 107, 46, 54, 117, 4, 24, 32, 53, 43, 83, 40,
    3, 105, 33, 43, 125, 46, 43, 99, 52, 6, 33, 14, 19, 99, 61,
]
key = [64, 116, 16]

flag = "".join(chr(v ^ key[i % len(key)]) for i, v in enumerate(xor_array))
print(flag)
