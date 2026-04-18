print("Starting test...")
from pwn import *
p = process('./highscore')
p.sendlineafter(b'> ', b'4')
print(p.recvall())
