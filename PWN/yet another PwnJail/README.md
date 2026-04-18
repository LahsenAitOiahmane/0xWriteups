# yet another PwnJail (436) - Professional Writeup

## Challenge Metadata

| Field | Value |
| --- | --- |
| Challenge | yet another PwnJail |
| Category | Pwn |
| Points | 436 |
| Author | siegward |
| Remote | `nc challs.insec.club 40004` |
| Binary | `yapj` |
| Flag format | `INSEC{...}` |

---

## Executive Summary

The binary is a shellcode jail:

1. It maps an RWX buffer.
2. Reads up to 2048 bytes of attacker-controlled shellcode.
3. Installs a seccomp filter that blocks many common syscalls.
4. Executes the shellcode.

Direct ORW (`open/read/write`) is blocked. The bypass is to use alternate, unblocked syscalls:

- `openat2(437)` for file open
- `preadv(295)` for file read
- `pwritev2(328)` for output

Bruteforcing likely flag paths showed the flag at `./flag.txt`.

---

## Recon

### Binary properties

`file yapj`:

- ELF 64-bit LSB PIE executable
- Dynamically linked
- Not stripped

`readelf` highlights:

- PIE: yes (`Type: DYN`, `FLAGS_1: PIE`)
- NX: yes (`GNU_STACK` is RW, not executable)
- RELRO: partial (`GNU_RELRO` present, no `BIND_NOW`)

Interesting imports/symbols:

- `mmap`, `read`, `puts`, `exit`, `prctl`
- `seccomp_init`, `seccomp_rule_add`, `seccomp_load`, `seccomp_arch_remove`
- `setup`, `main`

Prompt string:

- `Welcome to yet another PwnJail.`
- `Send shellcode (< 2048 bytes):`

---

## Control Flow and Jail Logic

Disassembly of `main` shows:

1. `setup()` configures alarm/unbuffered stdio.
2. `mmap(NULL, 0x800, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`
3. `read(0, mapped_buf, 0x800)`
4. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
5. `seccomp_init(0x7fff0000)` (`SCMP_ACT_ALLOW` default)
6. `seccomp_arch_remove(ctx, 0x40000003)` and `seccomp_arch_remove(ctx, 0x4000003e)`
7. Loop: `seccomp_rule_add(ctx, 0, syscall, 0)` for 31 syscall numbers (`0` is `SCMP_ACT_KILL`)
8. `seccomp_load(ctx)`
9. `call shellcode_buf`

So this is denylist seccomp over a directly executed shellcode buffer.

---

## Blocked Syscalls (from `main`)

The hardcoded denylist contains these 31 syscall numbers:

| Syscall # | Name |
| ---: | --- |
| 0 | read |
| 1 | write |
| 2 | open |
| 257 | openat |
| 59 | execve |
| 322 | execveat |
| 57 | fork |
| 58 | vfork |
| 56 | clone |
| 40 | sendfile |
| 310 | process_vm_readv |
| 157 | prctl |
| 41 | socket |
| 42 | connect |
| 85 | creat |
| 9 | mmap |
| 10 | mprotect |
| 17 | pread64 |
| 18 | pwrite64 |
| 19 | readv |
| 20 | writev |
| 425 | io_uring_setup |
| 426 | io_uring_enter |
| 44 | sendto |
| 326 | copy_file_range |
| 275 | splice |
| 276 | tee |
| 296 | pwritev |
| 327 | preadv2 |
| 43 | accept |
| 45 | recvfrom |

There is also an additional `seccomp_rule_add` call with syscall `-1` and comparator data involving `0x1f5` (501). In practice, this did not block syscall 501 in testing, so it appears ineffective (likely ignored due to an invalid rule, with return code unchecked by the binary).

---

## Exploit Strategy

### Why naive shellcode fails

- `open/read/write` shellcode is killed by seccomp (`SIGSYS`).
- NASM defaults can bite: without `BITS 64`, instructions may be interpreted in 16-bit mode and fail to assemble correctly.

### Reliable primitive

Use an alternate ORW chain:

1. `openat2(AT_FDCWD, path, &how, sizeof(how))` to obtain fd.
2. `preadv(fd, &iov, 1, 0)` to read file contents into buffer.
3. `pwritev2(1, &iov, 1, -1, -1, 0)` to print to stdout.

Critical implementation details:

- `BITS 64` + `DEFAULT REL` in shellcode source.
- Initialize `iov_base` at runtime (`lea rax, [rel buf]; mov [rel iov], rax`) to avoid bad pointers/EFAULT.
- Keep payload under 2048 bytes.

---

## Exploit Implementation

The solver in `exploit.py`:

- Generates NASM shellcode per candidate path.
- Assembles with `nasm -f bin`.
- Connects to remote service.
- Sends payload.
- Parses output and checks for `INSEC{`.

Path brute-force order includes:

- `flag`, `/flag`, `./flag`, `../flag`, `../../flag`,
- `/flag.txt`, `./flag.txt`, `../flag.txt`,
- common CTF fallback directories.

Winning path in this instance: `./flag.txt`.

---

## Reproduction

### Run exploit

```bash
python3 exploit.py
```

Expected success output includes:

```text
[+] FLAG FOUND
Welcome to yet another PwnJail.

Send shellcode (< 2048 bytes):
INSEC{sYsC4lLS_ar3_SUpP0sEd_To_B3_Un1QUE}
```

### Minimal local checks

```bash
file yapj
readelf -h yapj
readelf -l yapj
readelf -d yapj
objdump -d -Mintel yapj | sed -n '/<main>:/,/^$/p'
```

---

## Useful GDB Workflow

```bash
gdb -q ./yapj
```

Inside gdb:

```gdb
set disassembly-flavor intel
handle SIGSYS stop print nopass
b *main
run
```

For shellcode testing:

```gdb
run < shell.bin
```

Useful runtime inspection:

```gdb
ni
si
info registers
x/20i $rip
x/40gx $rsp
```

---

## Final Flag

`INSEC{sYsC4lLS_ar3_SUpP0sEd_To_B3_Un1QUE}`

---

## Hardening Notes

This challenge demonstrates why seccomp denylists are fragile:

- Blocking only common syscalls still leaves equivalent primitives.
- Better approach: strict allowlist for the exact syscalls required by program logic.
- Never execute user shellcode directly in RWX memory in production systems.
