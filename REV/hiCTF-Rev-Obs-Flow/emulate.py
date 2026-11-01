#!/usr/bin/env python3
import struct, io
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

# ---- load ELF ----
ELF_PATH = "extracted/challenge"
with open(ELF_PATH, "rb") as f:
    raw = f.read()
elf = ELFFile(io.BytesIO(raw))
data = raw

# map PT_LOAD segments
segments = []
for seg in elf.iter_segments():
    if seg["p_type"] != "PT_LOAD":
        continue
    segments.append((seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"],
                     seg["p_memsz"], seg["p_flags"], seg.data()))

BASE = 0x400000
STACK = 0x7ffffffde000
STACK_SIZE = 0x200000

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# map text/data
for vaddr, vend, memsz, flags, segdata in segments:
    perm = 0
    if flags & 1:  # PF_X
        perm |= UC_PROT_EXEC
    if flags & 2:  # PF_W
        perm |= UC_PROT_WRITE
    if flags & 4:  # PF_R
        perm |= UC_PROT_READ
    # align down/up to page
    addr = vaddr & ~0xfff
    size = ((vend - addr) + 0xfff) & ~0xfff
    try:
        mu.mem_map(addr, size, perm)
    except UcError:
        pass
    # write file data (only filesz, rest zero)
    mu.mem_write(vaddr, segdata[:vend - vaddr])

# map stack
mu.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
RSP0 = STACK + STACK_SIZE - 0x1000
mu.reg_write(UC_X86_REG_RSP, RSP0)

# argv dummy: argc=1, argv[0]=ptr, envp=0
argv_ptr = STACK + 0x800
arg0 = STACK + 0x900
mu.mem_write(arg0, b"prog\x00")
mu.mem_write(argv_ptr, struct.pack("<Q", arg0) + b"\x00" * 16)
mu.reg_write(UC_X86_REG_RDI, 1)          # argc
mu.mem_write(RSP0, struct.pack("<Q", argv_ptr))  # argv at [rsp]
# main is called with (argc, argv, envp); set rsi/rdx too
mu.reg_write(UC_X86_REG_RSI, argv_ptr)
mu.reg_write(UC_X86_REG_RDX, 0)

MAIN = 0x4010c0

# ---- PLT stubs ----
PLT = {
    0x401030: "strncmp",
    0x401040: "puts",
    0x401050: "strlen",
    0x401060: "printf",
    0x401070: "fgets",
    0x401080: "fflush",
}

# fake stdin input: valid format "hiCTF{" + 40 chars + "}"  (47 chars, NO newline)
FAKE_INPUT = b"hiCTF{" + b"A" * 40 + b"}"

captured_puts = []
captured_printf = []
output_dump = None
denied = False
success_print = None
state_at_decrypt = None
dispatch_log = []

def read_cstr(mu, addr, maxlen=200):
    out = b""
    for i in range(maxlen):
        b = mu.mem_read(addr + i, 1)
        if b == b"\x00":
            break
        out += b
    return out

def hook_code(mu, address, size, user_data):
    global output_dump, denied, success_print, state_at_decrypt, dispatch_log
    # dump output buffer right before hash compare
    if address == 0x401b76:
        # rsp+0x100 is output buffer (computed). read 0x62+1 bytes
        rsp = mu.reg_read(UC_X86_REG_RSP)
        try:
            buf = bytes(mu.mem_read(rsp + 0x100, 0x63))
            output_dump = buf
        except Exception as e:
            output_dump = ("ERR", str(e))
    # detect Access Denied path entry points
    if address in (0x401533, 0x401570):
        denied = True
        dispatch_log.append(("DENIED", hex(address)))
    # log dispatcher entries to capture the state-machine path
    if address in (0x401510, 0x401590, 0x401740):
        eax = mu.reg_read(UC_X86_REG_RAX)
        dispatch_log.append((hex(address), hex(eax & 0xffffffff)))
        # capture constant-init state S0 the first time we hit the dispatcher
        if state_at_decrypt is None:
            rsp = mu.reg_read(UC_X86_REG_RSP)
            try:
                state_at_decrypt = bytes(mu.mem_read(rsp + 0xe0, 32))
            except Exception as e:
                state_at_decrypt = ("ERR", str(e))

    # FORCE the real control-flow chain by overriding the next-state selections.
    # Map each handler's "next-state" instruction to the correct real successor.
    chain_fix = {
        0x401c6a: 0x6b3e91f2,   # handler 0x2f71a8d4 -> 0x6b3e91f2
        0x401738: 0x19c45d80,  # handler 0x6b3e91f2 -> 0x19c45d80
        0x401d32: 0x43b7e025,  # handler 0x19c45d80 -> 0x43b7e025
        0x401d6c: 0x51e29f3a,  # handler 0x43b7e025 -> 0x51e29f3a
        0x401816: 0x38a5f41c,  # handler 0x51e29f3a -> 0x38a5f41c (decrypt)
        0x4017cf: 0x38a5f41c,  # handler 0x3d087b16 -> 0x38a5f41c
    }
    if address in chain_fix:
        mu.reg_write(UC_X86_REG_RAX, chain_fix[address])
        dispatch_log.append(("FORCED", hex(address), hex(chain_fix[address])))
    # capture constant-init state S0 right after setup writes it (0x401233)
    if address == 0x401233:
        rsp = mu.reg_read(UC_X86_REG_RSP)
        try:
            state_at_decrypt = bytes(mu.mem_read(rsp + 0xe0, 32))
        except Exception as e:
            state_at_decrypt = ("ERR", str(e))
    # detect success printf: we capture in printf hook via format
    # PLT hooks
    if address in PLT:
        name = PLT[address]
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rsp = mu.reg_read(UC_X86_REG_RSP)
        retaddr = struct.unpack("<Q", bytes(mu.mem_read(rsp, 8)))[0]
        rax = 0
        if name == "fgets":
            buf = rdi
            size = rsi
            n = min(len(FAKE_INPUT), size - 1)
            mu.mem_write(buf, FAKE_INPUT[:n])
            mu.mem_write(buf + n, b"\x00")
            rax = buf
        elif name == "strlen":
            s = read_cstr(mu, rdi)
            rax = len(s)
        elif name == "strncmp":
            s1 = read_cstr(mu, rdi)
            s2 = read_cstr(mu, rsi)
            n = rdx
            a = s1[:n]; b = s2[:n]
            if a == b:
                rax = 0
            elif a < b:
                rax = -1
            else:
                rax = 1
        elif name == "puts":
            s = read_cstr(mu, rdi)
            captured_puts.append(s)
            rax = 1
        elif name == "printf":
            fmt = read_cstr(mu, rdi)
            captured_printf.append((fmt, rsi, rdx))
            # if format is "%s" and rsi points to output buffer region, capture
            if fmt == b"%s" or fmt.startswith(b"%s"):
                s = read_cstr(mu, rsi)
                success_print = s
            rax = 0
        elif name == "fflush":
            rax = 0
        # skip PLT stub: set rip to return addr, adjust rsp, set rax
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, retaddr)
        mu.reg_write(UC_X86_REG_RAX, rax & 0xffffffffffffffff)

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(MAIN, 0x40158a)  # main returns at 0x40158a (ret)
except UcError as e:
    print("UcError:", e)
    print("last PC approx:", hex(mu.reg_read(UC_X86_REG_RIP)))

print("===== RESULTS =====")
print("denied (access denied path)?", denied)
print("puts captured:", [s.decode('latin1') for s in captured_puts])
print("printf captured:", [(f.decode('latin1'), hex(s), hex(d)) for f, s, d in captured_printf])
print("success printf string:", success_print)
print("output_dump (before hash cmp):", output_dump)
print("state_at_decrypt (32 bytes at rsp+0xe0):", state_at_decrypt)
if isinstance(state_at_decrypt, bytes):
    print("state_at_decrypt hex:", state_at_decrypt.hex())
print("===== DISPATCH PATH (address, state_eax) =====")
for a, s in dispatch_log:
    print(a, s)
if isinstance(output_dump, bytes):
    print("output_dump repr:", output_dump)
    print("output_dump as latin1:", output_dump.decode('latin1'))
