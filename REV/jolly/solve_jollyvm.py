#!/usr/bin/env python3
"""Solve the jollyvm license key by emulating its custom VM.

This binary is an ELF64 PIE for Linux and is expected to be run under WSL.
We extract:
- jump table at .rodata+0x80 (only for documentation)
- const table at .rodata+0xE0 (52 bytes)
- bytecode program at .rodata+0x120 (0x9c instructions * 6 bytes)

Then emulate the VM and try to reconstruct a key.

If the VM implements a direct per-byte transform/compare, we can invert it.
Otherwise we fall back to a small Z3-free search leveraging the VM structure
(typically linear / bytewise independent).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional


RODATA = 0x2000
JT_OFF = 0x2080
CONST_OFF = 0x20E0
PROG_OFF = 0x2120
INSTR_COUNT = 0x9C
INSTR_SIZE = 6
KEY_LEN = 0x34


OP_NAMES = {
    0x00: "LDI",
    0x01: "MOV",
    0x02: "ADDI",
    0x03: "ADDR",
    0x04: "SUBI",
    0x05: "SUBR",
    0x06: "XOR",
    0x07: "OR",
    0x08: "SHL",
    0x09: "SHR",
    0x0A: "ANDI",
    0x0B: "LDBK",
    0x0C: "STBM",
    0x0D: "LDBM",
    0x0E: "LDBC",
    0x0F: "CLT",
    0x10: "CEQI",
    0x11: "CEQR",
    0x12: "JMP",
    0x13: "JT",
    0x14: "JF",
    0x15: "SETRES",
    0x16: "HALT",
}


@dataclass(frozen=True)
class Instr:
    op: int
    a: int
    b: int
    c: int
    imm: int

    def __str__(self) -> str:
        nm = OP_NAMES.get(self.op, f"OP{self.op:02X}")
        return f"{nm:<6} a={self.a:02X} b={self.b:02X} c={self.c:02X} imm={self.imm:04X}"


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def s16(x: int) -> int:
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def parse(binary: bytes) -> tuple[List[Instr], bytes]:
    const = binary[CONST_OFF : CONST_OFF + KEY_LEN]
    prog = binary[PROG_OFF : PROG_OFF + INSTR_COUNT * INSTR_SIZE]
    ins: List[Instr] = []
    for i in range(0, len(prog), INSTR_SIZE):
        op, a, b, c, imm = struct.unpack("<BBBBH", prog[i : i + INSTR_SIZE])
        ins.append(Instr(op, a, b, c, imm))
    return ins, const


@dataclass
class VM:
    regs: List[int]
    mem: bytearray
    key: bytes
    const: bytes
    flag: int = 0
    pending_set: bool = False
    pending_value: int = 0

    def __init__(self, key: bytes, const: bytes):
        # The binary uses DWORD regs indexed by 8-bit register id.
        # Allocate enough to cover reg[89] used as the final result storage.
        self.regs = [0] * 0x100
        self.mem = bytearray(0x100)  # addressable up to 0xff
        self.key = key
        self.const = const
        self.flag = 0
        self.pending_set = False
        self.pending_value = 0

        # Native initialization (see .text around 0x12f3):
        # - it zeros a 0x34-byte DWORD register area
        # - then sets DWORD [rsp] = 0x34 (reg0)
        # - and DWORD [rsp+0x24] = 0xF337 (reg9)
        self.regs[0] = KEY_LEN
        self.regs[9] = 0xF337

    def r(self, idx: int) -> int:
        return self.regs[idx & 0xFF]

    def w(self, idx: int, val: int) -> None:
        self.regs[idx & 0xFF] = u32(val)

    def exec_one(self, ip: int, ins: Instr) -> Optional[int]:
        op, a, b, imm = ins.op, ins.a, ins.b, ins.imm
        if op == 0x00:  # LDI
            self.w(a, s16(imm))
        elif op == 0x01:  # MOV
            self.w(a, self.r(b))
        elif op == 0x02:  # ADDI
            self.w(a, self.r(a) + s16(imm))
        elif op == 0x03:  # ADDR
            self.w(a, self.r(a) + self.r(b))
        elif op == 0x04:  # SUBI
            self.w(a, self.r(a) - s16(imm))
        elif op == 0x05:  # SUBR
            self.w(a, self.r(a) - self.r(b))
        elif op == 0x06:  # XOR
            self.w(a, self.r(a) ^ self.r(b))
        elif op == 0x07:  # OR
            self.w(a, self.r(a) | self.r(b))
        elif op == 0x08:  # SHL
            sh = imm & 0xFF
            self.w(a, u32(self.r(b) << sh))
        elif op == 0x09:  # SHR
            sh = imm & 0xFF
            self.w(a, (self.r(b) & 0xFFFFFFFF) >> sh)
        elif op == 0x0A:  # ANDI
            self.w(a, self.r(a) & (imm & 0xFFFF))
        elif op == 0x0B:  # LDBK dst=a, idx=reg[b]+imm
            idx = (self.r(b) + s16(imm))
            if 0 <= idx <= KEY_LEN - 1:
                self.w(a, self.key[idx])
            else:
                self.w(a, 0)
        elif op == 0x0C:  # STBM mem[reg[b]+imm]=reg[a]
            idx = (self.r(b) + s16(imm))
            if 0 <= idx <= 0xFF:
                self.mem[idx] = self.r(a) & 0xFF
        elif op == 0x0D:  # LDBM dst=a from mem[reg[b]+imm] (but only if <=0x33 per binary)
            idx = (self.r(b) + s16(imm))
            if 0 <= idx <= KEY_LEN - 1:
                self.w(a, self.mem[idx])
            else:
                self.w(a, 0)
        elif op == 0x0E:  # LDBC dst=a from const[reg[b]+imm]
            idx = (self.r(b) + s16(imm))
            if 0 <= idx <= KEY_LEN - 1:
                self.w(a, self.const[idx])
            else:
                self.w(a, 0)
        elif op == 0x0F:  # CLT reg[a] < imm
            self.flag = 1 if (self.r(a) & 0xFFFFFFFF) < (s16(imm) & 0xFFFFFFFF) else 0
        elif op == 0x10:  # CEQI reg[a] == imm
            self.flag = 1 if (self.r(a) & 0xFFFFFFFF) == (s16(imm) & 0xFFFFFFFF) else 0
        elif op == 0x11:  # CEQR reg[a] == reg[b]
            self.flag = 1 if self.r(a) == self.r(b) else 0
        elif op == 0x12:  # JMP
            # Native sets v13=imm and does NOT auto-increment.
            return s16(imm)
        elif op == 0x13:  # JT
            if self.flag:
                return s16(imm)
        elif op == 0x14:  # JF
            if not self.flag:
                return s16(imm)
        elif op == 0x15:  # SETRES (case 21)
            self.pending_value = 1 if imm != 0 else 0
            self.pending_set = True
        elif op == 0x16:  # HALT
            # Native: if pending_set then reg[89]=pending_value; then return reg[89]
            if self.pending_set:
                self.w(89, self.pending_value)
            return -1
        # default: next ip
        return None


def run_vm(program: List[Instr], key: bytes, const: bytes) -> tuple[int, VM]:
    vm = VM(key=key, const=const)
    ip = 0
    # Safety: cap steps.
    for _ in range(100000):
        if ip < 0 or ip >= len(program):
            break
        ins = program[ip]
        nxt = vm.exec_one(ip, ins)
        if nxt == -1:
            return int(vm.r(89) != 0), vm
        if nxt is None:
            ip += 1
        else:
            ip = nxt
    return 0, vm


def vm_output(program: List[Instr], key: bytes, const: bytes) -> bytes:
    """Return the 52-byte output buffer the binary compares against const."""
    _, vm = run_vm(program, key, const)
    return bytes(vm.mem[:KEY_LEN])


def bytes_to_bits_le(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little", signed=False)


def bits_to_bytes_le(x: int, nbytes: int) -> bytes:
    return int(x).to_bytes(nbytes, byteorder="little", signed=False)


def solve_linear(program: List[Instr], const: bytes) -> tuple[bytes, List[int], int]:
    """Solve for key such that vm_output(key) == const using GF(2) elimination.

    The VM uses only XOR/shifts/masking to compute the output buffer, making the
    mapping linear over GF(2). We exploit that by evaluating the VM on basis inputs.
    """

    nbits = KEY_LEN * 8
    base_key = bytes([0] * KEY_LEN)
    base_out = vm_output(program, base_key, const)
    base_out_bits = bytes_to_bits_le(base_out)
    target_bits = bytes_to_bits_le(const)
    b = target_bits ^ base_out_bits

    # Build matrix rows: each row is a bitset of length nbits describing which
    # key bits xor to produce that output bit.
    rows = [0] * nbits

    for in_bit in range(nbits):
        kb = bytearray(KEY_LEN)
        kb[in_bit // 8] = 1 << (in_bit % 8)
        out = vm_output(program, bytes(kb), const)
        delta = bytes_to_bits_le(out) ^ base_out_bits

        # For each output bit set in delta, that row depends on in_bit.
        d = delta
        while d:
            lsb = d & -d
            out_bit = (lsb.bit_length() - 1)
            rows[out_bit] |= (1 << in_bit)
            d ^= lsb

        if (in_bit + 1) % 64 == 0:
            print(f"[*] Built {in_bit+1}/{nbits} columns")

    # Gaussian elimination on rows.
    where = [-1] * nbits
    row = 0
    for col in range(nbits):
        # Find pivot row with bit col set.
        pivot = None
        for r in range(row, nbits):
            if (rows[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            continue
        # Swap into position
        rows[row], rows[pivot] = rows[pivot], rows[row]
        # Swap corresponding b bit
        bit_row = (b >> row) & 1
        bit_pivot = (b >> pivot) & 1
        if bit_row != bit_pivot:
            b ^= (1 << row) | (1 << pivot)

        where[col] = row

        # Eliminate col from all other rows.
        for r in range(nbits):
            if r != row and ((rows[r] >> col) & 1):
                rows[r] ^= rows[row]
                # b_r ^= b_row
                if ((b >> row) & 1):
                    b ^= (1 << r)

        row += 1
        if row == nbits:
            break

    # Check for inconsistency: row with 0 == 1
    for r in range(nbits):
        if rows[r] == 0 and ((b >> r) & 1):
            raise RuntimeError("Inconsistent system: no solution")

    # Extract solution.
    x = 0
    for col in range(nbits):
        r = where[col]
        if r == -1:
            # free variable -> keep 0
            continue
        if (b >> r) & 1:
            x |= (1 << col)

    key = bits_to_bytes_le(x, KEY_LEN)

    # Build a nullspace basis (each basis vector is a bitset over key bits).
    free_cols = [c for c in range(nbits) if where[c] == -1]
    basis: List[int] = []
    for f in free_cols:
        vec = 1 << f
        for pcol in range(nbits):
            prow = where[pcol]
            if prow == -1:
                continue
            if (rows[prow] >> f) & 1:
                vec |= 1 << pcol
        basis.append(vec)

    rank = nbits - len(free_cols)
    return key, basis, rank


def is_good_key_bytes(k: bytes, *, require_printable: bool) -> bool:
    # Must be a single fgets line: no NUL, no LF, and ideally no CR.
    bad = {0x00, 0x0A, 0x0D}
    if any(b in bad for b in k):
        return False
    if require_printable and not all(32 <= b < 127 for b in k):
        return False
    return True


def find_constrained_solution(particular: bytes, basis: List[int], *, require_printable: bool, tries: int = 200000) -> bytes:
    """Random-walk the affine solution space to satisfy byte constraints."""
    import random

    nbits = KEY_LEN * 8
    x0 = bytes_to_bits_le(particular)

    # Fast path: particular already valid.
    if is_good_key_bytes(particular, require_printable=require_printable):
        return particular

    if not basis:
        raise RuntimeError("No degrees of freedom; only one solution exists and it violates constraints")

    # Random combinations of nullspace basis vectors.
    best = None
    best_score = 10**9

    for t in range(tries):
        x = x0
        # Flip each basis vector with p=0.5
        for v in basis:
            if random.getrandbits(1):
                x ^= v
        k = bits_to_bytes_le(x, KEY_LEN)

        # Score by number of "bad" bytes, then by non-printable count.
        bad = sum(1 for b in k if b in (0x00, 0x0A, 0x0D))
        nonprint = sum(1 for b in k if not (32 <= b < 127))
        score = bad * 1000 + nonprint
        if score < best_score:
            best_score = score
            best = k
            if best_score == 0 and (not require_printable or nonprint == 0):
                break

        if is_good_key_bytes(k, require_printable=require_printable):
            return k

    raise RuntimeError(f"Failed to find constrained solution (best_score={best_score}, best={best!r})")


def main() -> int:
    here = Path(__file__).resolve().parent
    bin_path = here / "jollyvm"
    if not bin_path.exists():
        print(f"[-] Could not find binary at {bin_path}")
        return 1

    program, const = parse(bin_path.read_bytes())
    print(f"[*] Parsed {len(program)} instructions, const={const.hex()}")

    # Quick opcode histogram + locate HALTs / SETRES.
    from collections import Counter
    hist = Counter(i.op for i in program)
    used = ", ".join(f"{OP_NAMES.get(k,hex(k))}:{v}" for k, v in sorted(hist.items()))
    print(f"[*] Opcode histogram: {used}")
    for idx, ins in enumerate(program):
        if ins.op in (0x15, 0x16):
            print(f"[*] Control op at {idx:03d}: {ins}")

    for idx, ins in enumerate(program):
        if ins.op in (0x0C, 0x0D, 0x0E):
            print(f"[*] Mem/Const op at {idx:03d}: {ins}")

    # First, sanity-check VM vs native expectations on a dummy key.
    dummy = b"A" * KEY_LEN
    res, _ = run_vm(program, dummy, const)
    print(f"[*] VM sanity result with 'A'*{KEY_LEN}: {res}")

    # Dump a readable disassembly if requested.
    # (Keep it lightweight: only the first ~120 and the tail.)
    print("[*] Program head (first 60):")
    for i in range(min(60, len(program))):
        print(f"  {i:03d}: {program[i]}")
    print("[*] Program tail (last 30):")
    for i in range(max(0, len(program) - 30), len(program)):
        print(f"  {i:03d}: {program[i]}")

    print("[*] Program middle (60..125):")
    for i in range(60, min(126, len(program))):
        print(f"  {i:03d}: {program[i]}")

    print("[*] Solving key via GF(2) linear algebra (416x416)...")
    key0, basis, rank = solve_linear(program, const)
    print(f"[*] Linear solve done: rank={rank}, nullity={len(basis)}")

    # The raw solution may contain \n or \0, which can't be typed into the program.
    # Find an alternative solution that is safe to feed via fgets (and preferably printable).
    require_printable = True
    try:
        key = find_constrained_solution(key0, basis, require_printable=require_printable)
    except RuntimeError:
        # Fall back to "binary-safe" (still no NUL/LF/CR) if printable is too strict.
        require_printable = False
        key = find_constrained_solution(key0, basis, require_printable=require_printable)

    out = vm_output(program, key, const)
    ok = out == const
    print(f"[*] Emulated output matches const: {ok}")
    if not ok:
        print(f"[-] Mismatch: got {out.hex()} expected {const.hex()}")
        return 4

    if require_printable:
        print(f"[+] License key (ASCII, 52 chars): {key.decode('ascii')}")
    else:
        print(f"[+] License key (bytes, hex): {key.hex()}")
        print("[*] Use a script to send raw bytes (see below).")

    # Provide a ready-to-run WSL one-liner that feeds the key.
    print("[*] WSL verify command:")
    if require_printable:
        print(f"    printf '%s\\n' '{key.decode('ascii')}' | /mnt/c/Users/sadik/Downloads/jolly/jollyvm")
    else:
        print(f"    python3 - <<'PY'\nimport binascii,sys\nk=binascii.unhexlify('{key.hex()}')\nsys.stdout.buffer.write(k+b'\\n')\nPY\n| /mnt/c/Users/sadik/Downloads/jolly/jollyvm")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
