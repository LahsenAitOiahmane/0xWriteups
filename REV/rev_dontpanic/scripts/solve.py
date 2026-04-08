#!/usr/bin/env python3
"""Solve script for the HTB reverse challenge "Don't Panic!".

This script reconstructs the expected 31-byte input by:
- Reading the function-pointer table in src::check_flag
- Mapping each referenced stub to the byte it compares against (cmp dil, 0xNN)

Requirements:
- Linux environment (e.g., WSL)
- objdump available (binutils)

Usage:
  python3 scripts/solve.py ./dontpanic
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SolveResult:
    expected: str
    expected_hex: str
    stubs_found: int
    slots_written: int


def run_objdump(binary: Path) -> str:
    try:
        return subprocess.check_output(
            [
                "objdump",
                "-d",
                "--no-show-raw-insn",
                "-Mintel",
                str(binary),
            ],
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("objdump not found. Install binutils (e.g., `sudo apt-get install binutils`).") from exc


def parse_stub_required_bytes(objdump_text: str) -> dict[int, int]:
    """Return mapping: stub start address -> required byte value."""

    lines = objdump_text.splitlines()

    stub_req: dict[int, int] = {}
    current_addr: int | None = None
    in_stub = False

    # Stubs are Rust-mangled core::ops::function::FnOnce::call_once instantiations.
    stub_hdr = re.compile(r"^([0-9a-f]+) <_ZN4core3ops8function6FnOnce9call_once[^>]*>:$")

    for line in lines:
        m = stub_hdr.match(line)
        if m:
            current_addr = int(m.group(1), 16)
            in_stub = True
            continue

        if in_stub and current_addr is not None:
            m = re.search(r"\bcmp\s+dil,0x([0-9a-f]{2})\b", line)
            if m:
                stub_req[current_addr] = int(m.group(1), 16)
                in_stub = False

    return stub_req


def extract_check_flag_block(objdump_text: str) -> list[str]:
    """Extract the assembly block of _ZN3src10check_flag... without relying on demangling."""

    lines = objdump_text.splitlines()

    start = None
    for i, line in enumerate(lines):
        if re.match(r"^[0-9a-f]+ <_ZN3src10check_flag17h[0-9a-f]+E>:$", line):
            start = i
            break

    if start is None:
        raise SystemExit("Could not locate src::check_flag symbol in objdump output.")

    block: list[str] = []
    for line in lines[start + 1 :]:
        # Next symbol header terminates the function.
        if re.match(r"^[0-9a-f]+ <", line):
            break
        block.append(line)

    return block


def parse_function_pointer_slots(check_flag_block: list[str]) -> dict[int, int]:
    """Return mapping: stack slot offset -> target function address."""

    reg: dict[str, int] = {}
    slots: dict[int, int] = {}

    # Example:
    #   lea rax,[rip+0xffff...]        # 8b80 <...>
    #   mov QWORD PTR [rsp+0x10],rax
    for line in check_flag_block:
        m = re.search(
            r"\blea\s+(rax|rcx|rdx|rdi|r14),\[rip\+0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)\s+<",
            line,
        )
        if m:
            reg[m.group(1)] = int(m.group(2), 16)
            continue

        m = re.search(r"mov\s+QWORD PTR \[rsp\+0x([0-9a-f]+)\],(rax|rcx|rdx|rdi|r14)", line)
        if m:
            off = int(m.group(1), 16)
            slots[off] = reg.get(m.group(2), 0)

    # Filter out any zero entries (shouldn't happen in this challenge, but keeps it safer).
    return {k: v for k, v in slots.items() if v != 0}


def reconstruct_expected_string(slots: dict[int, int], stub_req: dict[int, int]) -> SolveResult:
    expected_chars: list[str] = []

    # The binary asserts length == 0x1f (31) and indexes a table at rsp+0x10.
    for off in range(0x10, 0x10 + 8 * 0x1F, 8):
        addr = slots.get(off)
        if addr is None:
            raise SystemExit(f"Missing function pointer slot for stack offset {hex(off)}")

        required = stub_req.get(addr)
        if required is None:
            raise SystemExit(f"No cmp immediate found for stub at {hex(addr)}")

        expected_chars.append(chr(required))

    expected = "".join(expected_chars)
    return SolveResult(
        expected=expected,
        expected_hex=expected.encode().hex(),
        stubs_found=len(stub_req),
        slots_written=len(slots),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconstruct the expected input for dontpanic")
    parser.add_argument("binary", nargs="?", default="./dontpanic", help="Path to the challenge binary")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"Binary not found: {binary}")

    disasm = run_objdump(binary)
    stub_req = parse_stub_required_bytes(disasm)
    check_flag_block = extract_check_flag_block(disasm)
    slots = parse_function_pointer_slots(check_flag_block)

    result = reconstruct_expected_string(slots, stub_req)

    print(f"stubs_found {result.stubs_found}")
    print(f"slots_written {result.slots_written}")
    print(f"expected {result.expected}")
    print(f"hex {result.expected_hex}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
