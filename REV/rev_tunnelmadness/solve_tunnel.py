import argparse
import collections
import socket
import struct
import sys
from dataclasses import dataclass


MAZE_ADDR = 0x20E0
MAZE_SIZE = 0x1F400
DIM = 20
CELL_SIZE = 16


@dataclass(frozen=True)
class Section:
    name: str
    addr: int
    offset: int
    size: int


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from('<H', b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from('<Q', b, off)[0]


def parse_elf64_sections(blob: bytes) -> list[Section]:
    if blob[:4] != b'\x7fELF':
        raise ValueError('Not an ELF file')
    if blob[4] != 2:
        raise ValueError('Not ELF64')
    if blob[5] != 1:
        raise ValueError('Not little-endian ELF')

    e_shoff = _u64(blob, 0x28)
    e_shentsize = _u16(blob, 0x3A)
    e_shnum = _u16(blob, 0x3C)
    e_shstrndx = _u16(blob, 0x3E)

    if e_shoff == 0 or e_shnum == 0:
        raise ValueError('No section headers')

    def sh(i: int) -> bytes:
        start = e_shoff + i * e_shentsize
        end = start + e_shentsize
        return blob[start:end]

    shstr = sh(e_shstrndx)
    shstr_off = _u64(shstr, 0x18)
    shstr_size = _u64(shstr, 0x20)
    shstrtab = blob[shstr_off:shstr_off + shstr_size]

    sections: list[Section] = []
    for i in range(e_shnum):
        hdr = sh(i)
        name_off = _u32(hdr, 0x00)
        sec_addr = _u64(hdr, 0x10)
        sec_off = _u64(hdr, 0x18)
        sec_size = _u64(hdr, 0x20)

        if name_off >= len(shstrtab):
            name = f'<badname:{name_off}>'
        else:
            end = shstrtab.find(b'\x00', name_off)
            if end == -1:
                end = len(shstrtab)
            name = shstrtab[name_off:end].decode('ascii', errors='replace')

        sections.append(Section(name=name, addr=sec_addr, offset=sec_off, size=sec_size))

    return sections


def load_maze_types(elf_path: str) -> list[int]:
    blob = open(elf_path, 'rb').read()
    sections = parse_elf64_sections(blob)
    rodata = next((s for s in sections if s.name == '.rodata'), None)
    if rodata is None:
        raise ValueError('Could not find .rodata section')
    if not (rodata.addr <= MAZE_ADDR < rodata.addr + rodata.size):
        raise ValueError('maze address not within .rodata')

    maze_off = rodata.offset + (MAZE_ADDR - rodata.addr)
    maze = blob[maze_off:maze_off + MAZE_SIZE]
    if len(maze) != MAZE_SIZE:
        raise ValueError('Failed to read full maze blob')

    expected_cells = DIM * DIM * DIM
    if len(maze) != expected_cells * CELL_SIZE:
        raise ValueError('Unexpected maze size')

    types: list[int] = [0] * expected_cells
    for i in range(expected_cells):
        x, y, z, t = struct.unpack_from('<4I', maze, i * CELL_SIZE)
        # Sanity-check a few entries; coordinates are stored redundantly.
        if i < 10:
            pass
        idx = x * (DIM * DIM) + y * DIM + z
        if idx < 0 or idx >= expected_cells:
            raise ValueError(f'Bad coordinates in maze struct: {(x, y, z)}')
        types[idx] = t

    return types


def solve_path(types: list[int]) -> str:
    def in_bounds(x: int, y: int, z: int) -> bool:
        return 0 <= x < DIM and 0 <= y < DIM and 0 <= z < DIM

    start = (0, 0, 0)
    if types[0] == 2:
        raise ValueError('Start cell is blocked')

    moves = [
        (-1, 0, 0, 'L'),
        (1, 0, 0, 'R'),
        (0, -1, 0, 'B'),
        (0, 1, 0, 'F'),
        (0, 0, -1, 'D'),
        (0, 0, 1, 'U'),
    ]

    q = collections.deque([start])
    prev: dict[tuple[int, int, int], tuple[tuple[int, int, int], str]] = {}
    seen = {start}

    goal = None
    while q:
        x, y, z = q.popleft()
        if types[x * (DIM * DIM) + y * DIM + z] == 3:
            goal = (x, y, z)
            break

        for dx, dy, dz, ch in moves:
            nx, ny, nz = x + dx, y + dy, z + dz
            if not in_bounds(nx, ny, nz):
                continue
            if (nx, ny, nz) in seen:
                continue
            t = types[nx * (DIM * DIM) + ny * DIM + nz]
            if t == 2:
                continue
            seen.add((nx, ny, nz)) # type: ignore
            prev[(nx, ny, nz)] = ((x, y, z), ch)
            q.append((nx, ny, nz)) # type: ignore

    if goal is None:
        raise ValueError('No goal (type=3) reachable')

    path_chars: list[str] = []
    cur = goal
    while cur != start:
        p, ch = prev[cur]
        path_chars.append(ch)
        cur = p
    path_chars.reverse()
    return ''.join(path_chars)


def interact(ip: str, port: int, path: str) -> str:
    s = socket.create_connection((ip, port), timeout=10)
    try:
        f = s.makefile('rwb', buffering=0)

        def read_some(max_bytes: int = 4096) -> bytes:
            try:
                return s.recv(max_bytes)
            except socket.timeout:
                return b''

        out = bytearray()

        # Prime: read initial banner/prompt.
        out += read_some()

        for ch in path:
            f.write(ch.encode() + b'\n')
            out += read_some()

        # After reaching goal, binary typically prints message + flag.
        out += read_some(65535)
        return out.decode(errors='replace')
    finally:
        s.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', default='tunnel', help='Path to local ELF binary')
    ap.add_argument('--ip', default=None, help='Remote IP (optional)')
    ap.add_argument('--port', type=int, default=None, help='Remote port (optional)')
    ap.add_argument('--print-path', action='store_true', help='Only print movement path')
    args = ap.parse_args()

    types = load_maze_types(args.elf)
    path = solve_path(types)

    if args.print_path or args.ip is None or args.port is None:
        print(path)
        return 0

    transcript = interact(args.ip, args.port, path)
    sys.stdout.write(transcript)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
