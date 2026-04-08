# TunnelMadness — Reverse Engineering Write-up

Author: L27Sen

## 1️⃣ Title & Metadata

- **Challenge:** TunnelMadness
- **Category:** Reverse Engineering
- **Difficulty:** Not provided
- **CTF/Platform:** Hack The Box (HTB)
- **Author:** L27Sen
- **Date:** 2026-01-04

## 2️⃣ Challenge Description

> Within Vault 8707 are located master keys used to access any vault in the country. Unfortunately, the entrance was caved in long ago. There are decades old rumors that the few survivors managed to tunnel out deep underground and make their way to safety. Can you uncover their tunnel and break back into the vault?

**Provided artifact(s):**

- `tunnel` (Linux executable)

**Remote service:**

- `nc 94.237.123.236 58120`

**Interaction model:**

- The service repeatedly prompts: `Direction (L/R/F/B/U/D/Q)?`
- Invalid moves respond with: `Cannot move that way`

**Constraints:** Not provided (no explicit brute-force/time-limit guidance was provided).

## 3️⃣ Goal / Objective

Reach the success condition that triggers flag output and retrieve a flag matching the format `HTB{...}`.

## 4️⃣ Initial Analysis & Reconnaissance

### File identification

The attachment is a single file named `tunnel`:

```powershell
PS C:\Users\sadik\Documents\HTB-CTF\REV\rev_tunnelmadness> Get-ChildItem -LiteralPath "c:\Users\sadik\Documents\HTB-CTF\REV\rev_tunnelmadness" | Format-List *

Name   : tunnel
Length : 144144
PSIsContainer : False
```

Using WSL’s `file` utility confirmed it is a 64-bit Linux ELF PIE:

```bash
$ file -b /mnt/c/Users/sadik/Documents/HTB-CTF/REV/rev_tunnelmadness/tunnel
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=69bd1f8548e32eed44b53fcd20d7138aecf8449d, for GNU/Linux 3.2.0, not stripped
```

Magic bytes (first 64 bytes) start with `7F 45 4C 46` (ELF):

```powershell
7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 3E 00 01 00 00 00 D0 10 00 00 00 00 00 00 40 00 00 00 00 00 00 00 90 2B 02 00 00 00 00 00 00 00 00 00 40 00 38 00 0B 00 40 00 1E 00 1D 00
```

SHA-256 of the binary:

```powershell
Algorithm : SHA256
Hash      : 58F55828DA6E94C33731837D127F68742AC66DCEA43958080BCF09EEC2AAC29D
Path      : C:\Users\sadik\Documents\HTB-CTF\REV\rev_tunnelmadness\tunnel
```

### Quick string reconnaissance

Strings reveal the user prompt, a success message, and a suspicious `/flag.txt` reference:

```bash
Direction (L/R/F/B/U/D/Q)?
Cannot move that way
Goodbye!
/flag.txt
HTB{fake_flag_for_testing}
You break into the vault and read the secrets within...
```

This indicates:

- The program is interactive and consumes a single character direction.
- A “fake flag” string exists locally (likely a decoy for offline runs).
- The real flag is likely read from `/flag.txt` at runtime on the remote container.

### Binary protections

- PIE: **Present** (reported by `file` as “pie executable”).
- NX/Canary/RELRO: **Not provided** (no `checksec` output was collected).

## 5️⃣ Attack Surface Identification

This is not a memory corruption challenge; the “attack surface” is the game logic exposed through input:

- **User-controlled input:** a single character per move (`L/R/F/B/U/D/Q`).
- **Network endpoint:** TCP service at `94.237.123.236:58120`.
- **Key logic surface:** movement validation and win condition (reaching a goal cell).

Because the move alphabet is small and the program enforces move validity, the practical path to exploitation is to **reverse the maze representation** and compute a valid path offline.

## 6️⃣ Deep Technical Analysis

### High-level control flow (`main`)

`main` maintains a 3D position (three integers on the stack) and loops until the current cell has type `3`:

```asm
0000000000001538 <main>:
...
1569: call   11e3 <prompt_and_update_pos>
...
1571: call   11b5 <get_cell>
1576: cmp    DWORD PTR [rax+0xc],0x3
157a: jne    155c <main+0x24>
...
158d: call   1446 <get_flag>
```

Interpretation:

- The program repeatedly prompts for a direction and updates `(x, y, z)`.
- It maps that position to a cell via `get_cell`.
- It checks `cell.type` at offset `+0xC`. When `type == 3`, it prints the success message and calls `get_flag`.

### Maze indexing (`get_cell`)

`get_cell` computes a pointer into a global `maze` array:

```asm
00000000000011b5 <get_cell>:
11b5: mov    eax,DWORD PTR [rdi]        ; x
...
11c3: mov    edx,DWORD PTR [rdi+0x4]    ; y
...
11ce: mov    edx,DWORD PTR [rdi+0x8]    ; z
...
11d4: shl    rax,0x4                    ; * 16 bytes per cell
11d8: lea    rdx,[rip+0xf01]            ; &maze
11df: add    rax,rdx
11e2: ret
```

The arithmetic corresponds to:

- Grid dimension is `20` in each axis.
- Flattening order is: `index = x*(20*20) + y*20 + z`.
- Each cell is `16` bytes.

### Maze location and size

Symbol table shows:

```bash
00000000000020e0 000000000001f400 R maze
```

So the maze blob begins at virtual address `0x20e0` and is `0x1f400` bytes.

Given `16` bytes per cell, this size matches:

$$
\frac{0x1f400}{16} = 0x1f40 = 8000 = 20^3
$$

### Cell structure

The `.rodata` hexdump around the maze start shows repeating 32-bit integers and aligns with a 16-byte struct:

- `uint32_t x`
- `uint32_t y`
- `uint32_t z`
- `uint32_t type`

Example hexdump excerpt (start of the maze area at `0x20e0`):

```text
0x000020f0 00000000 00000000 01000000 01000000
0x00002100 00000000 00000000 02000000 01000000
0x00002110 00000000 00000000 03000000 01000000
```

Interpreting as little-endian `u32` gives entries like:

- `(x=0, y=0, z=1, type=1)`
- `(x=0, y=0, z=2, type=1)`
- `(x=0, y=0, z=3, type=1)`

### Movement constraints and allowed directions

The prompt function reads a single `%c` and dispatches to movement cases. The important observation is that it checks the target cell’s `type` and refuses moves into `type == 2`:

```asm
1271: call   11b5 <get_cell>
1276: cmp    DWORD PTR [rax+0xc],0x2
127a: je     129a <prompt_and_update_pos+0xb7>
...
129a: puts   "Cannot move that way"
```

From this, we can treat:

- `type == 2` as a wall/blocked cell
- `type == 3` as the goal

## 7️⃣ Vulnerability / Weakness Explanation

**Type:** Logic/design weakness (hard-coded, client-side solvable puzzle)

**Why it exists:**

- The entire 3D maze is embedded in the binary as a contiguous `maze` array.
- The program uses deterministic validation (blocked vs open vs goal) without server-side secret state.

**Why it is exploitable:**

- Once the maze is extracted, the optimal path can be computed offline (e.g., BFS on a 20×20×20 grid).
- The remote service accepts a simple move stream, so replaying the computed path reliably reaches the win condition.

This is typical for CTF RE tasks: the “weakness” is that the challenge logic is fully recoverable from the shipped binary.

## 8️⃣ Exploitation Strategy

1. Identify how the binary checks for a win (`type == 3` in the current cell).
2. Locate the maze blob (`maze` symbol at address `0x20e0`, size `0x1f400`).
3. Parse the maze into a 3D grid of cell types.
4. Run BFS from start `(0,0,0)` to any cell with `type == 3`, avoiding `type == 2`.
5. Convert the BFS predecessor map into a direction string using the service’s alphabet (`L/R/F/B/U/D`).
6. Send the direction sequence to the remote service and read the flag.

## 9️⃣ Exploit Implementation

A reproducible solver/exploit script is provided as `solve_tunnel.py`.

### Key implementation points

- It parses ELF section headers to locate `.rodata` and convert the virtual address `0x20e0` into a file offset.
- It reads the maze blob and unpacks each cell as four little-endian `uint32` values `(x, y, z, type)`.
- It builds a `types[]` array indexed as `x*(20*20) + y*20 + z`.
- It performs BFS and reconstructs the move string.
- It connects to `ip:port` and sends one move per line.

### Minimal code excerpts

Maze extraction (virtual address → file offset):

```python
MAZE_ADDR = 0x20E0
MAZE_SIZE = 0x1F400

rodata = next((s for s in sections if s.name == '.rodata'), None)
maze_off = rodata.offset + (MAZE_ADDR - rodata.addr)
maze = blob[maze_off:maze_off + MAZE_SIZE]
```

BFS pathfinding (avoid `type == 2`, stop at `type == 3`):

```python
if types[nx * (DIM * DIM) + ny * DIM + nz] == 2:
    continue

if types[x * (DIM * DIM) + y * DIM + z] == 3:
    goal = (x, y, z)
    break
```

Remote interaction:

```python
for ch in path:
    f.write(ch.encode() + b'\n')
    out += read_some()
```

### Reproduction commands

Compute the move sequence locally:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/sadik/Documents/HTB-CTF/REV/rev_tunnelmadness; python3 solve_tunnel.py --elf ./tunnel --print-path'
```

Send the sequence to the remote service and print the response:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/sadik/Documents/HTB-CTF/REV/rev_tunnelmadness; python3 solve_tunnel.py --elf ./tunnel --ip 94.237.123.236 --port 58120 | tail -n +1'
```

## 🔟 Flag Retrieval

The computed path was:

```text
UUURFURURRFRRFFUUFURRUFUFFRFUFUUUUFFRRUUUFURFDFFUFFRRRRRFRR
```

Its length (character count) was:

```text
60
```

Running the exploit against the remote service produced the success banner and the real flag:

```text
... You break into the vault and read the secrets within...
HTB{tunn3l1ng_ab0ut_in_3d_b4bf7e204ccf1de1680a504069e6f13c}
```

## 1️⃣1️⃣ Mitigation / Lessons Learned (Optional but Professional)

For a real system (not a CTF), the core issue is relying on client-side verifiable logic with all state embedded in a distributable artifact.

Practical mitigations:

- Move secret state (maze layout / goal condition) to the server side.
- If the client must render a maze, avoid shipping the full solved-state; generate per-session mazes server-side.
- Rate-limit or detect automated input to reduce scripted replay.

## 1️⃣2️⃣ Conclusion

TunnelMadness is a reverse engineering task that hides a 3D maze directly in the binary.

By identifying the maze structure and win condition, extracting the embedded grid from `.rodata`, and running BFS to compute a valid move sequence, we can reliably reach the goal state remotely and retrieve the flag.
