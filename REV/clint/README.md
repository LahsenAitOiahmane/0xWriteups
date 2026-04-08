# Krampus Drone Link (Reverse Engineering) — Writeup

This challenge provides a stripped Linux ELF client binary (`client`) that talks to a remote drone-control endpoint:

```bash
nc ctf.csd.lol 6969
```

Goal: reverse the client’s protocol and use it to navigate the drone graph until the server returns the flag `csd{...}`.

---

## 1) Quick recon

The binary is a tiny ELF64 PIE and imports only basic networking + libc functions (`connect`, `send`, `recv`, `strncmp`, etc.).

Notable strings:

- `KMPS` (not in `.rodata`, but visible in disassembly)
- `CUR: %u`
- `csd{`
- `HELLO`

In `main`, after connecting, it calls a single function (shown as `sub_13AD` in IDA) that implements the entire client protocol.

---

## 2) Protocol reverse engineering

Inside `sub_13AD`, the client sends and receives framed messages.

### Frame format

All messages start with an 8-byte header:

- `magic` (4 bytes): ASCII `KMPS`
- `version` (1 byte): `0x01`
- `command` (1 byte): varies
- `length` (2 bytes, little-endian): total frame length including header

C struct equivalent:

```c
struct Header {
  char magic[4];   // "KMPS"
  uint8_t ver;     // 1
  uint8_t cmd;     // command
  uint16_t len;    // total bytes (header + payload)
};
```

The binary also contains helper loops that ensure **exact** send/recv of a requested length (i.e., `send_all` / `recv_all`).

### Commands

From disassembly + live probing, the commands used are:

- **cmd = 1 (HELLO)**
  - Client sends an empty frame (`len = 8`).
  - Server responds with a 16-byte frame (`len = 16`) whose payload begins with `HELLO`.

- **cmd = 2 (STATE / NEIGHBORS)**
  - Client sends an empty frame.
  - Server responds with a frame containing:
    - `cur` (uint32 little-endian): current node ID
    - `n` (uint32 little-endian): number of neighbor options
    - `n` neighbors, each `uint32`

- **cmd = 3 (MOVE)**
  - Client sends an 8-byte payload:
    - `to` (uint32)
    - `check` (uint32)
  - The client computes: `check = to ^ cur`.
  - Server replies with a 4-byte payload: new `cur` (uint32). (In practice it equals `to` if valid.)

- **cmd = 4 (FLAG / GOAL INFO)**
  - Client sends an empty frame.
  - If not at the goal, server returns a string like:
    - `Reach 0xdd209dce to get the flag.`
  - If at the goal node, server returns the flag string starting with `csd{...}`.

---

## 3) Solving strategy

The server exposes a graph traversal problem:

- You start at some `cur`.
- `cmd=2` gives you the neighbor list.
- `cmd=3` lets you move to one of those neighbors (with a simple XOR check).
- `cmd=4` tells you the target node (hex) you must reach.

A key observation from testing: after moving from `A -> B`, node `A` appears in `B`’s neighbor list. That means the graph edges are effectively reversible, so you can safely do a standard DFS with backtracking.

The provided solver [solve.py](solve.py):

1. Handshakes with `cmd=1`.
2. Calls `cmd=4` once to extract the target node ID.
3. Repeatedly:
   - calls `cmd=2` to get neighbors,
   - chooses an unvisited neighbor (sorted by a small heuristic),
   - moves with `cmd=3` using `check = to ^ cur`,
   - backtracks to the parent node when a node is exhausted.
4. Once `cur == target`, calls `cmd=4` again and prints the flag.

---

## 4) How to run

This workspace is on Windows, but the binary is Linux ELF, so run via WSL.

From PowerShell:

```powershell
wsl -e bash -lc 'cd /mnt/c/Users/sadik/Downloads/clint; python3 solve.py'
```

Expected output is the flag:

```text
csd{...}
```

---

## 5) Notes

- The solver is intentionally minimal and only implements what the reversed protocol requires.
- The server limits connection time, so the solver avoids unnecessary round-trips and retries the whole session a few times if needed.
