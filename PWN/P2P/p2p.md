# p2p — Professional Write‑Up (Journey to the Flag)

## 1) Challenge overview
The service presents itself as an “ultimate P2P secure chat” reachable over TCP:

- Target: `p2p.putcyberdays.pl:8080`
- Interaction: menu-driven (like `nc p2p.putcyberdays.pl 8080`)

Provided artifacts in the workspace:

- [protocol.h](protocol.h) — the protocol definition
- [base_client](base_client) — a reference client binary
- [server](server) — a server binary implementing the same logic as the remote

Goal: obtain the flag from the remote service.

---

## 2) First recon: what the remote expects
Connecting with netcat shows a standard menu:

```
=== P2P SECURE CHAT ===
1. Send Message
2. Read Conversation
3. Exit
Select >
```

Trying to “Send Message” with plain text quickly reveals that after entering a username, the server expects a **binary packet**, not a human-readable message, and it enforces:

- a magic constant check (rejects non-official clients)
- a checksum check (integrity enforcement)
- a maximum message size (allocation limit)

These error strings were later confirmed directly in the local `server` binary via `strings`.

---

## 3) Protocol from protocol.h: the 12-byte header
[protocol.h](protocol.h) defines a packed header:

- `magic` (32-bit) — must equal `0xCAFEBABE`
- `data_len` (32-bit) — payload length
- `checksum` (32-bit) — checksum over the payload

So the on-wire layout is:

```
struct PacketHeader {
  uint32_t magic;
  uint32_t data_len;
  uint32_t checksum;
};
// followed by data_len bytes of payload
```

The implementation uses native little-endian on x86-64, so the packet is sent as little-endian 32-bit integers.

---

## 4) Reversing base_client: exact client flow + checksum
### 4.1 Client flow (important for sequencing)
Disassembling `base_client` `main()` shows the exact sequence it uses:

1. Connect to `ip:port`
2. Read and print the server banner/menu
3. Read the menu choice from stdin (string), write it to the socket
4. If the choice is `1`:
   - read the username prompt
   - read username from stdin and write it to the socket
   - read the “send packet now…” prompt
   - read the message from stdin
   - send a binary packet: header + payload

This matters because the server mixes text input (menu + username) and raw binary (packet). If you send bytes at the wrong time, parsing desynchronizes.

### 4.2 Checksum algorithm
Both `base_client` and `server` include `calculate_checksum()` with identical logic.

Reconstructed algorithm (32-bit arithmetic):

- Initialize: `chk = 0x12345678`
- For each payload byte `b` at index `i`:
  - `chk ^= (b << (i & 3))`
  - `chk = rol32(chk, 5)`

This checksum is computed over the **raw payload bytes only** (not including the header).

---

## 5) Reversing server: what happens to our packet
`server` is very small and not stripped, so symbols guide the analysis:

- `handle_connection()` — prints menu and dispatches options
- `handle_send_message()` — reads username, reads packet header + payload, verifies checksum, calls `save_message()`
- `save_message()` — copies message and appends it to `/tmp/chat_history.txt`

Key observations from `handle_send_message()`:

- Reads username using `scanf("%31s", username)`
- Reads header with `read(0, &hdr, 12)`
- Validates:
  - `hdr.magic == 0xCAFEBABE`
  - `hdr.data_len <= 0x400`
- Allocates `malloc(hdr.data_len)`
- Reads exactly `data_len` bytes into the heap buffer
- Verifies checksum: `calculate_checksum(buf, data_len) == hdr.checksum`
- Calls `save_message(username, buf, data_len)`

So: if we can compute the checksum correctly, we can fully control `data_len` (up to 1024) and the payload bytes.

---

## 6) The bug: stack overflow in save_message()
`save_message()` contains the critical vulnerability:

- It has a fixed-size stack buffer at `[rbp-0x50]` (80 bytes)
- It does `memcpy(stack_buf, heap_msg, data_len)`
- `data_len` comes from the attacker-controlled header, and is allowed up to `0x400`

There is **no bounds check** on `memcpy`, so a payload longer than 80 bytes overwrites:

- saved `rbp`
- return address
- and more stack state

This is a classic stack-based buffer overflow.

### 6.1 Why exploitation is straightforward
A quick binary hardening check explains the ease:

- No stack canary (so return address overwrite is not detected)
- NX enabled (so we don’t inject shellcode)
- No PIE (fixed code addresses; ROP/ret2win is stable)

---

## 7) The “ret2win” primitive already exists: useful_gadgets()
The server contains a helper function named `useful_gadgets()`:

- It loads a static string pointer to `"cat flag.txt"`
- It calls `system("cat flag.txt")`

So the winning strategy is:

1. Overflow the return address in `save_message()`
2. Redirect execution into `useful_gadgets()`
3. Let it print the flag to the socket

### 7.1 Stack alignment detail
On amd64 System V ABI, stack alignment can matter when calling libc functions.
Because we reach `useful_gadgets()` via `ret` (not `call`), the stack may be misaligned by 8 bytes.

A common reliable fix is to place a single `ret` gadget first (a “stack alignment ret”), then jump into the real gadget/function.

---

## 8) Exploit construction
### 8.1 Offset to RIP
In `save_message()`:

- stack buffer begins at `rbp-0x50`
- return address is at `rbp+0x8`

So the offset from the start of the copied buffer to the saved return address is:

- `0x50 + 0x8 = 0x58`

### 8.2 ROP / control-flow chain
Payload structure:

- `b"A" * 0x58`
- `ret` gadget (alignment)
- `useful_gadgets` address (calls `system("cat flag.txt")`)
- a safe return address back into `handle_send_message` after `save_message` returns

All addresses come from the local `server` binary (non-PIE):

- `ret` alignment gadget: `0x40121d`
- `useful_gadgets`: `0x401206`
- “return to normal flow” in `handle_send_message`: `0x401554`

### 8.3 Full packet
The final on-wire message is:

- 12-byte header: `pack("<III", MAGIC, data_len, checksum)`
- followed by `data_len` bytes of payload

Where `checksum = calculate_checksum(payload)`.

---

## 9) Getting the flag (remote)
Once the payload is sent in the right place in the menu flow (option 1 → username → packet), the server:

- accepts the packet (magic + checksum OK)
- overflows in `save_message()`
- returns into `useful_gadgets()`
- executes `system("cat flag.txt")`

Resulting output includes the flag:

```
putcCTF{W1ill_U_B3_my_friend?}
```

---

## 10) Reference exploit script
A clean reproducible script is included as [solve_p2p.py](solve_p2p.py).

Run it:

```
python3 solve_p2p.py
```

It:

- follows the exact menu/username/packet sequence
- computes the correct checksum
- triggers the overflow and prints the server response (including the flag)

---

## 11) Final flag
`putcCTF{W1ill_U_B3_my_friend?}`
