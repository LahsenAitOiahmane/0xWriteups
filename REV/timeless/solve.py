#!/usr/bin/env python3

import ctypes
import re
import socket
import sys
import time

HOST = "challs.insec.club"
PORT = 40005
PAYLOAD_HEX = "d8a5d981d8aad98ed8ad20d98ad98ed8a720d8b3d990d985d992d8b3d990d985"

try:
    LIBC = ctypes.CDLL("libc.so.6")
except OSError:
    LIBC = ctypes.CDLL("libc.dylib")


def read_until(sock: socket.socket, marker: bytes, timeout_sec: float = 20.0) -> bytes:
    data = b""
    end_time = time.time() + timeout_sec
    while marker not in data and time.time() < end_time:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            pass
    return data


def parse_initial_regs(text: str) -> list[int]:
    pat = r"INITIAL REGS: R1:([0-9A-Fa-f]+) R2:([0-9A-Fa-f]+) R3:([0-9A-Fa-f]+) R4:([0-9A-Fa-f]+) R5:([0-9A-Fa-f]+)"
    m = re.search(pat, text)
    if not m:
        raise ValueError("Could not parse INITIAL REGS line")
    return [int(x, 16) for x in m.groups()]


def find_seed(initial_regs: list[int], now_ts: int, window: int = 86400) -> int:
    for delta in range(window + 1):
        candidates = [now_ts + delta] if delta == 0 else [now_ts + delta, now_ts - delta]
        for seed in candidates:
            LIBC.srand(seed)
            seq = [LIBC.rand() % 255 for _ in range(5)]
            if seq == initial_regs:
                return seed
    raise ValueError("Seed not found in search window")


def build_reroll_plan(seed: int, regs: list[int]) -> tuple[str, int]:
    LIBC.srand(seed)
    for _ in range(5):
        LIBC.rand()

    current = regs[:]
    commands: list[str] = []
    rerolls = 0

    while any(v != 0 for v in current):
        nxt = LIBC.rand() % 255
        idx = next(i for i, v in enumerate(current) if v != 0)
        commands.append("2")
        commands.append(str(idx + 1))
        current[idx] = nxt
        rerolls += 1

        if rerolls > 200000:
            raise RuntimeError("Unexpectedly large reroll count")

    commands.append("1")
    return "\n".join(commands) + "\n", rerolls


def extract_flag(text: str) -> str | None:
    m = re.search(r"INSEC\{[^}]+\}", text)
    return m.group(0) if m else None


def solve_once() -> str:
    payload = bytes.fromhex(PAYLOAD_HEX) + b"\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2.0)
        sock.connect((HOST, PORT))

        banner = read_until(sock, b"> ", timeout_sec=15.0)
        banner_text = banner.decode("utf-8", errors="ignore")

        initial = parse_initial_regs(banner_text)
        print(f"Initial regs: {initial}")

        seed = find_seed(initial, int(time.time()), window=86400)
        print(f"Recovered seed: {seed}")

        cmd_stream, rerolls = build_reroll_plan(seed, initial)
        print(f"Planned rerolls: {rerolls}")

        sock.sendall(cmd_stream.encode())
        pre_input = read_until(sock, b"Input:", timeout_sec=20.0)
        if b"Input:" not in pre_input:
            raise RuntimeError("Did not receive input prompt")

        sock.sendall(payload)

        # Gather trailing output until timeout.
        tail = b""
        end_time = time.time() + 5.0
        while time.time() < end_time:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                tail += chunk
            except socket.timeout:
                break

    full = (pre_input + tail).decode("utf-8", errors="ignore")
    flag = extract_flag(full)
    if not flag:
        raise RuntimeError(f"Flag not found. Output tail:\n{full[-600:]}")

    print(flag)
    return flag


def main() -> None:
    for attempt in range(1, 4):
        try:
            print(f"Attempt {attempt}")
            solve_once()
            return
        except Exception as e:
            print(f"Attempt {attempt} failed: {e}")
            time.sleep(1)

    sys.exit(1)


if __name__ == "__main__":
    main()
