import re
import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional

HOST = "ctf.csd.lol"
PORT = 6969
MAGIC = b"KMPS"


def recvall(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def sendmsg(sock: socket.socket, cmd: int, payload: bytes = b"") -> None:
    hdr = struct.pack("<4sBBH", MAGIC, 1, cmd, 8 + len(payload))
    sock.sendall(hdr + payload)


def recvmsg(sock: socket.socket) -> Tuple[int, int, bytes]:
    hdr = recvall(sock, 8)
    magic, ver, cmd, length = struct.unpack("<4sBBH", hdr)
    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}")
    if ver != 1:
        raise ValueError(f"bad version {ver}")
    body = recvall(sock, length - 8) if length > 8 else b""
    return cmd, length, body


def hello(sock: socket.socket) -> None:
    sendmsg(sock, 1)
    recvmsg(sock)  # ignore payload (e.g., HELLO)


def get_target(sock: socket.socket) -> int:
    sendmsg(sock, 4)
    cmd, length, body = recvmsg(sock)
    text = body.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    m = re.search(r"0x([0-9a-fA-F]+)", text)
    if not m:
        raise ValueError(f"could not parse target from: {text!r}")
    return int(m.group(1), 16)


def get_state(sock: socket.socket) -> Tuple[int, List[int]]:
    sendmsg(sock, 2)
    cmd, length, body = recvmsg(sock)
    if len(body) < 8:
        raise ValueError(f"state body too short: {len(body)}")
    cur, n = struct.unpack("<II", body[:8])
    opts_bytes = body[8:]
    # Server usually includes options inline in this response; if not, read the remainder.
    need = n * 4
    if len(opts_bytes) < need:
        opts_bytes += recvall(sock, need - len(opts_bytes))
    opts = list(struct.unpack(f"<{n}I", opts_bytes[:need])) if n else []
    return cur, opts


def move(sock: socket.socket, cur: int, to: int) -> int:
    payload = struct.pack("<II", to, to ^ cur)
    sendmsg(sock, 3, payload)
    cmd, length, body = recvmsg(sock)
    if len(body) < 4:
        raise ValueError(f"move body too short: {len(body)}")
    (newcur,) = struct.unpack("<I", body[:4])
    return newcur


def get_flag(sock: socket.socket) -> str:
    sendmsg(sock, 4)
    cmd, length, body = recvmsg(sock)
    text = body.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return text


@dataclass
class Frame:
    node: int
    neighbors: List[int]
    idx: int = 0


def heuristic(node: int, target: int) -> int:
    # Cheap heuristic: smaller XOR distance tends to cluster related nodes.
    return node ^ target


def solve_once(host: str = HOST, port: int = PORT, max_moves: int = 20000) -> Optional[str]:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        hello(sock)
        target = get_target(sock)

        cur, neighbors = get_state(sock)
        visited = {cur}

        neighbors = sorted(neighbors, key=lambda x: heuristic(x, target))
        stack: List[Frame] = [Frame(cur, neighbors)]

        moves = 0
        while moves < max_moves:
            cur = stack[-1].node
            if cur == target:
                flag = get_flag(sock)
                if flag.startswith("csd{"):
                    return flag
                # If the service ever changes the message, still return it for visibility.
                return flag

            frame = stack[-1]
            while frame.idx < len(frame.neighbors) and frame.neighbors[frame.idx] in visited:
                frame.idx += 1

            if frame.idx >= len(frame.neighbors):
                if len(stack) == 1:
                    return None
                parent = stack[-2].node
                newcur = move(sock, cur, parent)
                moves += 1
                stack.pop()
                if newcur != parent:
                    # Protocol expects newcur == destination
                    return None
                continue

            nxt = frame.neighbors[frame.idx]
            frame.idx += 1

            newcur = move(sock, cur, nxt)
            moves += 1
            if newcur != nxt:
                return None

            cur2, neighbors2 = get_state(sock)
            if cur2 != nxt:
                return None

            visited.add(cur2)
            neighbors2 = sorted(neighbors2, key=lambda x: heuristic(x, target))
            stack.append(Frame(cur2, neighbors2))

    return None


def main() -> None:
    for attempt in range(1, 6):
        flag = solve_once(max_moves=20000)
        if flag:
            print(flag)
            return
        print(f"attempt {attempt}: not found (retrying)")


if __name__ == "__main__":
    main()
