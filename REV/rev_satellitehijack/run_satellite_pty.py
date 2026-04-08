import os
import pty
import select
import sys
import time

WORKDIR = "/mnt/c/Users/sadik/Documents/HTB-CTF/REV/rev_satellitehijack"


def run_once(payload: str, enable_env: bool, timeout_s: float = 3.0) -> str:
    os.chdir(WORKDIR)

    pid, master_fd = pty.fork() # type: ignore
    if pid == 0:
        # Child: exec satellite with env var enabled.
        if enable_env:
            os.environ["SAT_PROD_ENVIRONMENT"] = "1"
        else:
            os.environ.pop("SAT_PROD_ENVIRONMENT", None)
        os.execv("./satellite", ["./satellite"])

    out = bytearray()
    sent = False
    start = time.time()

    try:
        while time.time() - start < timeout_s:
            r, _, _ = select.select([master_fd], [], [], 0.05)
            if r:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk

            if (not sent) and (b"READY TO TRANSMIT" in out and b">" in out):
                os.write(master_fd, payload.encode("utf-8", errors="ignore"))
                sent = True

        # Give it a moment to react after sending
        end_wait = time.time() + 0.5
        while time.time() < end_wait:
            r, _, _ = select.select([master_fd], [], [], 0.05)
            if not r:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

        # Best-effort cleanup
        try:
            os.kill(pid, 9)
        except OSError:
            pass

    return out.decode("utf-8", errors="replace")


def main() -> int:
    payloads = [
        "test\n",
        "START\n",
    ]

    for p in payloads:
        print("== RUN (pty) no env payload ==")
        print(repr(p))
        print(run_once(p, enable_env=False))

        print("== RUN (pty) SAT_PROD_ENVIRONMENT=1 payload ==")
        print(repr(p))
        print(run_once(p, enable_env=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
