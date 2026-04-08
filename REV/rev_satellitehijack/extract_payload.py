import pathlib

LIB = pathlib.Path("library.so")
START = 0x11A9
SIZE = 0x1000
KEY = 0x2A
OUT = pathlib.Path("payload_dec.bin")

b = LIB.read_bytes()
chunk = bytearray(b[START:START+SIZE])
if len(chunk) != SIZE:
    raise SystemExit(f"Expected {SIZE} bytes, got {len(chunk)}")

for i in range(len(chunk)):
    chunk[i] ^= KEY

OUT.write_bytes(chunk)
print(f"Wrote {OUT} ({len(chunk)} bytes), xor key=0x{KEY:02x}, from {LIB} offset 0x{START:x}")

# Quick ASCII scan for embedded strings
ascii_runs = []
run = bytearray()
for by in chunk:
    if 32 <= by <= 126:
        run.append(by)
    else:
        if len(run) >= 4:
            ascii_runs.append(run.decode('ascii', errors='ignore'))
        run.clear()
if len(run) >= 4:
    ascii_runs.append(run.decode('ascii', errors='ignore'))

hits = [s for s in ascii_runs if any(k in s for k in ("HTB{", "flag", "FLAG", "code", "CODE", "sat", "SAT"))]
print("Interesting ASCII strings in decrypted payload:")
for s in hits[:80]:
    print(s)
