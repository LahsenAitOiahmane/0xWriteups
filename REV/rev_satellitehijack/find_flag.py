import pathlib

p = pathlib.Path("payload_dec.bin")
b = p.read_bytes()
idx = b.find(b"HTB{")
if idx < 0:
    raise SystemExit("HTB{ not found")

window = b[idx:idx+200]
print(f"Found 'HTB{{' at offset 0x{idx:x} ({idx})")

# Hex dump
for i in range(0, len(window), 16):
    chunk = window[i:i+16]
    hexpart = " ".join(f"{x:02x}" for x in chunk)
    asciipart = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
    print(f"{idx+i:08x}: {hexpart:<47}  {asciipart}")

# Try a few reconstructions
candidates = []

# 1) Raw printable run
raw = bytearray()
for by in window:
    if 32 <= by <= 126:
        raw.append(by)
    else:
        if raw:
            break
candidates.append(("raw_printable_prefix", raw.decode('ascii', errors='ignore')))

# 2) Strip NULs
strip_nul = bytes(x for x in window if x != 0)
# stop at first '}' if present
end = strip_nul.find(b"}")
if end != -1:
    strip_nul = strip_nul[:end+1]
candidates.append(("strip_nul", strip_nul.decode('ascii', errors='ignore')))

# 3) Take even/odd bytes (common for UTF-16LE-like storage)
for which, name in [(0, "even_bytes"), (1, "odd_bytes")]:
    sub = window[which::2]
    end = sub.find(b"}")
    if end != -1:
        sub = sub[:end+1]
    candidates.append((name, sub.decode('ascii', errors='ignore')))

print("\nCandidate reconstructions:")
for name, val in candidates:
    print(f"- {name}: {val}")
