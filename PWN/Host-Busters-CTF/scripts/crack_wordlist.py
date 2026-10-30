"""Sweep top-100k + rule mutations against mort1cia's md5crypt hash."""
import hashlib
import sys
import time

SALT = b"de4df4ce"
TARGET = "$1$de4df4ce$1pZYBMWLPXg1tZo6pke20"
MAGIC = b"$1$"
ITOA64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def md5crypt(pw: bytes) -> str:
    ctx = hashlib.md5(pw + MAGIC + SALT)
    alt = hashlib.md5(pw + SALT + pw).digest()
    pl = len(pw)
    while pl > 0:
        ctx.update(alt[:min(pl, 16)])
        pl -= 16
    i = len(pw)
    while i:
        ctx.update(b"\x00" if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if i & 1 else final)
        if i % 3:
            c.update(SALT)
        if i % 7:
            c.update(pw)
        c.update(final if i & 1 else pw)
        final = c.digest()
    out = b""
    for a, b_, cc in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        w = (final[a] << 16) | (final[b_] << 8) | final[cc]
        for shift in (0, 6, 12, 18):
            idx = (w >> shift) & 63
            out += ITOA64[idx:idx + 1]
    w = final[11]
    for shift in (0, 6):
        idx = (w >> shift) & 63
        out += ITOA64[idx:idx + 1]
    return "$1$" + SALT.decode() + "$" + out.decode()


seen = set()
hits = []


def test(pw):
    if not pw or pw in seen or len(pw) > 64 or "\n" in pw:
        return
    seen.add(pw)
    if md5crypt(pw.encode("utf-8", "replace")) == TARGET:
        hits.append(pw)
        print("!! HIT:", pw, flush=True)


words = []
with open("C:/Users/sadik/WorkBuddy AI/2026-10-17-23-02-39/top100k.txt", encoding="utf-8", errors="replace") as fh:
    words = [l.rstrip("\n") for l in fh]

t0 = time.time()
for w in words:
    test(w)
print(f"pass1 raw {len(words)} words in {time.time()-t0:.0f}s", flush=True)

# rule mutations
def mutate(w):
    yield w
    yield w.capitalize()
    yield w.upper()
    yield w + "1"
    yield w + "123"
    yield w + "1234"
    yield w + "!"
    yield w + "@"
    yield w + "#"
    yield w + "2024"
    yield w + "2025"
    yield w + "2026"
    yield w + "!"
    yield w[:1].upper() + w[1:] + "1"
    yield w + "_1"
    yield w + "_123"
    yield w.capitalize() + "1"
    yield w.capitalize() + "123"
    yield w.capitalize() + "!"
    yield w + "123456"
    yield w + "007"
    yield w + "69"

t0 = time.time()
for w in words[:30000]:
    for m in mutate(w):
        test(m)
print(f"pass2 mutations done in {time.time()-t0:.0f}s", flush=True)
print("total tested:", len(seen), "hits:", hits, flush=True)
