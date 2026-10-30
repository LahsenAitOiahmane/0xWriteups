"""Pure-python MD5-crypt + candidate sweep for mort1cia's hash."""
import hashlib
import itertools
import string

SALT = b"de4df4ce"
TARGET = "$1$de4df4ce$1pZYBMWLPXg1tZo6pke20"
MAGIC = b"$1$"
ITOA64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def md5crypt(pw: bytes, salt: bytes = SALT) -> str:
    ctx = hashlib.md5(pw + MAGIC + salt)
    alt = hashlib.md5(pw + salt + pw).digest()
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
            c.update(salt)
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
    return "$1$" + salt.decode() + "$" + out.decode()


if __name__ == "__main__":
    # verify against the openssl ground truth from earlier
    probe = md5crypt(b"Sk4t3rB0y_S1nce_2011")
    print("self-test :", probe)
    print("openssl   : $1$de4df4ce$UHK.oW4FQLqoAsg6znrNq/")
    assert probe == "$1$de4df4ce$UHK.oW4FQLqoAsg6znrNq/", "md5crypt implementation mismatch"
    print("md5crypt OK\n")


def leet_variants(w):
    out = {w, w[:1].upper() + w[1:], w.upper(), w.lower()}
    lw = w
    for a, b in (("a", "4"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "5"), ("t", "7")):
        lw = lw.replace(a, b).replace(a.upper(), b)
    out.add(lw)
    out.add(w.replace("o", "0").replace("e", "3").replace("i", "1")
            .replace("a", "4").replace("s", "5").replace("t", "7"))
    return out


bases = ["mort1cia", "morticia", "addams", "ghosttown", "ghost", "town", "crypt",
         "osint", "morticiaaddams", "addamsfamily", "gomez", "pugsley", "wednesday",
         "thing", "deephax", "gh0st404", "sunstalker", "lilith", "spookyboi",
         "charon", "deadface", "dctf", "hostbusters", "welles", "serena", "cronin",
         "leverage", "scraper", "kingmaker", "shepherd", "shepherd2026", "ghosty",
         "ghosttown2026", "w3ll3s", "r1s1ng", "dark", "witch", "spooky", "boo"]
suffixes = ["", "1", "12", "123", "1234", "2024", "2025", "2026", "!", "!!", "007",
            "_1", "_123", "!1", "#1", "69", "13", "666", "404", "_!", "_pw", "pw",
            "_2026", "2026!", "_007", "!!!"]
seps = ["", "_", "-", ".", "@", "1337", "!", "$", "x"]

checked = set()
hits = []


def test(pw):
    if not pw or pw in checked or len(pw) > 64:
        return
    checked.add(pw)
    global _TARGET_HIT
    if md5crypt(pw.encode()) == TARGET:
        hits.append(pw)


for b in bases:
    for v in leet_variants(b):
        test(v)
        for s in suffixes:
            test(v + s)

for a, b in itertools.product(bases[:20], bases[:20]):
    if a != b:
        for sep in seps:
            test(a + sep + b)
            for suf in suffixes[:10]:
                test(a + sep + b + suf)

print(f"tested {len(checked)} candidates; HITS: {hits}")
