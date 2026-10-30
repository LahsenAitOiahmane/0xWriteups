"""Focused sweep: mort1cia password from the Halloween-princess photo."""
import hashlib

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


cores = ["tiara", "princess", "pink", "pinkprincess", "princesstiara", "pinktiara",
         "tiaraprincess", "disney", "disneyprincess", "belle", "aurora", "cinderella",
         "wand", "magicwand", "halloween", "pumpkin", "pinkdress", "dress",
         "littleprincess", "prettyprincess", "princess2015", "tiara2015",
         "halloween2015", "pinkprincess2015", "disneyprincess2015",
         "princessdiaries", "princessbride", "glassslipper", "slipper",
         "princess2011", "princess2016", "princess2014", "princess2013",
         "princess2012", "princess2026", "princess101", "princess1",
         "mort1cia", "morticia", "mort1cia2015", "princessmort1cia",
         "onceupon", "fairytale", "happilyeverafter", "offwiththeirheads",
         "queen", "crown", "coronation", "g0th", "gothicprincess", "blackprincess",
         "t1ara", "pr1ncess", "p1nk", "d1sney", "h4lloween", "t1ar4", "c0rwn",
         "princessdiana", "diana", "waltz", "cinderella2015", "sleepingbeauty"]

suffixes = ["", "1", "2", "01", "123", "1234", "!", "!!", "007", "2015", "2011",
            "16", "17", "18", "21", "23", "31", "10", "25", "69", "00", "07",
            "_1", "_123", "_2015", "!1", "!!1", "#1", "$", "_pw", "pw", "_pw1",
            "2015!", "2011!", "!!!", "?", "_", "_01"]
seps = ["", "_", "-", ".", "@", "!"]
prefixes = ["", "the", "my", "its", "a"]

seen, hits = set(), []


def test(pw):
    if not pw or pw in seen or len(pw) > 64:
        return
    seen.add(pw)
    if md5crypt(pw.encode()) == TARGET:
        hits.append(pw)
        print("!! HIT:", pw, flush=True)


def variants(s):
    yield s
    yield s.capitalize()
    yield s.upper()
    yield s[:1].upper() + s[1:]
    lw = s
    for a, b in (("a", "4"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "5"), ("t", "7")):
        lw = lw.replace(a, b).replace(a.upper(), b)
    yield lw
    yield lw.capitalize()


for c in cores:
    for v in variants(c):
        test(v)
        for sfx in suffixes:
            test(v + sfx)
        for pfx in prefixes:
            for sep in seps:
                test(pfx + sep + v)

# word pairs
pairs = [("pink", "tiara"), ("pink", "princess"), ("disney", "princess"),
         ("magic", "wand"), ("pink", "dress"), ("little", "princess"),
         ("princess", "tiara"), ("tiara", "2015"), ("pink", "tiara2015"),
         ("disney", "princess2015"), ("princess", "halloween"), ("cinderella", "2015"),
         ("princess", "diaries"), ("pretty", "princess"), ("dark", "princess"),
         ("gothic", "princess"), ("princess", "crown"), ("glass", "slipper"),
         ("halloween", "princess"), ("princess", "pumpkin"), ("mort1cia", "princess")]
for a, b in pairs:
    for sep in seps + ["", "_"]:
        for sfx in ["", "1", "2015", "!", "2011", "123"]:
            test(a + sep + b + sfx)
            test(a.capitalize() + sep + b.capitalize() + sfx)

print(f"tested {len(seen)} candidates; HITS: {hits}")
