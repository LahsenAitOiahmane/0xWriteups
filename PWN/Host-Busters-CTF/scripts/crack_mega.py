"""Mega sweep v2: photo elements + identity + multi-word + date formats."""
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


def casevars(s):
    yield s
    yield s.capitalize()
    yield s.upper()
    lw = s
    for a, b in (("a", "4"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "5"), ("t", "7")):
        lw = lw.replace(a, b).replace(a.upper(), b)
    yield lw
    yield lw.capitalize()


TAILS = ["", "1", "2", "3", "01", "12", "123", "1234", "007", "2015", "2016",
         "2011", "2026", "!", "!!", "!!!", "?", "_", ".", "!1", "_1", "_123",
         "_2015", "2015!", "2011!", "69", "13", "31", "10", "25", "00", "07",
         "101", "111", "222", "444", "55", "77", "88", "99", "_pw", "pw",
         "_the", "x", "X", "7", "9", "5", "4", "8", "6", "11", "22", "33"]

# single cores
CORES = [
    # photo elements
    "tiara", "princess", "pink", "pinkprincess", "tiaraprincess", "pinktiara",
    "disney", "disneyprincess", "belle", "aurora", "princessaurora", "cinderella",
    "cinderella2015", "sleepingbeauty", "snowwhite", "rapunzel", "tiana", "merida",
    "jasmine", "mulan", "ariel", "moana", "pocahontas", "wand", "magicwand",
    "fairytale", "fairytaleprincess", "onceuponatime", "happilyeverafter",
    "glassslipper", "slipper", "gown", "dress", "pinkdress", "crown",
    "princesscrown", "queen", "princesspeach", "peach", "mario",
    # halloween
    "halloween", "halloween2015", "trickortreat", "hocuspocus", "spooky",
    "pumpkin", "jackolantern", "vampire", "witch", "ghost", "boo", "sweettooth",
    "candy", "solo", "redcup", "cowboy", "catwoman", "cat",
    # her identity
    "mort1cia", "morticia", "morticiaaddams", "addams", "addamsfamily",
    "gomez", "wednesday", "pugsley", "thing", "unclefester", "fester", "lurch",
    "gothic", "goth", "gothicprincess", "blackprincess", "darkprincess",
    "vampireprincess", "black", "blackcat", "raven", "crow", "widow", "blackwidow",
    "vamp", "dracula", "funeral", "grim", "reaper", "mourning", "velvet", "lace",
    "g0th", "m0rt1c1a", "v4mp1r3",
    # dates
    "20151031", "10312015", "103115", "10312015halloween", "halloween1015",
    "halloween1031", "october31", "31october",
    # misc 2015
    "classof2015", "2015", "2011", "gary", "sourdough", "garythestarter",
]

# multi-word phrases (with space preserved)
PHRASES = [
    "pink princess", "pink princess 2015", "princess 2015", "disney princess",
    "disney princess 2015", "magic wand", "tiara 2015", "pink tiara",
    "princess tiara", "pink dress", "pretty princess", "little princess",
    "princess diaries", "sleeping beauty", "happily ever after", "trick or treat",
    "happy halloween", "halloween 2015", "hocus pocus", "i love pink",
    "pink is my color", "off with their heads", "vampire princess",
    "morticia addams", "addams family", "black is the new pink",
    "princess morticia", "my prince will come", "glass slipper",
    "the princess", "i am the princess", "pink princess tiara", "princess wand",
    "once upon a time", "dark princess", "gothic princess", "all black",
]

seen, hits = set(), []


def test(pw):
    if not pw or pw in seen or len(pw) > 64 or len(pw) < 3:
        return
    seen.add(pw)
    if md5crypt(pw.encode()) == TARGET:
        hits.append(pw)
        print("!! HIT:", repr(pw), flush=True)


for c in CORES:
    for v in casevars(c):
        test(v)
        for t in TAILS:
            test(v + t)

for p in PHRASES:
    for v in casevars(p):
        test(v)
        for t in TAILS:
            test(v + t)
    # space-separated variants of the phrase words joined
    test(p.replace(" ", ""))
    test(p.replace(" ", "_"))
    test(p.replace(" ", "-"))
    test(p.replace(" ", "."))
    for v in casevars(p.replace(" ", "")):
        for t in ("2015", "!", "1", "123"):
            test(v + t)

print(f"tested {len(seen)} candidates; HITS: {hits}")
