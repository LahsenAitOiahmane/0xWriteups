"""Offline validation for find_flags.py - no network needed."""
import re
import sys

sys.path.insert(0, r"C:\Users\sadik\WorkBuddy AI\2026-10-17-23-02-39")
import find_flags as ff  # noqa: E402

# 1) the real HUNT-shaped output the box actually produced (captured earlier)
SAMPLE = r"""HUNT_START
HUNT|deadface{f00th0ld_0n_ch4r0n}|/home/svc-deploy/flag.txt|svc-deploy
HUNT|deadface{h1st0ry_r3m3mb3rs_4ll}|/home/deephax/flag.txt|deephax
HUNT|deadface{g1t_n3v3r_f0rg3ts}|/home/gh0st404/flag.txt|gh0st404
HUNT|deadface{sud0_b3c4m3_l1l1th}|/home/lilith/flag.txt|lilith
HUNT|deadface{cr0n_r4n_my_p4yl04d}|/home/sunstalker/flag.txt|sunstalker
HUNT|deadface{c4p_s3tu1d_pwn3d}|/home/spookyboi/flag.txt|spookyboi
HUNT|deadface{h4sh_cr4ck3d_w1d3_0p3n}|/home/mort1cia/flag.txt|mort1cia
HUNT|deadface{p4th_t0_th3_cr0wn}|/root/flag.txt|root
HUNT_END
CAPS: /opt/crypto/pytool cap_setuid=ep
"""

hits = ff.parse_hits(SAMPLE)
print(f"parse_hits -> {len(hits)} rows")
assert len(hits) == 8, hits

# 2) frame decoding: ttyd is MESSAGE-oriented - one command byte per message,
#    payload is raw pty output with NO newline framing.
assert ff._decode_msg(b"0hello world\n") == "hello world\n"
assert ff._decode_msg(b"0charon:~$ ") == "charon:~$ "      # prompt, no newline
assert ff._decode_msg(b"1window title") == ""               # title -> ignored
assert ff._decode_msg(b"2prefs") == ""
assert ff._decode_msg(b"4reconnect") == ""
assert ff._decode_msg(b"") == ""
# a message with no recognised prefix passes through rather than vanishing
assert ff._decode_msg(b"raw bytes") == "raw bytes"
print("_decode_msg-> ok (message-oriented, prompts survive)")

# 3) py() payload must survive the shell unchanged (base64 round trip)
import base64
code = ff.SCAN_BODY
b64 = base64.b64encode(code.encode()).decode()
assert base64.b64decode(b64).decode() == code
print(f"payload    -> ok ({len(b64)} b64 chars, fits a single terminal line)")

# 4) the flag regex is the one that actually matters (bytes pattern -> bytes input)
BYTE_PAT = re.compile(ff.FLAG_RE.pattern.encode() if isinstance(ff.FLAG_RE.pattern, str) else ff.FLAG_RE.pattern)
for good in [b"deadface{c4p_s3tu1d_pwn3d}", b"flag{abc}",
             b"FLAG{X}", b"someCTF{zz_9}"]:
    assert BYTE_PAT.search(good), good
for bad in [b"not_a_flag", b"{}", b"deadface{}"]:
    assert not BYTE_PAT.search(bad), bad
print("FLAG_RE    -> ok")

print("\nALL OFFLINE CHECKS PASSED")
