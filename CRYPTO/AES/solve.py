#!/usr/bin/env python3
"""
Solver for the custom AES CTF challenge.
The key hint is 26 hex chars; we brute-force the missing 6 hex chars (3 bytes).
We verify using a known plaintext-ciphertext pair.
"""

import sys
from itertools import product
from multiprocessing import Pool, cpu_count
import time

# ── Inline the AES implementation ─────────────────────────────────────────────

IRREDUCIBLE_POLY = 0x11B

def gf_mult(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= (IRREDUCIBLE_POLY & 0xFF)
        b >>= 1
    return result

def gf_pow(base: int, exp: int) -> int:
    if exp == 0:
        return 1
    result = 1
    while exp > 0:
        if exp & 1:
            result = gf_mult(result, base)
        base = gf_mult(base, base)
        exp >>= 1
    return result

def generate_sbox():
    sbox = []
    for x in range(256):
        val = gf_pow(x, 23)
        val ^= 0x63
        sbox.append(val)
    return sbox

def generate_inv_sbox(sbox):
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return inv_sbox

SBOX = generate_sbox()
INV_SBOX = generate_inv_sbox(SBOX)

MIX_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

INV_MIX_MATRIX = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E]
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key: bytes, rounds: int = 6):
    assert len(key) == 16
    words = []
    for i in range(4):
        words.append(list(key[4*i:4*i+4]))
    for i in range(4, 4 * (rounds + 1)):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[(i // 4) - 1]
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(rounds + 1):
        rk = bytes()
        for i in range(4):
            rk += bytes(words[r*4 + i])
        round_keys.append(rk)
    return round_keys

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    result = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            result[r][c] = state[r][(c + r) % 4]
    return result

def inv_shift_rows(state):
    result = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            result[r][c] = state[r][(c - r) % 4]
    return result

def mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            val = 0
            for i in range(4):
                val ^= gf_mult(MIX_MATRIX[r][i], state[i][c])
            result[r][c] = val
    return result

def inv_mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            val = 0
            for i in range(4):
                val ^= gf_mult(INV_MIX_MATRIX[r][i], state[i][c])
            result[r][c] = val
    return result

def add_round_key(state, round_key: bytes):
    result = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            result[r][c] = state[r][c] ^ round_key[r + 4*c]
    return result

def bytes_to_state(data: bytes):
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def state_to_bytes(state) -> bytes:
    result = []
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    return bytes(result)

ROUNDS = 4

def encrypt(plaintext: bytes, round_keys) -> bytes:
    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])
    for r in range(1, ROUNDS):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[ROUNDS])
    return state_to_bytes(state)

def decrypt(ciphertext: bytes, round_keys) -> bytes:
    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[ROUNDS])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for r in range(ROUNDS - 1, 0, -1):
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)

# ── Load challenge data ────────────────────────────────────────────────────────

KEY_HINT = "26ab77cadcca0ed41b03c8f2e5"
print(f"[*] Key hint: {KEY_HINT} ({len(KEY_HINT)} hex chars, missing {32 - len(KEY_HINT)} hex chars)")

# Load samples
samples = []
with open("output.txt") as f:
    lines = f.readlines()

encrypted_flag = None
for line in lines:
    line = line.strip()
    if line.startswith("encrypted_flag:"):
        encrypted_flag = bytes.fromhex(line.split(": ")[1].strip())
    elif "," in line and not line.startswith("key_hint") and not line.startswith("num_samples") and not line.startswith("samples"):
        pt_hex, ct_hex = line.split(",")
        samples.append((bytes.fromhex(pt_hex.strip()), bytes.fromhex(ct_hex.strip())))

print(f"[*] Loaded {len(samples)} sample pairs")
print(f"[*] Encrypted flag: {encrypted_flag.hex() if encrypted_flag else 'NOT FOUND'}")

# Use first few samples for verification (one match is probabilistically unique)
test_samples = samples[:3]

# ── Brute-force missing 6 hex chars (3 bytes) ─────────────────────────────────
# Key: 26ab77cadcca0ed41b03c8f2e5??????
# Position 26 hex chars = 13 bytes known, positions 13,14,15 are unknown

def try_suffix(suffix: bytes) -> bytes | None:
    """Try a candidate suffix and return it if it produces correct encryptions."""
    key_candidate = bytes.fromhex(KEY_HINT) + suffix
    try:
        rks = key_expansion(key_candidate, ROUNDS)
    except Exception:
        return None
    pt, ct_expected = test_samples[0]
    if encrypt(pt, rks) == ct_expected:
        # Double-check with second sample
        pt2, ct2 = test_samples[1]
        if encrypt(pt2, rks) == ct2:
            return key_candidate
    return None

if __name__ == "__main__":
    total = 256 ** 3  # 16,777,216
    print(f"[*] Brute-forcing {total:,} key candidates ({cpu_count()} CPUs)...")
    
    found_key = None
    start = time.time()
    count = 0
    
    for b0 in range(256):
        for b1 in range(256):
            chunk = [bytes([b0, b1, b2]) for b2 in range(256)]
            for suffix in chunk:
                result = try_suffix(suffix)
                if result is not None:
                    found_key = result
                    break
                count += 1
            if found_key:
                break
        if found_key:
            break
        if b0 % 16 == 0:
            elapsed = time.time() - start
            done = b0 * 256 * 256
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            print(f"  Progress: {done:,}/{total:,} ({100*done/total:.1f}%) | {rate:.0f}/s | ETA: {eta:.0f}s", end="\r")
    
    print()
    if found_key:
        elapsed = time.time() - start
        print(f"\n[+] KEY FOUND in {elapsed:.2f}s: {found_key.hex()}")
        
        # Decrypt the flag (handle multi-block ciphertext)
        rks = key_expansion(found_key, ROUNDS)
        flag_bytes = b""
        
        # Try each 16-byte block
        ct = encrypted_flag
        if ct:
            for i in range(0, len(ct), 16):
                block = ct[i:i+16]
                if len(block) == 16:
                    flag_bytes += decrypt(block, rks)
        
        try:
            flag = flag_bytes.decode("utf-8", errors="replace").rstrip('\x00').rstrip()
            print(f"[+] FLAG: {flag}")
        except Exception as e:
            print(f"[+] Raw decrypted bytes: {flag_bytes.hex()}")
    else:
        print("[-] Key not found! Check the key hint or brute-force range.")
