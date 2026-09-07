#!/usr/bin/env python3
"""
Free Agent — Automated Solver & Flag Recovery Script
"""
import subprocess
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def main():
    print("[*] Stage 1: Deriving Client X25519 Keypair from Host Identity...")
    identity = b"lightlight_DESKTOP-DD6SS6U"
    client_priv_bytes = hashlib.sha256(identity).digest()
    client_priv = x25519.X25519PrivateKey.from_private_bytes(client_priv_bytes)
    client_pub_bytes = client_priv.public_key().public_bytes_raw()
    print(f"    Client Private Key : {client_priv_bytes.hex()}")
    print(f"    Client Public Key  : {client_pub_bytes.hex()}")

    print("[*] Stage 2: Computing Shared Secret & Session Key...")
    server_pub_bytes = bytes.fromhex("d26e1248c5c117fc4c3afe949b4a3e79dd2890775e9823161edd03e9c319323a")
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = client_priv.exchange(server_pub)
    digest2 = hashlib.sha256(shared_secret).digest()

    session_id = b"f3bbb50728251459"
    xor_mask = bytes.fromhex("8cf1a7139e02d67f")
    xored_session = bytes(b ^ xor_mask[i % 8] for i, b in enumerate(session_id))
    digest1 = hashlib.sha256(xored_session).digest()

    aes_key = hashlib.sha256(digest1 + digest2).digest()
    print(f"    AES-GCM Session Key: {aes_key.hex()}")

    print("[*] Stage 3: Extracting Exfiltrated Ciphertext from traffic.pcapng...")
    cmd = [
        "tshark", "-r", "traffic.pcapng",
        "-Y", "frame.number == 2195 and http2.data.data",
        "-T", "fields", "-e", "http2.data.data"
    ]
    raw_hex = subprocess.check_output(cmd, text=True).strip()
    raw_bytes = bytes.fromhex("".join(chunk for chunk in raw_hex.split(",") if chunk))

    # Strip 5-byte gRPC framing header
    grpc_len = int.from_bytes(raw_bytes[1:5], "big")
    msg_bytes = raw_bytes[5:5 + grpc_len]

    # Minimal Protobuf decoder for field 3 (nonce) and field 4 (ciphertext)
    idx = 0
    fields = {}
    while idx < len(msg_bytes):
        tag = msg_bytes[idx]; idx += 1
        w_type = tag & 7; f_num = tag >> 3
        if w_type == 0:
            shift = 0; val = 0
            while idx < len(msg_bytes):
                b = msg_bytes[idx]; idx += 1
                val |= (b & 0x7f) << shift
                if not (b & 0x80): break
                shift += 7
            fields[f_num] = val
        elif w_type == 2:
            shift = 0; length = 0
            while idx < len(msg_bytes):
                b = msg_bytes[idx]; idx += 1
                length |= (b & 0x7f) << shift
                if not (b & 0x80): break
                shift += 7
            val = msg_bytes[idx:idx + length]; idx += length
            fields[f_num] = val

    nonce = fields[3]
    ct = fields[4]

    decrypted_pt = AESGCM(aes_key).decrypt(nonce, ct, None)
    
    # Locate OpenSSL "Salted__" magic header
    salt_pos = decrypted_pt.find(b"Salted__")
    if salt_pos == -1:
        raise ValueError("Could not locate Salted__ OpenSSL magic in decrypted payload.")
    enc_file_bytes = decrypted_pt[salt_pos:salt_pos + 96]

    print("[*] Stage 4: Decrypting Exfiltrated Flag with OpenSSL PBKDF2...")
    with open("/tmp/flag_exfil.enc", "wb") as f:
        f.write(enc_file_bytes)
    
    password = b"!!!_thr347_4ct0r_5ecr37_k3yy_!!!"
    with open("/tmp/key.txt", "wb") as f:
        f.write(password)

    dec_cmd = [
        "openssl", "enc", "-d", "-aes-256-cbc",
        "-salt", "-pbkdf2", "-iter", "200000",
        "-in", "/tmp/flag_exfil.enc",
        "-pass", "file:/tmp/key.txt"
    ]
    flag_output = subprocess.check_output(dec_cmd).decode("utf-8").strip()
    print("\n" + "=" * 60)
    print(f"[+] RECOVERED FLAG: {flag_output}")
    print("=" * 60)

if __name__ == "__main__":
    main()
