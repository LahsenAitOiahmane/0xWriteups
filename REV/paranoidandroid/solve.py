#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PACKAGE_NAME = "com.sys.node"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def parse_apk_signing_pairs(apk_bytes: bytes) -> dict[int, bytes]:
    eocd = apk_bytes.rfind(b"\x50\x4b\x05\x06")
    if eocd < 0:
        raise ValueError("EOCD not found")

    central_dir_off = u32(apk_bytes, eocd + 16)
    footer_off = central_dir_off - 24

    if apk_bytes[footer_off + 8 : footer_off + 24] != b"APK Sig Block 42":
        raise ValueError("APK signing block magic not found")

    block_size = u64(apk_bytes, footer_off)
    block_start = central_dir_off - (block_size + 8)
    pairs_blob = apk_bytes[block_start + 8 : footer_off]

    pairs: dict[int, bytes] = {}
    off = 0
    while off < len(pairs_blob):
        pair_len = u64(pairs_blob, off)
        pair_id = u32(pairs_blob, off + 8)
        value_start = off + 12
        value_end = off + 8 + pair_len
        pairs[pair_id] = pairs_blob[value_start:value_end]
        off += 8 + pair_len

    return pairs


def extract_first_cert_der(v2_or_v3_value: bytes) -> bytes:
    signer_len = u32(v2_or_v3_value, 4)
    signer = v2_or_v3_value[8 : 8 + signer_len]

    signed_data_len = u32(signer, 0)
    signed_data = signer[4 : 4 + signed_data_len]

    digests_len = u32(signed_data, 0)
    certs_off = 4 + digests_len

    certs_len = u32(signed_data, certs_off)
    certs = signed_data[certs_off + 4 : certs_off + 4 + certs_len]

    cert_len = u32(certs, 0)
    cert_der = certs[4 : 4 + cert_len]
    return cert_der


def load_seg1(base: Path) -> str:
    arrays_xml = base / "resources" / "res" / "values" / "arrays.xml"
    root = ET.parse(arrays_xml).getroot()

    items = root.findall(".//array[@name='sys_matrix']/item")
    if not items:
        items = root.findall(".//string-array[@name='sys_matrix']/item")

    if not items:
        raise ValueError("sys_matrix not found in arrays.xml")

    align = len(PACKAGE_NAME)
    return "".join(chr(int(it.text) ^ align) for it in items)


def load_seg2(base: Path) -> str:
    path = base / "resources" / "assets" / "data_matrix.bin"
    data = path.read_bytes()
    return data[518 : 518 + 14].decode("utf-8")


def load_seg3(base: Path) -> str:
    apk_path = base / "GemMiner.apk"
    apk_bytes = apk_path.read_bytes()

    pairs = parse_apk_signing_pairs(apk_bytes)
    sign_block = pairs.get(V2_BLOCK_ID) or pairs.get(V3_BLOCK_ID)
    if sign_block is None:
        raise ValueError("Neither v2 nor v3 signing block found")

    cert_der = extract_first_cert_der(sign_block)
    aes_key = hashlib.sha256(cert_der).digest()[:16]

    blob = (base / "resources" / "assets" / "flag_blob.bin").read_bytes()
    nonce = blob[:12]
    ciphertext_and_tag = blob[12:]

    plain = AESGCM(aes_key).decrypt(nonce, ciphertext_and_tag, PACKAGE_NAME.encode())
    return plain.decode("utf-8")


def main() -> None:
    base = Path(__file__).resolve().parent

    seg1 = load_seg1(base)
    seg2 = load_seg2(base)
    seg3 = load_seg3(base)

    flag = f"{seg1}{seg2}{seg3}"

    print(f"SEG1={seg1}")
    print(f"SEG2={seg2}")
    print(f"SEG3={seg3}")
    print(f"FLAG={flag}")


if __name__ == "__main__":
    main()
