# Free Agent — Reverse Engineering CTF Writeup

## 1. Challenge Information

* **CTF Name:** BlackHat MEA CTF
* **Challenge Name:** Free Agent (`free-agent`)
* **Category:** Reverse Engineering
* **Difficulty:** Hard
* **Points:** 500
* **Flag Format:** `BHFlagY{...}`
* **Files Provided:**
  * `free-agent.exe` (12 MB Windows x86-64 executable)
  * `free-agent_session_debug.zip` (Encrypted host diagnostic artifacts)
  * `traffic.pcapng` (Network packet capture containing gRPC/HTTP2 communications)
* **Objective:** Analyze the provided Windows executable and network traffic, reconstruct the multi-stage unpacking process and proprietary C2 encryption scheme, and recover the exfiltrated flag.

---

## 2. Executive Summary

The **Free Agent** challenge centers around a multi-stage Windows x86-64 implant written in Go (`go1.20.5`). Rather than a single self-contained binary, the challenge presents an integrated puzzle spanning host forensics, embedded executable unpacking, and encrypted network command-and-control (C2) communication.

The initial stage, `free-agent.exe`, gathers host survey metrics and encrypts them into 15 `.txt` files (bundled in `free-agent_session_debug.zip`) using AES-256-CBC with a hardcoded master key located in `.data`. Decrypting these files recovers critical environment variables representing the victim host's identity: `USERNAME = lightlight` and `COMPUTERNAME = DESKTOP-DD6SS6U`. Cross-referencing the master key reveals a second reference in a custom packer routine (`0x6407A0`). This routine unpacks a 7.1 MB static data blob embedded at `.data:0xF6F610` using a proprietary algorithm designated as `FALZ\x01` (a custom LZ77 variant coupled with a modular subtraction/XOR loop), producing a standalone 9.6 MB stripped Go executable.

Static analysis of the unpacked Stage 2 binary reveals an obfuscated C2 client communicating over plaintext HTTP/2 with a remote gRPC service (`/free.model/{Init, Prompt, Model}`). Crucially, the client does not generate an ephemeral X25519 private key at random; instead, it deterministically computes $\text{SHA-256}(\text{"lightlight\_DESKTOP-DD6SS6U"})$ as its private key. By computing the ECDH shared secret against the server's public key extracted from the traffic capture and reversing the subsequent session key derivation (involving an 8-byte XOR mask on the session ID followed by dual SHA-256 hashing), we derive the active AES-GCM session key. Decrypting the gRPC frames reveals an interactive shell session where the operator staged an OpenSSL command to encrypt `D:\BlackHat\flag.txt` with a known key before exfiltrating the ciphertext. Decrypting this payload yields the flag.

---

## 3. Environment & Tools

* **Operating System:** Ubuntu 22.04 LTS (WSL2 / Linux 6.6 x86_64) & Windows 11
* **Disassemblers & Decompilers:**
  * IDA Pro 8.3 / Ghidra 11.0
  * GNU `objdump` 2.38
* **Network & Protocol Analysis:**
  * Wireshark 4.2 & `tshark`
* **Scripting & Cryptography:**
  * Python 3.10+ (`cryptography`, `pefile`)
  * OpenSSL 3.0 CLI

---

## 4. Initial Reconnaissance

### 4.1 File Identification

Running `file` on the primary executable:

```bash
$ file free-agent.exe
free-agent.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows
```

The binary is a 64-bit Windows Portable Executable (PE32+). Although symbols and PDB paths have been stripped, Go runtime artifacts such as the program counter line table (`pclntab`) remain intact in `.rdata`.

### 4.2 Binary Properties

Examining the section layout using `objdump -h`:

```bash
$ objdump -h free-agent.exe
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00243318  0000000000401000  0000000000401000  00000600  2**4
  1 .rdata        0022a0a0  0000000000645000  0000000000645000  00243a00  2**4
  2 .data         00708400  0000000000870000  0000000000870000  0046dc00  2**4
  3 .idata        00000490  0000000000fd6000  0000000000fd6000  00b76000  2**2
  4 .reloc        00009ad8  0000000000fd7000  0000000000fd7000  00b76600  2**2
```

**Key Observation:** The `.data` section is unusually large (`0x708400` bytes $\approx 7.37\text{ MB}$), indicating that substantial payloads, encrypted blobs, or resources are compiled directly into the binary rather than retrieved dynamically.

### 4.3 Strings and Go Package Metadata

Extracting function and package references from `pclntab` located in `.rdata` (VA `0x6EE9B0`):

```text
fagent/cmd/free-agent
diagnostics.Collect
diagnostics.gather
diagnostics.sealValue
diagnostics.pkcs7Pad
diagnostics.fieldCipher
diagnostics.writeFieldFiles
report.tryUpload
report.SendAndCleanup
ui.Run
ui.handleSubmission
ui.printBanner
util.ZipAndRemove
util.writeZip
util.addFile
```

These package paths indicate that `free-agent.exe` gathers host telemetry (`diagnostics`), seals the values with encryption, packages them into a zip archive (`util`), and attempts exfiltration to a web endpoint (`report.tryUpload`, targeting `http://not-malicious-website.ctf/upload`).

### 4.4 Encrypted Host Survey (`free-agent_session_debug.zip`)

Inspecting the provided zip archive:

```bash
$ unzip -l free-agent_session_debug.zip
Archive:  free-agent_session_debug.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       64  1980-00-00 00:00   appdata.txt
       32  1980-00-00 00:00   argv0.txt
       48  1980-00-00 00:00   collected_at.txt
       32  1980-00-00 00:00   computer_name.txt
       48  1980-00-00 00:00   cwd.txt
       32  1980-00-00 00:00   golang_version.txt
       32  1980-00-00 00:00   hostname.txt
       32  1980-00-00 00:00   operating_system.txt
      336  1980-00-00 00:00   path_env.txt
       32  1980-00-00 00:00   pid.txt
       64  1980-00-00 00:00   temp.txt
       32  1980-00-00 00:00   user_domain.txt
       32  1980-00-00 00:00   user_input.txt
       48  1980-00-00 00:00   user_profile.txt
       48  1980-00-00 00:00   username.txt
---------                     -------
      912                     15 files
```

Each file's size is a strict multiple of 16 bytes, consistent with block cipher output and PKCS#7 padding.

---

## 5. Static Analysis

### 5.1 Host Telemetry Encryption (`Diagnostics_SealValue`)

Disassembling `diagnostics.sealValue` at `0x4EDBC0`:

```assembly
0x4EDBC0: ; Allocates 16-byte random IV via crypto/rand.Read
0x4EDBD4: call    crypto/rand.Read
0x4EDC01: ; Calculates PKCS#7 padding: pad = 16 - (len & 0xF)
0x4EDC15: ; Padded length = (len & ~0xF) + 16
0x4EDC3A: call    crypto/aes.NewCipher
0x4EDC42: call    crypto/cipher.NewCBCEncrypter
0x4EDC60: ; Encrypts blocks via CryptBlocks
0x4EDC85: ; Writes output format: IV (16 bytes) || Ciphertext
```

The key passed into `crypto/aes.NewCipher` originates from `Diagnostics_CollectAndSealAll` at `0x4EDE60`:

```assembly
0x4EDEBD: lea     rax, [rip + 0x3836bc]   ; VA 0x871580 (.data)
```

Extracting 32 bytes from `0x871580` yields the **Master Key**:
$$\text{Master Key} = \texttt{6e1ac4f78b33905ed20f77a94cb821e63d9512da607ecf1b48a3590ce42db673}$$

### 5.2 Decrypting Host Telemetry Files

Using AES-256-CBC with the Master Key and extracting the first 16 bytes of each file as the IV, we decrypt the survey artifacts:

```text
username.txt:         DESKTOP-DD6SS6U\lightlight
computer_name.txt:    DESKTOP-DD6SS6U
hostname.txt:         DESKTOP-DD6SS6U
user_domain.txt:      DESKTOP-DD6SS6U
cwd.txt:              C:\Users\lightlight\Downloads
user_profile.txt:     C:\Users\lightlight
golang_version.txt:   go1.20.5
operating_system.txt: windows/amd64
```

These values define the victim's exact runtime profile, which becomes vital in later cryptographic stages.

### 5.3 Cross-Referencing the Master Key: The Second Routine (`0x6406E0`)

Searching the binary for all references to `0x871580` reveals exactly two locations:
1. `0x4EDEBD` (in `Diagnostics_CollectAndSealAll`)
2. `0x64070D` (in an unlabelled function at `0x6406E0`)

Inspecting `0x6406E0`:

```assembly
0x6406F8: mov     rax, [rip + 0x92ef11]   ; 0xF6F610 (Data pointer)
0x6406FF: mov     rbx, [rip + 0x92ef12]   ; 0xF6F618 (Length = 7,128,493)
0x640706: mov     rcx, [rip + 0x92ef13]   ; 0xF6F620 (Capacity = 7,128,493)
0x64070D: lea     rdi, [rip + 0x230e6c]   ; 0x871580 (Master Key)
0x640714: mov     esi, 0x20               ; Key length = 32
0x640719: mov     r8, rsi
0x640720: call    0x6407A0                ; Unpack & Decrypt Routine
0x640725: test    dil, dil                ; Check success boolean
0x640728: je      fail
0x640739: call    0x640D80                ; In-memory PE Loader
0x640757: call    0x641760                ; Execute entry point
```

Address `0xF6F610` points to a static slice in `.data` at VA `0x8A1D40` containing `7,128,493` bytes. The routine at `0x6407A0` decompresses and decrypts this blob in memory and executes it as a Portable Executable.

---

## 6. Control Flow & Unpacking Analysis

### 6.1 The Custom `FALZ\x01` Unpacker (`0x6407A0`)

The unpacking routine operates in two sequential phases: decompression followed by modular decryption.

```
                  ┌─────────────────────────────────┐
                  │ Embedded Slice @ 0x8A1D40       │
                  │ Length: 7,128,493 bytes         │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ Verify Header:                  │
                  │ Magic "FALZ", Version 0x01      │
                  │ Extract 4B BE Compressed Length │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ Decompressor Routine @ 0x6409C0 │
                  │ Bespoke LZ77 Sliding Window     │
                  │ Output: 9,649,152 bytes         │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ Decryption Loop @ 0x6408D0      │
                  │ Transform with Master Key:      │
                  │ out[i] = ((dec[i] ^ K1) - K2)   │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────┐
                  │ Unpacked PE32+ Executable       │
                  │ (Stage 2 C2 Client)             │
                  └─────────────────────────────────┘
```

#### Phase 1: Header Validation and Slicing
At `0x6407CC`:
* Bytes 0–3: `0x5A4C4146` (`"FALZ"`)
* Byte 4: Version byte `0x01`
* Bytes 6–9: Big-Endian 32-bit compressed length: `0x006CC5A3` ($7,128,483$ bytes)
* Offset 10: Beginning of compressed payload passed to `0x6409C0`.

#### Phase 2: LZ77 Decompression (`0x6409C0`)
The decompression routine reads a 32-bit Big-Endian integer specifying the target uncompressed size ($9,649,152$ bytes) and allocates the output buffer using `runtime.makeslice`.

Processing proceeds using 8-bit flag bytes:
* **Literal (Bit = 0):** Copies the next byte directly from the input stream to the output buffer.
* **Match (Bit = 1):** Reads a 16-bit Big-Endian word from input:
  $$\text{offset} = \text{word} \gg 4$$
  $$\text{match\_len} = (\text{word} \ \& \ 0\text{xF}) + 3$$
  $$\text{dist} = \text{offset} + 1$$
  Bytes are copied from $\text{output}[\text{current\_pos} - \text{dist}]$ byte-by-byte into the output buffer, naturally supporting run-length encoding when $\text{match\_len} > \text{dist}$.

#### Phase 3: Modular Decryption Loop (`0x6408D0`)
Once decompressed, the buffer is transformed using the 32-byte Master Key ($K$):

```assembly
0x6408FA: mov     rax, rbx                ; rax = i (current byte index)
0x640902: idiv    r9                      ; rdx = i % 32
0x64090A: lea     r10, [rbx + rbx*2]      ; r10 = 3 * i
0x64090E: lea     rax, [rbx + r10*2]      ; rax = 7 * i
0x640912: lea     rax, [rax + 3]          ; rax = 7 * i + 3
0x64091B: idiv    r9                      ; rdx = (7 * i + 3) % 32
0x6408D0: movzx   r11d, byte ptr [rdx+rdi] ; r11 = K[(7*i + 3) % 32]
0x6408D5: movzx   r12d, byte ptr [rbx+rsi] ; r12 = decompressed[i]
0x6408DA: xor     r12d, r11d               ; r12 = decompressed[i] ^ K[(7*i + 3) % 32]
0x6408DD: sub     r12d, r10d               ; r12 = (decompressed[i] ^ K1) - K[i % 32]
0x6408E0: mov     byte ptr [r8+rbx], r12b  ; output[i] = r12b (mod 256)
```

Mathematically, for each byte $i \in [0, 9649152)$:
$$\text{output}[i] = \Big(\big(\text{decompressed}[i] \oplus K[(7i + 3) \bmod 32]\big) - K[i \bmod 32]\Big) \bmod 256$$

Executing this transformation produces a valid executable starting with `MZ\x90\x00` and the standard DOS stub: `"This program cannot be run in DOS mode."`

---

## 7. Stage 2 Analysis: The Obfuscated C2 Client

Inspecting the unpacked binary:
* **Format:** PE32+ console executable, Go version `1.20.5`
* **Size:** 9,649,152 bytes
* **Symbols:** Obfuscated with identifier replacement (`GGGOOOGOOGOGOG`, `OOGOOOGOGOOOGGOOO`, etc.)

Parsing its `pclntab` located at file offset `0x631460` maps out all `main` functions:

| Virtual Address | Function Symbol | Inferred Functionality |
|---|---|---|
| `0x849E20` | `main.main` | Control flow flattened C2 loop |
| `0x84D8E0` | `main.GGGGGOGOOGGOGGGO` | gRPC client setup |
| `0x84E040` | `main.(*GGGOOOGOOGOGOG).GGOGOGOGOOGGO` | `/free.model/Init` handler |
| `0x852E80` | `main.(*GGGOOOGOOGOGOG).GOGOOOGGGG` | `/free.model/Prompt` handler |
| `0x858440` | `main.(*GGGOOOGOOGOGOG).OOGOGOOGOO` | `/free.model/Model` handler |
| `0x85BFE0` | `main.GGOOGOGGOGGOOOOOOOO` | Remote command execution (`exec.Command`) |
| `0x85EC40` | `main.OGGOOGOOGOGGGGOOOOG` | Local file reading (`os.ReadFile`) |
| `0x85F980` | `main.GGGGOGGGGGGOO` | Local file writing (`os.WriteFile`) |
| `0x860140` | `main.OOGOOOOOOGGOGGGGG` | X25519 key generation wrapper |
| `0x8617A0` | `main.OOGOOOGOGOOOGGOOO` | Host-derived private key generator |
| `0x8642A0` | `main.OGGOGGOGOGOOGGO` | Environment variable query (`os.LookupEnv`) |
| `0x864FE0` | `main.GGGOOGGGGOOGGOO` | 8-byte XOR permutation routine |
| `0x8660C0` | `main.GOOGOOGOOOOGGOO` | Session key derivation (ECDH + dual SHA-256) |
| `0x86B460` | `main.OGGOGGGOGOGGOOGGG` | AES-GCM cipher wrapper |

### 7.1 C2 Architecture

`main.main` connects to `192.168.137.1:50051` via `google.golang.org/grpc.DialContext` and enters a poll-response loop:
1. Calls `Init`: Exchanges identity and X25519 public keys; establishes a session ID and derived AES-GCM key.
2. Calls `Prompt`: Polls the server for encrypted command instructions.
3. Dispatches task:
   * Execute command via `cmd.exe /c` (`0x85BFE0`)
   * Read file (`0x85EC40`)
   * Write file (`0x85F980`)
4. Calls `Model`: Returns the AES-GCM encrypted output back to the operator.

---

## 8. Algorithm Reconstruction

### 8.1 Deterministic Client Private Key Derivation (`0x8617A0`)

Standard TLS and C2 implementations generate ephemeral private keys via a cryptographically secure pseudo-random number generator (`crypto/rand`). Here, `0x8617A0` builds the key deterministically:

1. Calls `0x8642A0` with argument `"USERNAME"`:
   * Resolves `os.LookupEnv("USERNAME")`.
   * From our host survey, this yields `"lightlight"`.
2. Calls `0x8642A0` with argument `"COMPUTERNAME"`:
   * Resolves `os.LookupEnv("COMPUTERNAME")`.
   * From our host survey, this yields `"DESKTOP-DD6SS6U"`.
3. Calls `runtime.concatstring3` at `0x862DA7`:
   * Passes `a0 = "lightlight"`, `a1 = "_"`, and `a2 = "DESKTOP-DD6SS6U"`.
   * Result: `"lightlight_DESKTOP-DD6SS6U"`.
4. Computes SHA-256 at `0x861FE0`:
   $$\text{client\_priv} = \text{SHA-256}(\text{"lightlight\_DESKTOP-DD6SS6U"})$$
   $$\text{client\_priv} = \texttt{a68c071a078d0011ae5ea9698d2a561d57ddb124f11fd2ff34ab7d1076c140a6}$$
5. Passes this 32-byte array to `crypto/ecdh.(*x25519Curve).NewPrivateKey`.

**Verification:** Deriving the X25519 public key from this private key:
$$\text{client\_pub} = \text{X25519\_Public}(\text{client\_priv}) = \texttt{fcce28708604b98004450d32ea2ab2ffb9e4dc1961cc7257af2f80c8c8b1fa76}$$

Inspecting Frame 753 of `traffic.pcapng` (the gRPC `Init` request), field 2 contains precisely:
`fcce28708604b98004450d32ea2ab2ffb9e4dc1961cc7257af2f80c8c8b1fa76`. This proves the reconstructed private key is 100% correct.

### 8.2 Shared Secret Computation

From Frame 758 (the gRPC `Init` response):
* Field 1 (`session_id`): `"f3bbb50728251459"`
* Field 2 (`server_pub`): `d26e1248c5c117fc4c3afe949b4a3e79dd2890775e9823161edd03e9c319323a`

Computing the ECDH shared secret:
$$\text{shared\_secret} = \text{X25519}(\text{client\_priv}, \text{server\_pub})$$
$$\text{shared\_secret} = \texttt{14488f97ebdc8e8bad1e48057af735b86dbecbea2c6e7105eb7c38145d1e3072}$$

### 8.3 Proprietary Session Key Derivation (`0x8660C0`)

Function `0x8660C0` receives `client_priv`, `server_pub`, and `session_id`, and derives the AES-GCM key as follows:

```
 [ shared_secret (32B) ]                [ session_id (16B ASCII) ]
           │                                        │
           ▼                                        ▼
    SHA-256 Hash                          XOR with 8-byte mask:
           │                             \x8c\xf1\xa7\x13\x9e\x02\xd6\x7f
           │                                        │
           │                                        ▼
           │                                  SHA-256 Hash
           │                                        │
           ▼                                        ▼
      [ digest2 ]                              [ digest1 ]
           │                                        │
           └───────────────────┬────────────────────┘
                               │ Concatenate
                               ▼
                   [ digest1 || digest2 ] (64B)
                               │
                               ▼
                          SHA-256 Hash
                               │
                               ▼
                     [ AES-GCM Session Key ]
```

1. **Digest 2:**
   $$\text{digest2} = \text{SHA-256}(\text{shared\_secret})$$
   $$\text{digest2} = \texttt{19c0c491a43555323436b797b78da08592847dc34d9c04c1765ea6b367e3868a}$$

2. **Digest 1:**
   The session ID ASCII string (`"f3bbb50728251459"`) is processed through `0x864FE0`, which XORs each byte with an 8-byte cyclic key stored at `0xCCC708`:
   $$\text{XOR Key} = \texttt{\\x8c\\xf1\\xa7\\x13\\x9e\\x02\\xd6\\x7f}$$
   $$\text{xored\_session}[i] = \text{session\_id}[i] \oplus \text{XOR Key}[i \bmod 8]$$
   $$\text{digest1} = \text{SHA-256}(\text{xored\_session})$$
   $$\text{digest1} = \texttt{b3c58eb6a02c2dce192b06f32e503c19bf5211ce4321eec353cdc7791d7d1a0b}$$

3. **Combined Key:**
   Lines `0x866896` to `0x8668FA` concatenate `digest1` and `digest2` into a 64-byte buffer and hash it with SHA-256:
   $$\text{AES Key} = \text{SHA-256}(\text{digest1} \,\|\, \text{digest2})$$
   $$\text{AES Key} = \texttt{7c29d2dc03567d188b844a11d08d5c82707bb052ea012e0729658948fc832b93}$$

---

## 9. Network Traffic Decryption & Evidence Analysis

With the AES-GCM key derived, all HTTP/2 DATA frames on TCP port 50051 are parsed and decrypted. Each encrypted gRPC payload contains a 12-byte random nonce and AES-GCM ciphertext.

### Decrypted Activity Log

```text
[Frame 806  | Stream 7  | Srv -> Cli]  Empty poll
[Frame 1262 | Stream 9  | Srv -> Cli]  Empty poll
[Frame 1383 | Stream 11 | Srv -> Cli]  Command: "dir D:\."
[Frame 1394 | Stream 13 | Cli -> Srv]  Output: Directory listing of D:\
[Frame 1510 | Stream 17 | Srv -> Cli]  Command: "dir D:\BlackHat\"
[Frame 1522 | Stream 19 | Cli -> Srv]  Output: Shows flag.txt (73 bytes)
[Frame 1645 | Stream 23 | Srv -> Cli]  WriteFile: "D:\BlackHat\key.txt"
                                        Content: "!!!_thr347_4ct0r_5ecr37_k3yy_!!!"
[Frame 1853 | Stream 31 | Srv -> Cli]  Command: "openssl" (Verification of binary)
[Frame 2096 | Stream 37 | Srv -> Cli]  Command:
  "openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
   -in D:\BlackHat\flag.txt -out D:\BlackHat\flag.txt.enc \
   -pass file:D:\BlackHat\key.txt"
[Frame 2193 | Stream 41 | Srv -> Cli]  ReadFile: "D:\BlackHat\flag.txt.enc"
[Frame 2195 | Stream 43 | Cli -> Srv]  Exfiltrated File Content:
  Salted__\xea\x1cf\x0f\xc6\xb14!)Y)O\x11\x1d\x9fr_\xe9\xff... (96 bytes)
```

The operator wrote an encryption key to `D:\BlackHat\key.txt`, executed an OpenSSL PBKDF2 encryption command against `flag.txt`, and exfiltrated the resulting `flag.txt.enc` over the C2 channel.

---

## 10. Flag Recovery

### 10.1 Complete Solver Script

The following Python script automates the entire resolution:
1. Derives the deterministic client X25519 keypair.
2. Computes the shared secret and derives the AES-GCM session key.
3. Extracts Frame 2195 from `traffic.pcapng` and decrypts the gRPC payload.
4. Parses the Protobuf envelope to recover the raw `Salted__` OpenSSL ciphertext.
5. Invokes OpenSSL to decrypt the ciphertext using the recovered password.

```python
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
```

### 10.2 Execution and Verification

Running the solver script:

```bash
$ python3 solve.py
[*] Stage 1: Deriving Client X25519 Keypair from Host Identity...
    Client Private Key : a68c071a078d0011ae5ea9698d2a561d57ddb124f11fd2ff34ab7d1076c140a6
    Client Public Key  : fcce28708604b98004450d32ea2ab2ffb9e4dc1961cc7257af2f80c8c8b1fa76
[*] Stage 2: Computing Shared Secret & Session Key...
    AES-GCM Session Key: 7c29d2dc03567d188b844a11d08d5c82707bb052ea012e0729658948fc832b93
[*] Stage 3: Extracting Exfiltrated Ciphertext from traffic.pcapng...
[*] Stage 4: Decrypting Exfiltrated Flag with OpenSSL PBKDF2...

============================================================
[+] RECOVERED FLAG: BHFlagY{wh4t_y0u_5Ee_15n't_wh4t_y0u_G3t_8cc56ad688964fd5f72f3c414971b1d6}
============================================================
```

---

## 11. Flag

```text
BHFlagY{wh4t_y0u_5Ee_15n't_wh4t_y0u_G3t_8cc56ad688964fd5f72f3c414971b1d6}
```

---

## 12. Key Takeaways

1. **Static Payload Identification:** Abnormally large data sections in compiled binaries (`.data` > 7 MB) often indicate embedded secondary stages, packed payloads, or embedded virtual filesystems.
2. **Cross-Reference Analysis:** Tracking every cross-reference of hardcoded keys frequently reveals dual-purpose cryptographic primitives (here, host survey encryption and stage-two payload decryption).
3. **Deterministic Key Generation in Malware:** Complex modern cryptography (X25519, AES-GCM) is rendered breakable if ephemeral secrets are seeded by static or discoverable environmental attributes like `USERNAME` and `COMPUTERNAME`.
4. **Holistic Artifact Correlation:** Solving complex CTF challenges requires synthesizing information across disparate files—using static binary analysis to decrypt diagnostic files, diagnostic outputs to derive network keys, and network traffic to extract final encrypted flags.

---

## 13. Appendix

### 13.1 Important Addresses (Stage 1: `free-agent.exe`)

| Virtual Address | File Offset | Description |
|---|---|---|
| `0x4EDBC0` | `0x0ED5C0` | `diagnostics.sealValue` (AES-256-CBC file encrypter) |
| `0x6406E0` | `0x23F6E0` | Embedded PE extraction & execution wrapper |
| `0x6407A0` | `0x23F7A0` | Custom `FALZ\x01` decompressor & decryptor |
| `0x6409C0` | `0x23F9C0` | LZ77 sliding window decompression engine |
| `0x871580` | `0x46E580` | 32-byte Master Key in `.data` |
| `0xF6F610` | `0xB6D210` | Embedded slice header (pointer, length, capacity) |
| `0x8A1D40` | `0x49ED40` | Raw embedded `FALZ\x01` binary blob ($7,128,493$ bytes) |

### 13.2 Important Addresses (Stage 2: Unpacked PE)

| Virtual Address | Symbol / Label | Description |
|---|---|---|
| `0x849E20` | `main.main` | C2 communication dispatcher loop |
| `0x84E040` | `(*GGGOOOGOOGOGOG).GGOGOGOGOOGGO` | gRPC `/free.model/Init` client method |
| `0x852E80` | `(*GGGOOOGOOGOGOG).GOGOOOGGGG` | gRPC `/free.model/Prompt` client method |
| `0x858440` | `(*GGGOOOGOOGOGOG).OOGOGOOGOO` | gRPC `/free.model/Model` client method |
| `0x8617A0` | `main.OOGOOOGOGOOOGGOOO` | Generates private key from host environment |
| `0x8660C0` | `main.GOOGOOGOOOOGGOO` | Derives AES-GCM session key |
| `0x864FE0` | `main.GGGOOGGGGOOGGOO` | 8-byte XOR permutation routine |
| `0x86B460` | `main.OGGOGGGOGOGGOOGGG` | AES-GCM encryption/decryption execution |
| `0xCCC708` | Key constant | 8-byte XOR key (`8cf1a7139e02d67f`) |

### 13.3 Key Commands Quick Reference

```bash
# Decompress and unpack Stage 2 PE:
python3 -c '...test_falz.py...'

# Decrypt Stage 1 diagnostic files:
python3 decrypt.py

# Extract HTTP/2 gRPC data from PCAP:
tshark -r traffic.pcapng -Y "http2.data.data" -T fields -e frame.number -e http2.data.data

# Decrypt exfiltrated flag manually:
openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 200000 \
  -in flag_exfil.enc -pass pass:'!!!_thr347_4ct0r_5ecr37_k3yy_!!!'
```
