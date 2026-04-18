# paranoidandroid Write-up

## Challenge
- Name: paranoidandroid
- Category: Reverse Engineering
- Points: 436
- Attachment: `GemMiner.apk`

## Summary
The app pretends to be a gem generator. Static analysis shows it builds a hidden value from three segments and hashes it in UI flow, but the segments themselves are recoverable directly.

## High-Level Flow
`MainActivity -> CoreEngine.computeIdentifier()`

`CoreEngine` builds:

```text
aggregated = accountId + seg1 + seg2 + seg3
```

Where:
- `seg1` comes from `sys_matrix` in resources.
- `seg2` comes from a fixed offset in `data_matrix.bin`.
- `seg3` comes from decrypting `flag_blob.bin` using an AES key derived from APK signing certificate bytes.

## Function-by-Function Notes

### 1) `ResourceParser.extractConfiguration`
- Reads `R.array.sys_matrix`.
- Computes alignment as `len(packageName)`.
- XORs each integer with alignment.
- Here package is `com.sys.node`, so alignment is `12`.

Result:

```text
SEG1 = INSEC{V3EeERY_
```

### 2) `StreamExtractor.retrieveBlock`
- Opens `assets/data_matrix.bin`.
- Skips to offset `518`.
- Reads `14` bytes.

Result:

```text
SEG2 = LEeg1!1T_GeeM_
```

### 3) `CertLoader.resolveSegment`
- Reads APK signer certificate bytes.
- Computes `SHA-256(cert_der)` and takes first 16 bytes as AES key.
- Reads `assets/flag_blob.bin`.
- Uses:
  - nonce = first 12 bytes
  - ciphertext+tag = remaining bytes
  - AAD = `com.sys.node`
  - cipher = `AES/GCM/NoPadding`

Result:

```text
SEG3 = GeNEr44t0o!!r}
```

## Reconstruction

```text
FLAG = SEG1 + SEG2 + SEG3
```

Final:

```text
INSEC{V3EeERY_LEeg1!1T_GeeM_GeNEr44t0o!!r}
```

## Solve Script
The included `solve.py` reproduces all three extraction paths and prints:
- `SEG1`
- `SEG2`
- `SEG3`
- `FLAG`

Run:

```bash
pip install cryptography
python3 solve.py
```

## Flag
`INSEC{V3EeERY_LEeg1!1T_GeeM_GeNEr44t0o!!r}`
