**Challenge Summary**
- **Name:** Miner (rev)
- **Goal:** Recover a valid `putcCTF{...}` flag from the provided executable.
- **Trick:** The program “mines” each flag character by simulating an intentionally slow state update loop, including absurdly large iteration counts (up to ~\(10^{22}\)), making a naïve run infeasible.

---

**Initial Recon**
1. Identify the artifact:
   - `file miner` → 64-bit Linux ELF, **stripped**.
2. Run briefly to observe behavior:
   - `timeout 20s ./miner`
   - Output shows per-character progress like:
     - `[1/26] Calculating key...`
     - “Simulation progress…”
     - “Block added to blockchain!”
     - Then prints a single character, and repeats.
3. Check for easy tells:
   - `strings -n 3 miner | grep -i pyi`
   - Finds `pyi-python-flag` and embedded Python runtime references → the ELF is a **PyInstaller one-file** executable.

This matters because PyInstaller bundles Python bytecode and resources into an embedded archive we can extract and analyze directly (instead of treating it like pure native code).

---

**Extracting the Embedded Python (PyInstaller)**
To make extraction easy and deterministic, install PyInstaller tools (or use an environment that already has them), then list the archive table-of-contents:

- `pyi-archive_viewer -l ./miner`

The TOC reveals key entries, notably:
- `PYZ.pyz` (the bundled Python module archive)
- miner (the application entrypoint bytecode blob)

Then extract them with `pyi-archive_viewer` (interactive mode supports an `X <name>` command). In this solve, the extracted artifacts were saved under:
- PYZ.pyz
- miner.pyc

---

**Peeling the Obfuscation Layers**
Disassembling miner.pyc shows it’s not the real logic yet. It’s a tiny loader that does roughly:

- Take a large bytes constant.
- Reverse it (`payload[::-1]`).
- Base64-decode.
- zlib-decompress.
- `exec()` the result.

In other words, it’s a “stage 0” unpacker.

When we decompress the payload we get another `exec((_)(b'...'))` wrapper… which itself contains another reversed-base64+zlib payload. This repeats many times.

A reliable strategy is to automate the unpacking:
- Detect the wrapper form: `exec((_)(b'...'))`
- Extract the `b'...'` payload
- Reverse, base64-decode, zlib-decompress
- Repeat until the prefix is no longer the wrapper

This produces the first “real” source layer as:
- layer_31.py

(Your layer number may differ depending on how you start the chain; the important part is that eventually you land on readable Python source.)

---

**Understanding the Real Logic**
In the final source, the important functions/data are:

- `FLAG1_DATA`: a list of tuples `(ts, ev)` for the first segment
- `FLAG2_DATA`: same for the second segment
- `sss(ts)`: simulates a state update loop `ts` times and returns `c_x`
- `decode_flag(flag_data, new_pickaxe=...)`:
  - computes `ksx = sss(ts)`
  - uses `kb = ksx & 0xFF` (low byte)
  - decodes a character with `chr(ev ^ kb)`
  - for `FLAG2_DATA`, applies a rotation (“new pickaxe”):
    - `mined_chars = mined_chars[-13:] + mined_chars[:-13]`

The intended slowdown is inside `sss(ts)`:
- It updates a 3D state \((c_x, c_y, c_z)\) mod \(10^9+7\) for `ts` steps.
- Some `ts` values are huge (10–20+ digits), so the loop is impossible to finish in time.

---

**Key Observation: It’s a Linear Recurrence**
The state update is linear:

\[
\begin{bmatrix}
x'\\y'\\z'
\end{bmatrix}
=
\begin{bmatrix}
3 & 2 & 5\\
1 & 4 & 0\\
0 & 1 & 2
\end{bmatrix}
\cdot
\begin{bmatrix}
x\\y\\z
\end{bmatrix}
\pmod{10^9+7}
\]

Let that matrix be \(M\). After \(t\) steps:

\[
\begin{bmatrix}
x_t\\y_t\\z_t
\end{bmatrix}
=
M^t
\cdot
\begin{bmatrix}
x_0\\y_0\\z_0
\end{bmatrix}
\pmod{10^9+7}
\]

So instead of looping \(t\) times, compute \(M^t\) via **binary exponentiation** in \(O(\log t)\). That makes even \(t \approx 10^{22}\) completely manageable.

We only need \(x_t\) (the function returns `c_x`), and then only the low byte `x_t & 0xFF` to decode the character.

---

**Fast Solver (Matrix Exponentiation)**
Below is a clean solver (matching the logic in the unpacked code) that computes the same output instantly:

```python
MOD = 10**9 + 7
INITIAL_VALUES = (1337, 2137, 999)
NUMBER_OF_MINERALS = 13

FLAG1_DATA = [
    (13691526, 85),
    (67714635, 250),
    (45889193, 92),
    (119333921, 92),
    (28660401, 71),
    (91192320, 226),
    (98698869, 14),
]

FLAG2_DATA = [
    (19385771243582136162726, 119),
    (20338468563599170406034, 244),
    (20348006767133331653585, 84),
    (20855346972076738813432, 108),
    (21275032782538569035493, 44),
    (21688316937478910332906, 213),
    (10000000000000000000000, 248),
    (10434543483380626658076, 213),
    (11432360796540021360875, 89),
    (11893508966092798746611, 0),
    (12629823227009614311307, 71),
    (13239336466487376418254, 130),
    (14213837926783723743645, 144),
    (15144837827511220276057, 129),
    (15901977772834060831411, 234),
    (16759029998774462742839, 143),
    (17454032695551734274782, 170),
    (18154830948193389431256, 102),
    (18647374405210769869223, 151),
]

M = (
    (3, 2, 5),
    (1, 4, 0),
    (0, 1, 2),
)

def mat_mul(A, B):
    return (
        (
            (A[0][0]*B[0][0] + A[0][1]*B[1][0] + A[0][2]*B[2][0]) % MOD,
            (A[0][0]*B[0][1] + A[0][1]*B[1][1] + A[0][2]*B[2][1]) % MOD,
            (A[0][0]*B[0][2] + A[0][1]*B[1][2] + A[0][2]*B[2][2]) % MOD,
        ),
        (
            (A[1][0]*B[0][0] + A[1][1]*B[1][0] + A[1][2]*B[2][0]) % MOD,
            (A[1][0]*B[0][1] + A[1][1]*B[1][1] + A[1][2]*B[2][1]) % MOD,
            (A[1][0]*B[0][2] + A[1][1]*B[1][2] + A[1][2]*B[2][2]) % MOD,
        ),
        (
            (A[2][0]*B[0][0] + A[2][1]*B[1][0] + A[2][2]*B[2][0]) % MOD,
            (A[2][0]*B[0][1] + A[2][1]*B[1][1] + A[2][2]*B[2][1]) % MOD,
            (A[2][0]*B[0][2] + A[2][1]*B[1][2] + A[2][2]*B[2][2]) % MOD,
        ),
    )

def mat_vec_mul(A, v):
    return (
        (A[0][0]*v[0] + A[0][1]*v[1] + A[0][2]*v[2]) % MOD,
        (A[1][0]*v[0] + A[1][1]*v[1] + A[1][2]*v[2]) % MOD,
        (A[2][0]*v[0] + A[2][1]*v[1] + A[2][2]*v[2]) % MOD,
    )

def sss_fast(ts):
    v = INITIAL_VALUES
    power = M
    e = ts
    while e:
        if e & 1:
            v = mat_vec_mul(power, v)
        power = mat_mul(power, power)
        e >>= 1
    return v[0]  # c_x

def decode_flag(flag_data, new_pickaxe=False):
    mined = []
    for ts, ev in flag_data:
        kb = sss_fast(ts) & 0xFF
        mined.append(chr(ev ^ kb))
    if new_pickaxe and mined:
        mined = mined[-NUMBER_OF_MINERALS:] + mined[:-NUMBER_OF_MINERALS]
    return ''.join(mined)

f1 = decode_flag(FLAG1_DATA, new_pickaxe=False)
f2 = decode_flag(FLAG2_DATA, new_pickaxe=True)
print(f1 + f2)
```

Running it prints the real flag immediately.

---

**Flag**
- `putcCTF{3v3ryth1Ng_0n_R3d}`