# Lua Crackme — ch45.out

**Challenge:** Lua bytecode (Lua 5.1) crackme that validates an input password.

**Goal:** Recover the password expected by the bytecode.

**Tools used:**
- `strings`
- `luac -l -p` (disassembly listing)
- Small Python helpers in this workspace: `lua_consts_verbose.py`, `extract_arrays.py`, `compute_start.py`

**Short summary / result**
- Reversing the bytecode shows three numeric arrays embedded as constants: `start_array`, `shift_array`, and `end_array`.
- The validation loop checks each character (by position) using a parity rule (odd/even index) combining `start_array` and `shift_array` to match `end_array`.
- Using the parity rule (odd indices: start = end - shift; even indices: start = end + shift) produces a readable candidate.

Final password (derived):

Balance_Ton_QuooOooOOi!

**Detailed steps**

1. Inspect the file with `strings ch45.out` to see embedded human strings (welcome message, prompts, and function names).

2. Use `luac -l -p ch45.out` to list the bytecode. The main function creates a child function that builds three arrays and then runs the validation loop. The important artifacts:
- constants containing numeric arrays (the arrays are stored in constants and assigned to globals `start_array`, `shift_array`, `end_array`).

3. Extract constants programmatically:
- I used `lua_consts_verbose.py` to dump constants from the chunk and `extract_arrays.py` to pick the numeric arrays between `start_array` and `end_array` markers.

4. Reconstruct the original input bytes:
- From the disassembly, the loop applies a different operation depending on the character index parity. Interpreting indices 1-based and using the mapping below recovers the original characters:
  - if index is odd: start_byte = end_array[index] - shift_array[index]
  - if index is even: start_byte = end_array[index] + shift_array[index]

5. Convert the resulting bytes to ASCII to obtain the password. I used `compute_start.py` (in this workspace) to perform the arithmetic and print candidate strings.

**Commands used (examples)**

```
strings ch45.out
luac -l -p ch45.out
python3 lua_consts_verbose.py ch45.out
python3 extract_arrays.py ch45.out
python3 compute_start.py
```

**Notes / observations**
- The byte arrays include signed values in the bytecode constants; ensure you treat the `shift_array` values as signed 8-bit when reasoning about subtraction/addition.
- I validated the reconstructed bytes against the check algorithm implemented by the Lua bytecode.

If you want, I can:
- produce a minimal runnable script that inputs the password to the original `ch45.out` (requires a Lua 5.1 interpreter), or
- add a short explanation of how the parity logic maps to the bytecode instructions (disassembly snippets).

----
Writeup generated and saved to `WRITEUP.md`.
