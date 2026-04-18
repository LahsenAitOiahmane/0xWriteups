import os
import random
import warnings
import logging
import re

warnings.filterwarnings("ignore")
logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import asm, context
context.log_level = 'critical'

OFFSETS = [random.randint(0, 25) for _ in range(12)]
CURRENT_STEP = 0
OATH_LINES = [
    "I shall not harm.",
    "I shall not exploit without consent.",
    "I shall not access what is not mine.",
    "I shall not abuse knowledge or power.",
    "I shall act within scope and authorization.",
    "Night gathers, and now my watch begins, for this system and all systems to come."
]

def caesar_shift(text):
    global OFFSETS
    out = ""
    for i, char in enumerate(text):
        idx = i % 12
        off = OFFSETS[idx]
        v = ord(char)
        if 32 <= v <= 126:
            nv = 32 + ((v - 32 + off) % 95)
            out += chr(nv)
        else:
            out += char
        OFFSETS[idx] = (OFFSETS[idx] + 1) % 26
    return out

while True:
    try:
        if CURRENT_STEP < len(OATH_LINES):
            user_input = input("> ")
            transformed = caesar_shift(user_input)
            if transformed == OATH_LINES[CURRENT_STEP]:
                CURRENT_STEP += 1
                if CURRENT_STEP == len(OATH_LINES):
                    print("Your watch begins.")
                else:
                    print("Hear my words, and bear witness to my vow.")
                continue

            try:
                if re.fullmatch(r"[A-Za-z0-9+\-*/. ~]+", transformed):
                    eval(transformed, {"__builtins__": {}}, {})
                    print("None")
                else:
                    print("An error occured")
            except Exception:
                print("An error occured")
            
            CURRENT_STEP = 0
            continue

        try:
            shellcode_input = input("asm_input> ")
            transformed_shellcode = caesar_shift(shellcode_input)
            shellcode = asm(transformed_shellcode, arch='amd64', os='linux')
            if shellcode:
                print('Compiled shellcode to X86!')
                print(shellcode.hex(' '))
        except Exception:
            print('Could not compile shellcode. Exiting...')
            exit()
            
    except (KeyboardInterrupt, EOFError):
        break
    except Exception:
        print("An error occured")