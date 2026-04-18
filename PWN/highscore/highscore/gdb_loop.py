import subprocess
import re

print(f"{'run#':<5} {'rbp':<18} {'val10':<18} {'diff':<10}")
print("-" * 55)

for i in range(8):
    with open("input.txt", "w") as f:
        f.write("1\nAAAA\n4\n")
    
    gdb_commands = [
        "break *main+0x204",
        "run < input.txt",
        "print $rbp",
        "print *(unsigned long long*)($rbp+0x10)",
        "quit"
    ]
    
    with open("gdb_script.txt", "w") as f:
        f.write("\n".join(gdb_commands))
    
    result = subprocess.run(["gdb", "-q", "-batch", "-x", "gdb_script.txt", "./highscore"], 
                            capture_output=True, text=True)
    
    # Extract values using regex
    rbp_match = re.search(r"\$1 = \(void \*\) (0x[0-9a-f]+)", result.stdout)
    val_match = re.search(r"\$2 = ([0-9]+)", result.stdout)
    
    if rbp_match and val_match:
        rbp = int(rbp_match.group(1), 16)
        val = int(val_match.group(1))
        diff = val - rbp
        print(f"{i:<5} {hex(rbp):<18} {hex(val):<18} {hex(diff):<10}")
    else:
        print(f"{i:<5} Error parsing output")
