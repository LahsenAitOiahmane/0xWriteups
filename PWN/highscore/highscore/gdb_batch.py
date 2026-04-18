import subprocess
import re

def run_gdb():
    # Use a simpler input file
    with open("input.txt", "w") as f:
        f.write("1\nAAAA\n4\n")

    # GDB script using 'run < input.txt' and 'quit' at the end
    gdb_script = """set disable-randomization off
break *main+0x204
run < input.txt
p/x $rbp
p/x *(unsigned long long*)($rbp+0x10)
p/x ((unsigned long long)*(unsigned long long*)($rbp+0x10) - (unsigned long long)$rbp)
quit
"""
    with open("gdb_script.txt", "w") as f:
        f.write(gdb_script)

    # Use a timeout to prevent hanging
    try:
        process = subprocess.Popen(['gdb', '-batch', '-x', 'gdb_script.txt', './highscore'],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        return ["Timeout", "Timeout", "Timeout"]
    
    rbp = re.search(r'\$1 = (0x[0-9a-f]+)', stdout)
    rbp_plus_10 = re.search(r'\$2 = (0x[0-9a-f]+)', stdout)
    delta = re.search(r'\$3 = (0x[0-9a-f]+)', stdout)
    
    return [rbp.group(1) if rbp else "N/A", 
            rbp_plus_10.group(1) if rbp_plus_10 else "N/A", 
            delta.group(1) if delta else "N/A"]

results = []
for i in range(8):
    results.append(run_gdb())

print(f"| Run | $rbp | [$rbp+0x10] | Delta |")
print(f"|---|---|---|---|")
for i, res in enumerate(results):
    print(f"| {i+1} | {res[0]} | {res[1]} | {res[2]} |")

deltas = set([res[2] for res in results])
if len(deltas) == 1 and "N/A" not in deltas:
    print(f"\nConclusion: Delta stays constant at {list(deltas)[0]}.")
else:
    print(f"\nConclusion: Delta is NOT constant. Unique deltas: {deltas}")
