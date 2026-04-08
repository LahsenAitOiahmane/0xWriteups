#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "== STRINGS FILTER (satellite) =="
strings -n 4 ./satellite | egrep -ni 'sat|code|key|flag|htb\{|error|usage|control|transmit|auth|password|enter|token|decrypt|encrypt' || true

echo "== STRINGS FILTER (library.so) =="
strings -n 4 ./library.so | egrep -ni 'sat|code|key|flag|htb\{|error|usage|control|transmit|auth|password|enter|token|decrypt|encrypt' || true

echo "== STRINGS HEAD (satellite) =="
strings -n 4 ./satellite | head -n 140

echo "== STRINGS HEAD (library.so) =="
strings -n 4 ./library.so | head -n 200

echo "== SYMBOLS (satellite: dynamic) =="
readelf -Ws ./satellite

echo "== SYMBOLS (library.so: dynamic) =="
readelf -Ws ./library.so

echo "== NM -D (satellite) =="
nm -D ./satellite || true

echo "== NM -D (library.so) =="
nm -D ./library.so || true

echo "== OBJDUMP -d (satellite: main-ish) =="
objdump -d -Mintel ./satellite | egrep -n '(<main>|<__libc_start_main@plt>|call|cmp|jne|je|jz|jnz|printf@plt|puts@plt|scanf@plt|fgets@plt|getenv@plt|strcmp@plt|memcmp@plt|strlen@plt)' | head -n 260 || true

echo "== OBJDUMP satellite main (full) =="
objdump -d -Mintel ./satellite | sed -n '/<main>:/,/^$/p'

echo "== OBJDUMP library send_satellite_message (0x25d0..) =="
objdump -d -Mintel --start-address=0x25b0 --stop-address=0x2700 ./library.so

echo "== OBJDUMP library .rodata (head) =="
objdump -s -j .rodata ./library.so | head -n 220 || true

echo "== GREP HTB{ (strings) =="
(strings -n 4 ./satellite ./library.so | grep -n 'HTB{' ) || true
