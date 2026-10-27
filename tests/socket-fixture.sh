#!/bin/sh
# socket-fixture — runtime-socket severity must respect ancestor-directory
# traversal: connect(2) on a unix domain socket needs +x on every parent
# (path_resolution(7)), so a 777 socket inside 0700 dirs is unreachable
# by non-root (dockerd 29.x pattern). Also: non-writable socket modes
# print · (inventory), not !.
#
# Usage: tests/socket-fixture.sh [sysmap.sh]   Exit: 0 pass, 1 fail.

SM=${1:-./sysmap.sh}
fail=0
fix=$(mktemp -d) || exit 1
trap 'rm -rf "$fix"' EXIT INT TERM

# extract _sock_traversable between markers
prog=$(awk '/^# sockscan$/{f=1;next} /^# sockscan-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: sockscan markers not found in %s\n' "$SM"; exit 1; }
printf '%s\n' "$prog" > "$fix/fn.sh"
. "$fix/fn.sh"

# --- Case 1: 777 socket inside 0700 dir (dockerd pattern) — NOT traversable
d1="$fix/run/docker"
mkdir -p "$d1"
chmod 700 "$d1"
mkfifo "$d1/test.sock" 2>/dev/null || :  # fixture stands in for socket type
if _sock_traversable "$d1/test.sock" 2>/dev/null; then
    printf 'FAIL: 777 socket in 0700 dir should NOT be traversable\n'
    fail=1
else
    printf 'ok   777 socket in 0700 dir -> not traversable (masked)\n'
fi

# --- Case 2: 777 socket inside 755 chain — traversable, real finding
d2="$fix/run2/pub"
mkdir -p "$d2"
chmod 755 "$fix" "$fix/run2" "$d2"
mkfifo "$d2/test.sock" 2>/dev/null || :
if _sock_traversable "$d2/test.sock" 2>/dev/null; then
    printf 'ok   777 socket in 755 chain -> traversable (real !!)\n'
else
    printf 'FAIL: 777 socket in 755 chain SHOULD be traversable\n'
    fail=1
fi

# --- Case 3: 750 dir blocks others even under a 755 parent
d3="$fix/run3/limited"
mkdir -p "$d3"
chmod 755 "$fix/run3"
chmod 750 "$d3"
mkfifo "$d3/test.sock" 2>/dev/null || :
if _sock_traversable "$d3/test.sock" 2>/dev/null; then
    printf 'FAIL: 777 socket under 750 dir should NOT be traversable\n'
    fail=1
else
    printf 'ok   777 socket under 750 dir -> not traversable (masked)\n'
fi

# --- Case 4: root is always traversable (mode 755 on /)
if _sock_traversable "/tmp/anything.sock" 2>/dev/null; then
    printf 'ok   /tmp chain -> traversable\n'
else
    printf 'FAIL: /tmp chain should be traversable\n'
    fail=1
fi

[ "$fail" -eq 0 ] && printf 'socket-fixture: ALL PASS\n'
exit "$fail"
