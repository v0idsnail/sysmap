#!/bin/sh
# path-fixture — exercise the PATH-directory writability audit
# (_pathcheck) against a real temp PATH tree. The filesystem is the
# oracle: real dirs, real symlinks, real stat(1); no shims, no root.
#
# Covers the 1.1.1 fix: a usrmerge-style symlink (mode 777 in its own
# right) must be judged by its TARGET directory (755 -> silent, 777 ->
# !!), not by the link's own mode. 1.1.0 printed "!! group/world-
# writable dir in PATH: /bin" on stock trixie (live 2026-10-25).
#
# Usage: tests/path-fixture.sh [sysmap.sh]   Exit: 0 pass, 1 fail.

SM=${1:-./sysmap.sh}
fail=0
fix=$(mktemp -d) || exit 1
trap 'rm -rf "$fix"' EXIT INT TERM

prog=$(awk '/^# pathscan$/{f=1;next} /^# pathscan-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: pathscan markers not found in %s\n' "$SM"; exit 1; }
printf '%s\n' "$prog" > "$fix/pathcheck.sh"
. "$fix/pathcheck.sh"

mkdir -p "$fix/real755" "$fix/real777" "$fix/own755"
chmod 755 "$fix/real755" "$fix/own755"
chmod 777 "$fix/real777"
ln -s real755 "$fix/link755"      # usrmerge shape: link (own mode 777) -> 755 dir
ln -s real777 "$fix/link777"
ln -s own755  "$fix/link-own"

uid=$(id -u)
savePATH=$PATH
# /usr/bin:/bin appended so stat(1) itself stays resolvable; both are
# root-owned 755 (or a symlink to it) -> silent under the audit.
PATH="$fix/real755:$fix/link755:$fix/real777:$fix/link777:$fix/own755:$fix/link-own:/usr/bin:/bin"

# root branch (mode-bit analysis) — forced via EUID_N regardless of
# the invoking uid; stat is the oracle either way.
EUID_N=0
want=$(printf '%s\n' \
    "!! group/world-writable dir in PATH: $fix/real777" \
    "!! group/world-writable dir in PATH: $fix/link777" | sort)
if [ "$uid" != 0 ]; then
    want=$(printf '%s\n%s\n' "$want" \
        "! PATH dir writable by uid $uid: $fix/real755
! PATH dir writable by uid $uid: $fix/link755
! PATH dir writable by uid $uid: $fix/own755
! PATH dir writable by uid $uid: $fix/link-own" | sort)
fi
got=$(_pathcheck | sort)
if [ "$got" != "$want" ]; then
    printf 'FAIL: root-branch audit mismatch\n--- want ---\n%s\n--- got ---\n%s\n' "$want" "$got"
    fail=1
fi

# unprivileged branch ([ -w ], follows symlinks natively) — only
# meaningful when actually unprivileged
if [ "$uid" != 0 ]; then
    EUID_N=1
    got=$(_pathcheck)
    case $got in
        *"!! writable directory in PATH: $fix/real777"*) ;;
        *) printf 'FAIL: unprivileged branch missed writable %s\n' "$fix/real777"; fail=1 ;;
    esac
    # a symlink to a root-owned 755 dir (/bin on usrmerge hosts, which
    # the test PATH appends) must NOT flag — judged by target, not by
    # the link's own 777 mode. Exact-line match: /usr/bin is a substring
    # of the same shape.
    if printf '%s\n' "$got" | grep -qx '!! writable directory in PATH: /bin'; then
        printf 'FAIL: unprivileged branch judged /bin by symlink mode\n'
        fail=1
    fi

else
    printf 'skip unprivileged [ -w ] branch (running as root)\n'
fi

PATH=$savePATH
[ "$fail" -eq 0 ] && printf 'path-fixture: ALL PASS\n'
exit "$fail"
