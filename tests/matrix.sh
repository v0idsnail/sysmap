#!/bin/sh
# matrix — run sysmap under every available shell and validate the exit
# contract, JSONL well-formedness, and module sentinels.
#
# Uses only what is installed (bash always; dash/busybox when present).
# Exit: 0 all runs clean, 1 any failure.

SM=${1:-./sysmap.sh}
fail=0
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT INT TERM

# sanity: exactly one banner and one rc sentinel per module
sentinels() { # outfile nmod_expected
    b=$(grep -c '^==\[ ' "$1" 2>/dev/null || printf 0)
    s=$(grep -c "$(printf '\001')rc=" "$1" 2>/dev/null || printf 0)
    [ "$b" = "$2" ] && [ "$s" = "$2" ] && return 0
    printf '  sentinels: banners=%s rc=%s (want %s)\n' "$b" "$s" "$2"
    return 1
}

run_one() { # label shell_binary
    sh_=$2
    command -v "$sh_" >/dev/null 2>&1 || { printf 'skip %s (not installed)\n' "$1"; return 0; }
    out=$tmp/"$1".txt
    "$sh_" "$SM" >"$out" 2>"$tmp/$1.err"
    rc=$?
    ok=1
    [ "$rc" -eq 0 ] || { printf 'FAIL %s: exit %d\n' "$1" "$rc"; ok=0; }
    sentinels "$out" 8 || { printf 'FAIL %s: sentinel count\n' "$1"; ok=0; }
    grep -q 'survey complete' "$out" || { printf 'FAIL %s: no completion footer\n' "$1"; ok=0; }
    # json well-formed under this shell
    "$sh_" "$SM" --json 2>/dev/null | jq -e -c . >/dev/null 2>&1 \
        || { printf 'FAIL %s: JSONL not jq-clean\n' "$1"; ok=0; }
    # usage error contract
    "$sh_" "$SM" no-such-module >/dev/null 2>&1
    [ "$?" -eq 64 ] || { printf 'FAIL %s: usage exit != 64\n' "$1"; ok=0; }
    # fail-on gate
    "$sh_" "$SM" --fail-on warn >/dev/null 2>&1
    [ "$?" -eq 2 ] || { printf 'FAIL %s: fail-on warn exit != 2\n' "$1"; ok=0; }
    [ "$ok" -eq 1 ] && printf 'ok   %s (%s)\n' "$1" "$sh_"
    [ "$ok" -eq 1 ] || fail=1
}

printf 'sysmap matrix: %s\n' "$SM"
run_one sh    sh
run_one bash  bash
run_one dash  dash
run_one busybox-ash busybox   # busybox sh

# awk-variant spot check: JSON escaping of backslashes via engagement tag
for awkbin in awk gawk mawk busybox; do
    command -v "$awkbin" >/dev/null 2>&1 || { printf 'skip awk:%s (not installed)\n' "$awkbin"; continue; }
    line=$(PATH="$(dirname "$(command -v "$awkbin")"):/usr/bin:/bin" \
        "$SM" --json -E 'FIX\2026' 2>/dev/null | grep '"engagement"' | head -1)
    printf '%s' "$line" | grep -q '"FIX\\\\2026"' \
        && printf 'ok   awk:%s backslash escaping\n' "$awkbin" \
        || { printf 'FAIL awk:%s backslash escaping: %s\n' "$awkbin" "$line"; fail=1; }
done

[ "$fail" -eq 0 ] && printf 'matrix: ALL PASS\n'
exit "$fail"
