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

# banner sanity: exactly one banner per module. The \001rc sentinels are
# internal to the producer->filter stream and never reach the rendered
# report — a clean exit 0 IS the sentinel contract (the filter exits 1
# when sentinels go missing).
banners() { # outfile nmod_expected
    b=$(grep -c '^==\[ ' "$1" 2>/dev/null || printf 0)
    [ "$b" = "$2" ] && return 0
    printf '  banners=%s (want %s)\n' "$b" "$2"
    return 1
}

run_one() { # label command...  (command may be multi-word: "busybox sh")
    label=$1; shift
    cmd=$*
    command -v "$1" >/dev/null 2>&1 || { printf 'skip %s (not installed)\n' "$label"; return 0; }
    out=$tmp/"$label".txt
    $cmd "$SM" >"$out" 2>"$tmp/$label.err"
    rc=$?
    ok=1
    [ "$rc" -eq 0 ] || { printf 'FAIL %s: exit %d\n' "$1" "$rc"; ok=0; }
    banners "$out" 8 || { printf 'FAIL %s: banner count\n' "$1"; ok=0; }
    # json well-formed under this shell (jq optional — skip when absent)
    if command -v jq >/dev/null 2>&1; then
        $cmd "$SM" --json 2>/dev/null | jq -e -c . >/dev/null 2>&1 \
            || { printf 'FAIL %s: JSONL not jq-clean\n' "$label"; ok=0; }
    else
        printf 'skip %s: jq not installed\n' "$label"
    fi
    # usage error contract
    $cmd "$SM" no-such-module >/dev/null 2>&1
    [ "$?" -eq 64 ] || { printf 'FAIL %s: usage exit != 64\n' "$label"; ok=0; }
    # fail-on gate
    $cmd "$SM" --fail-on warn >/dev/null 2>&1
    [ "$?" -eq 2 ] || { printf 'FAIL %s: fail-on warn exit != 2\n' "$label"; ok=0; }
    [ "$ok" -eq 1 ] && printf 'ok   %s (%s)\n' "$label" "$cmd"
    [ "$ok" -eq 1 ] || fail=1
}

printf 'sysmap matrix: %s\n' "$SM"
run_one sh    sh
run_one bash  bash
run_one dash  dash
run_one busybox-ash busybox sh

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
