#!/bin/sh
# procnet-fixture — verify the /proc/net fallback decoder in sysmap.sh
#
# Extracts the awk program between the '# procnet-decode' markers in
# sysmap.sh and replays crafted /proc/net/{tcp,tcp6,udp,udp6} lines,
# asserting decoded addresses and ports.
#
# Usage: tests/procnet-fixture.sh [path-to-sysmap.sh]   (default ./sysmap.sh)
# Exit: 0 all assertions pass, 1 any failure.

SM=${1:-./sysmap.sh}
fail=0

prog=$(awk '/^ *# procnet-decode$/{f=1;next} /^ *# procnet-decode-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: procnet-decode markers not found in %s\n' "$SM"; exit 1; }

# run S V6 PF  — feeds a header line plus $* as socket lines
run() {
    printf 'sl local_address rem_address st tx_queue rx_queue tr tm when retrnsmt uid timeout inode\n%s\n' "$1" \
        | awk -v S="$2" -v V6="$3" -v PF="$4" "$prog"
}

check() { # name expected actual
    if [ "$2" = "$3" ]; then
        printf 'ok   %s\n' "$1"
    else
        printf 'FAIL %s: expected [%s] got [%s]\n' "$1" "$2" "$3"
        fail=1
    fi
}

# --- IPv4: port must decode from all 4 hex digits (v1.0.1 bug: only 2) ---
check 'v4 wildcard ssh 22'  'tcp 0.0.0.0 22 uid=0'    "$(run '0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1234 1' 0A 0 tcp)"
check 'v4 loopback 8080'    'tcp 127.0.0.1 8080 uid=0' "$(run '1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1235 1' 0A 0 tcp)"
check 'v4 443 (01BB)'       'tcp 0.0.0.0 443 uid=100' "$(run '2: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 100 0 1236 1' 0A 0 tcp)"
check 'v4 mysql 3306 (0CEA)' 'tcp 10.0.3.5 3306 uid=999' "$(run '3: 0503000A:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 999 0 1237 1' 0A 0 tcp)"
check 'v4 udp dns 53'       'udp 0.0.0.0 53 uid=98'   "$(run '4: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 98 0 1238 1' 07 0 udp)"

# --- IPv6: kernel stores four little-endian 32-bit words (v1.0.1 bug: none) ---
check 'v6 loopback ::1'     'tcp6 ::1 22 uid=0'       "$(run '5: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1239 1' 0A 1 tcp6)"
check 'v6 wildcard ::'      'tcp6 :: 22 uid=0'        "$(run '6: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1240 1' 0A 1 tcp6)"
check 'v6 mapped loopback'  'tcp6 ::ffff:127.0.0.1 5432 uid=0' "$(run '7: 0000000000000000FFFF00000100007F:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1241 1' 0A 1 tcp6)"
check 'v6 global addr'      'tcp6 2a01:4f9:1:2::5 443 uid=0' "$(run '8: f904012a020001000000000005000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1242 1' 0A 1 tcp6)"

[ "$fail" -eq 0 ] && printf 'procnet-fixture: ALL PASS\n'
exit "$fail"
