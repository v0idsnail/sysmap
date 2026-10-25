#!/bin/sh
# spool-fixture — replay canned stat(1) output through the sched spool
# severity table (_ssline/_ssstat) using a PATH-shimmed stat. No root,
# no real spool dirs touched; identical on every platform.
#
# Covers the 1.1.1 fix: Debian's at(1) spool dir is daemon:daemon 1770,
# not root:crontab — the 1.1.0 exemption keyed only on group 'crontab',
# so stock atjobs flagged '! ... executes as uid 1' (found live on
# trixie 2026-10-25; the runbook's at control had never run because
# `at` was missing from its setup line).
#
# Usage: tests/spool-fixture.sh [sysmap.sh]   Exit: 0 pass, 1 fail.

SM=${1:-./sysmap.sh}
fail=0
fix=$(mktemp -d) || exit 1
trap 'rm -rf "$fix"' EXIT INT TERM

prog=$(awk '/^# ssline$/{f=1;next} /^# ssline-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: ssline markers not found in %s\n' "$SM"; exit 1; }
printf '%s\n' "$prog" > "$fix/ssline.sh"
. "$fix/ssline.sh"

# shim stat(1): answers only the exact -c formats sysmap uses, from a
# fixed path->mode/uid/gid table. Unknown path or format fails loudly.
mkdir -p "$fix/bin"
cat > "$fix/bin/stat" <<'EOF'
#!/bin/sh
fmt=$2; p=$3
row=$(printf '%s\n' \
    "/var/spool/cron/crontabs 1730 0 997" \
    "/var/spool/cron/atjobs 1770 1 1" \
    "/var/spool/cron/eviljobs 1770 1 1" \
    "/var/spool/cron/crontabs/alice 600 1000 1000" \
    "/var/spool/cron/crontabs/alice.ww 666 1000 1000" \
    "/var/spool/cron/crontabs/root.ww 666 0 0" \
    "/etc/crontab.user 644 1000 1000" \
    "/etc/cron.d.ww 666 0 0" \
    | awk -v p="$p" '$1==p{print; exit}')
[ -n "$row" ] || { printf 'shim-stat: no table row for %s\n' "$p" >&2; exit 1; }
set -- $row
mode=$2 uid=$3 gid=$4
name() { case $1 in 0) echo root ;; 1) echo daemon ;; 997) echo crontab ;; *) echo alice ;; esac; }
case $fmt in
    '%a %u %g %n') printf '%s %s %s %s\n' "$mode" "$uid" "$gid" "$p" ;;
    '%G')          name "$gid" ;;
    '%U %G')       printf '%s %s\n' "$(name "$uid")" "$(name "$gid")" ;;
    *)             printf 'shim-stat: unexpected -c %s\n' "$fmt" >&2; exit 1 ;;
esac
EOF
chmod +x "$fix/bin/stat"
PATH="$fix/bin:$PATH"
export PATH

chk() {
    got=$(_ssstat "$1" "$2")
    if [ "$got" != "$3" ]; then
        printf 'FAIL: %s (flag %s)\n  want: %s\n  got:  %s\n' "$1" "$2" "$3" "$got"
        fail=1
    fi
}

# stock crontab(1) spool dir — setgid mechanism, reported clean
chk /var/spool/cron/crontabs y \
   '· 1730 0 997 /var/spool/cron/crontabs (debian crontab(1) spool mechanism)'

# stock at(1) spool dir — the 1.1.1 fix (daemon:daemon, not root:crontab)
chk /var/spool/cron/atjobs y \
   '· 1770 1 1 /var/spool/cron/atjobs (debian at(1) spool mechanism)'

# same ownership+mode off the atjobs path — exemption must NOT apply
chk /var/spool/cron/eviljobs n \
   '! 1770 1 1 /var/spool/cron/eviljobs (group/world-writable, executes as uid 1)'

# user spool file, mode 600 — stock mechanism, silent even with flag y
chk /var/spool/cron/crontabs/alice y ''

# user spool file made writable — '!' keyed to the owning uid
chk /var/spool/cron/crontabs/alice.ww n \
   '! 666 1000 1000 /var/spool/cron/crontabs/alice.ww (group/world-writable, executes as uid 1000)'

# root spool file made writable — '!!'
chk /var/spool/cron/crontabs/root.ww n \
   '!! 666 0 0 /var/spool/cron/crontabs/root.ww (group/world-writable)'

# non-spool paths keep the generic severity table
chk /etc/crontab.user n \
   '!! 644 1000 1000 /etc/crontab.user (non-root-owned)'
chk /etc/cron.d.ww n \
   '!! 666 0 0 /etc/cron.d.ww (group/world-writable)'

[ "$fail" -eq 0 ] && printf 'spool-fixture: ALL PASS\n'
exit "$fail"
