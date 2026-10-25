#!/bin/sh
# cron-fixture — verify the cron wildcard-injection scan field offsets
#
# Extracts the awk program between '# cronscan' markers in sysmap.sh,
# rewrites the /etc/ path prefixes to a fixture tree, and replays:
#   - 7-field system crontab (/etc/crontab, /etc/cron.d/*): cmd at $7
#   - 4-field anacrontab: cmd at $4
#   - 6-field user spool: cmd at $6
#   - @reboot forms (system $3, user $2)
#   - glob arguments (tar cf out.tar /src/*), not schedule wildcards
#
# Usage: tests/cron-fixture.sh [sysmap.sh]   Exit: 0 pass, 1 fail.

SM=${1:-./sysmap.sh}
fail=0
fix=$(mktemp -d) || exit 1
trap 'rm -rf "$fix"' EXIT INT TERM
prog=$(awk '/^ *# cronscan$/{f=1;next} /^ *# cronscan-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: cronscan markers not found in %s\n' "$SM"; exit 1; }
prog=$(printf '%s\n' "$prog" | sed "s|/etc/|$fix/|g")

mkdir -p "$fix/cron.d"
# 7-field system format: user at $6, command at $7 — tar + glob arg FLAGGED
printf '10 2 * * * root tar czf /backup/home.tgz /home/*\n' > "$fix/cron.d/backup"
# @reboot in system format: command at $3 — cp + glob arg FLAGGED
printf '@reboot root cp /tmp/boot-* /var/log/boot/\n' > "$fix/cron.d/reboot-copy"
# 6-field user spool format: command at $6 — rsync + glob arg FLAGGED
printf '15 3 * * * rsync -a /srv/*/ /bkp/\n' > "$fix/spool-user"
# anacrontab 4-field: command at $4 — tar + glob arg FLAGGED
printf '1 5 daily-backup tar cf /var/bk/daily-*.tar /etc\n' > "$fix/anacrontab"
# schedule-field wildcards are NOT commands — must NOT flag
printf '*/15 * * * * root run-parts /etc/cron.15min\n' > "$fix/crontab"
# schedule wildcard + safe command — must NOT flag
printf '0 * * * * root /usr/local/bin/hourly-ship\n' > "$fix/cron.d/ship"
# var assignment lines skipped
printf 'MAILTO=admin\n1 2 3 4 5 root /bin/true\n' > "$fix/cron.d/mailto"

out=$(awk "$prog" "$fix/crontab" "$fix/cron.d/backup" "$fix/cron.d/reboot-copy" \
      "$fix/cron.d/ship" "$fix/cron.d/mailto" "$fix/spool-user" "$fix/anacrontab" 2>&1)

expect_n=4
got_n=$(printf '%s\n' "$out" | grep -c 'wildcard cmd')
[ "$got_n" = "$expect_n" ] || { printf 'FAIL: expected %d flags, got %d:\n%s\n' "$expect_n" "$got_n" "$out"; fail=1; }

printf '%s\n' "$out" | grep -q 'cron.d/backup'  || { printf 'FAIL: system crontab $7 not scanned\n'; fail=1; }
printf '%s\n' "$out" | grep -q 'reboot-copy'    || { printf 'FAIL: @reboot system-format $3 not scanned\n'; fail=1; }
printf '%s\n' "$out" | grep -q 'spool-user'     || { printf 'FAIL: 6-field spool $6 not scanned\n'; fail=1; }
printf '%s\n' "$out" | grep -q 'anacrontab'     || { printf 'FAIL: anacrontab $4 not scanned\n'; fail=1; }
printf '%s\n' "$out" | grep -q 'cron.d/ship'    && { printf 'FAIL: safe command falsely flagged\n'; fail=1; }
printf '%s\n' "$out" | grep -q 'crontab.*run-parts' && { printf 'FAIL: schedule wildcard falsely flagged\n'; fail=1; }

[ "$fail" -eq 0 ] && printf 'cron-fixture: ALL PASS\n'
exit "$fail"
