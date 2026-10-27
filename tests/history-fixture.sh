#!/bin/sh
# history-fixture — credential-shaped lines in shell histories must be
# caught with correct severity tiering; benign near-misses must be
# silent. Pattern philosophy: every pattern demands an assignment or
# auth-flag shape — the opposite of linPEAS's recall-first regex which
# matches "root", "@", "sudo" and hits "grep password README.md".
#
# Usage: tests/history-fixture.sh [sysmap.sh]   Exit: 0 pass, 1 fail.

SM=${1:-./sysmap.sh}
fail=0
fix=$(mktemp -d) || exit 1
trap 'rm -rf "$fix"' EXIT INT TERM

# extract _hist_scan between markers
prog=$(awk '/^# histscan$/{f=1;next} /^# histscan-end$/{f=0} f' "$SM")
[ -n "$prog" ] || { printf 'FAIL: histscan markers not found in %s\n' "$SM"; exit 1; }
printf '%s\n' "$prog" > "$fix/fn.sh"
. "$fix/fn.sh"

# --- benign corpus: every line must produce ZERO output
printf 'grep password README.md\ncd /root/projects\ncat /etc/passwd\nssh admin@10.0.0.5\nsudo systemctl status docker\nopenssl x509 -in cert.pem -text\nping -c 1 8.8.8.8\nhistory | grep ssh\necho "email is foo@bar.com"\nmake -C /src/passwd-check\ncurl https://api.example.com/health\n' \
    > "$fix/benign.hist"

benign_out=$(_hist_scan "$fix/benign.hist" 2>/dev/null)
if [ -n "$benign_out" ]; then
    printf 'FAIL: benign hits (must be zero):\n%s\n' "$benign_out"
    fail=1
else
    printf 'ok   benign corpus: zero hits\n'
fi

# --- credential corpus: must all be caught with correct severity
printf 'mysql -u root --password=Sup3rS3cret\nexport password=hunter2\nsshpass -p MyPw123 ssh host\ncurl -H "Authorization: Bearer eyJhbGci" https://api\npsql --password=xyz host\nAPI_KEY=sk_live_abc123\ndb_secret=p4ssw0rd\nTOKEN=ghp_16C7e\n' \
    > "$fix/creds.hist"

creds_out=$(_hist_scan "$fix/creds.hist" 2>/dev/null)
strong=$(printf '%s\n' "$creds_out" | grep -c '!!' || true)
weak=$(printf '%s\n' "$creds_out" | grep -c '^!' || true)

[ "$strong" -ge 5 ] || { printf 'FAIL: expected >=5 strong (!!), got %s\n%s\n' "$strong" "$creds_out"; fail=1; }
[ "$strong" -ge 5 ] && printf 'ok   strong (!!): %d credential lines caught\n' "$strong"
[ "$weak" -ge 3 ] || { printf 'FAIL: expected >=3 weak (!), got %s\n' "$weak"; fail=1; }
[ "$weak" -ge 3 ] && printf 'ok   weak (!): %d secret-shaped variables caught\n' "$weak"

# --- empty-value suppression: password= must NOT hit
cat > "$fix/empty.hist" <<'EOF'
password=
password=""
password=''
TOKEN=
secret=
EOF
empty_out=$(_hist_scan "$fix/empty.hist" 2>/dev/null)
if [ -n "$empty_out" ]; then
    printf 'FAIL: empty values should be suppressed, got:\n%s\n' "$empty_out"
    fail=1
else
    printf 'ok   empty values: suppressed\n'
fi

[ "$fail" -eq 0 ] && printf 'history-fixture: ALL PASS\n'
exit "$fail"
