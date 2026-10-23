# Engagement guide — sysmap in contracted assessments

## Positioning

sysmap is the **collection** step of a host assessment. It does not score,
remediate, or benchmark against a framework. Its output is the raw finding
list you triage, verify, and write up.

## The read-only guarantee, precisely

- No files written, except the single `-o FILE` you explicitly request.
- No configuration read-modified, no processes signalled or killed, no
  packages touched.
- No network connections. sysmap never leaves the host.
- External programs executed, complete list (all read-only forms):
  `awk cat date find getcap getenforce grep hostname id ls ps sed ss netstat
  stat sudo systemctl systemd-detect-virt tr uname who`. `systemctl` is
  invoked read-only (`list-timers`, `list-units`); `iptables`/`nft` are
  detected but never executed.
- Verify it yourself if the engagement demands it:

```sh
strace -f -e trace=openat,write,connect -o /tmp/trace.log ./sysmap.sh
grep -E 'O_WRONLY|O_RDWR|connect\(' /tmp/trace.log   # writes: only your -o file; connects: none
```

## Standard workflow

### 1. Baseline before you touch anything

```sh
sudo sysmap --json -E ACME-2026-041 -o baseline.jsonl
# (with -o, stdout is the report copy; or:)
sudo sysmap --json -E ACME-2026-041 > baseline.jsonl
```

Run this the moment you get access, before any hardening work. This is your
"state as found" evidence.

### 2. Triage with the client

Work the `!!` list first, `!` second. Every finding line already carries
the evidence inline (path, mode, user, port, capability) — paste it into the
finding tracker as-is. The `engagement` and `auditor` fields travel with
every record, so imported findings need no post-hoc tagging.

### 3. Re-survey after remediation

```sh
sudo sysmap --json -E ACME-2026-041 > after.jsonl
```

The diff between baseline and after is your remediation evidence:

```sh
jq -rs '.[] | select(.schema=="sysmap.finding/v1") | "\(.severity)\t\(.module)\t\(.msg)"' \
    baseline.jsonl | sort > base.tsv
jq -rs '.[] | select(.schema=="sysmap.finding/v1") | "\(.severity)\t\(.module)\t\(.msg)"' \
    after.jsonl    | sort > post.tsv
diff base.tsv post.tsv
```

Findings that vanish = remediated. Findings that appear = regressions or
your changes' side effects. Both belong in the report.

### 4. Evidence package

Attach to the report:

| Artifact | Role |
|---|---|
| `sysmap_<host>_<engagement>_<timestamp>.txt` (text run, `-o`) | Human-readable appendix |
| `sysmap_<host>_<engagement>_<timestamp>.jsonl` | Machine-readable findings; tracker import |
| The summary footer / `sysmap.summary/v1` record | Methodology statement: modules run, coverage, tool version |

The run header (version, host, timestamp, executing user, engagement,
auditor, read-only statement) is designed to be screenshot-able as the
chain-of-evidence opener for each host section.

## Redaction before sharing

The summary footer says it on every run: **review and redact before sharing
outside the engagement.** Two leak classes to check:

1. **Paths reveal user names and application names** — usually fine in the
   report, sometimes not fine in an appendix the client forwards internally.
2. **Credential-indicator lines** (secrets module) include the *matching
   line* from configs — typically just `password=***`, but verify before the
   report leaves your hands.

A conservative scrub before external sharing:

```sh
sed -E 's/(password|pass|secret|token|key)=[^ ]+/\1=REDACTED/gi' report.txt
```

## Scope and authorization

sysmap runs locally on the host you execute it on — it does not target
remote systems, which keeps it inside the usual host-assessment scope. The
tool prints its authorization reminder in `--help`; the engagement ID
(`-E`) exists precisely so every artifact is traceable to the engagement
that authorized it.

## CI / regression use between engagements

For your own infrastructure (or a client you retain):

```sh
# nightly, alert only on notable findings
sudo sysmap --json --fail-on warn | ingest || oncall

# golden-baseline drift detection on a fleet
for h in $(cat fleet.txt); do
    ssh "$h" sysmap --json -E fleet-baseline | tag-with "$h" >> fleet.jsonl
done
```

Exit code 2 (the gate) is the CI signal; exit 1 means the run itself failed
— never conflate the two in your pipeline logic.
