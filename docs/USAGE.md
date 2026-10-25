# Usage — complete CLI reference

```
sysmap [OPTIONS] [MODULE ...]
```

Running with no arguments executes all eight modules. Naming modules runs
only those, in the order given. `--help` prints the same summary from the
script header.

## Options

| Option | Argument | Effect |
|---|---|---|
| `-o`, `--output` | `FILE` | Write the report to FILE instead of stdout. Terminal keeps stderr notes. FILE is created (probed first — an unwritable path exits 1 before any scanning starts). |
| `-E`, `--engagement` | `ID` | Tag every line of output — header, each JSONL record — with an engagement/case ID. Control characters rejected (exit 64). |
| `-a`, `--auditor` | `NAME` | Record the auditor name in the run header and every JSONL record. Control characters rejected (exit 64). |
| `--json` | — | Emit JSONL instead of text: one `sysmap.finding/v1` record per finding plus a final `sysmap.summary/v1` record. See [OUTPUT-FORMATS.md](OUTPUT-FORMATS.md). |
| `--fail-on` | `warn` \| `info` | Gate the exit code: `warn` → exit 2 if any `!!` finding exists; `info` → exit 2 if any finding exists (`!!`, `!`, or `·`). Default off. |
| `-q`, `--quiet` | — | Text mode only: suppress `·` informational lines; keep `!!` and `!` findings and the summary. |
| `--no-color` | — | Reserved; output is plain text by default. |
| `--list-modules` | — | Print the module names one per line, exit 0. Machine-readable. |
| `-V`, `--version` | — | Print name, version, copyright, license. Exit 0. |
| `-h`, `--help` | — | Print the usage header. Exit 0. |

## Modules

```
posture  identity  execsurf  sched  netsurf  secrets  contain  hygiene
```

Module names match exactly — glob patterns (`post*`) are rejected with exit
64. Repeated names are deduplicated. See [MODULES.md](MODULES.md) for what
each module checks.

## Exit codes

sysmap follows the audit-tool convention (Lynis, Trivy, semgrep, checkov):
**findings are data, not program failure.** A survey that finds problems
still exits 0 — that is what makes it cron- and CI-safe.

| Code | Meaning |
|---|---|
| `0` | Survey completed. Findings may exist — gate with `--fail-on` if you need otherwise. |
| `1` | Runtime error: a module failed, or the run was truncated (fewer module results arrived than were scheduled). |
| `2` | The `--fail-on` gate tripped at the chosen level. |
| `64` | Usage error: unknown option or module (sysexits `EX_USAGE`, same as Lynis). |

`130` from an interrupt always means the report is incomplete.

## Privilege

Run unprivileged for a quick look; run as root for full coverage. The
difference is real, not cosmetic:

- `/etc/shadow` readability, all sudoers drop-ins (identity)
- every file capability and every listener's owning process (execsurf, netsurf)
- root's crontab and all system units (sched)

The tool calibrates its severity logic for both modes — as root,
`[ -w ]` and `[ -r ]` are always true, so PATH-writability and key-readability
checks switch to mode-bit analysis instead of flooding you with false `!!`
lines.

## Examples

```sh
# Everything, full coverage, evidence to file
sudo sysmap -o sysmap_web01_$(date -u +%Y%m%dT%H%M%SZ).txt

# Only the fast modules on a fragile target
sysmap posture identity netsurf

# Baseline + gate: nightly cron alerts on new notable findings
sudo sysmap --json -E nightly --fail-on warn | your-ingest || alert-oncall

# Diff-friendly text, findings only
sysmap -q hygiene execsurf | sort > today.txt
diff yesterday.txt today.txt

# What modules exist, for scripts
sysmap --list-modules | while read -r m; do ...; done
```

## Performance

Full eight-module run on a workstation-class host: ~15 s (dominated by the
SUID/SGID filesystem walk and capability scan). Module subsets run
proportionally faster. Single process, no background jobs, no network —
safe on production hosts during business hours.

## Self-containment


The script is self-documenting: `--help` prints its own header comment
(usage, flags, module descriptions, exit codes) by reading `$0`, and
`--version` prints embedded constants — no external files are needed for
basic use. The `docs/` directory adds the deeper material (engagement
workflow, JSONL field reference, interpretation guidance) and is meant to
accompany the script for professional use, not enable it.

One consequence: `--help` requires the script to exist as a readable file
at the invoked path. Save-then-run is the supported invocation — which is
also the right habit for any audit tool, since you should review it before
executing it. Piping straight into a shell (`curl … | sh`) leaves `$0`
unresolvable and breaks `--help`/`--version` along with it.

## Dependencies

`awk` and `grep` — both present in busybox, so effectively universal.
Everything else (ss, netstat, getcap, systemctl, getenforce, …) is probed
per-module with fallbacks; missing tools degrade coverage, never the run.
