# Design — decisions and their reasons

## Single file of POSIX sh

The whole tool is one `#!/bin/sh` file that parses under bash, dash, and
busybox ash. Constraint set enforced throughout:

- No arrays, no `[[ ]]`, no `${var//}`, no `<<<`, no `$'...'`
- `$((0x1f))` hex arithmetic only (never `$((16#1f))` — dash aborts on it)
- awk: POSIX functions only — no `{n,m}` intervals (mawk silently
  no-matches), no `gensub`/`strtonum`; hex decoding via `index()` on a
  digit table
- grep: no `-P`; `find`: no `-printf` (busybox lacks both)
- `stat -c '%a %u %g %n'` is the portable core (GNU/busybox/uutils all
  agree); numeric `%u/%g`, never `%U/%G`
- Accepted extensions, documented in the header: `local`,
  `find -maxdepth` — universal on Linux targets

Portability was verified against live Alpine/busybox 1.36, Debian dash +
mawk, and GNU/uutils toolchains during development, not assumed from
cheat sheets.

## Read-only, provably

Every check reads files, `/proc`, `/sys`, or process listings. The design
rule during development: if a check needs to execute anything with effects,
it doesn't ship. The `-o FILE` flag is the single sanctioned write, probed
with `: > FILE` before `exec >` because a failed exec-redirect exits the
shell on dash/ash before any error handler could run.

## One stream, two renderers

Module bodies print plain text with `!!`/`!`/`·` markers. A single awk
filter — the *only* consumer — normalizes marker spacing, counts severities,
emits JSONL in `--json` mode, and decides the exit code. Findings printed
inside `cmd | while read` subshells (where shell counters would silently
vanish) are counted correctly because the counting happens one process
over, in the filter.

This post-hoc design was chosen over an `emit()` helper after counting the
cost: ~124 printf sites across modules, ~15 findings printed from *inside*
awk programs (unreachable from a shell helper), and three existing
pipe-into-`while` subshells that would lose shell-side counters.

## Exit contract: findings are data

`0` completed · `1` runtime failure · `2` `--fail-on` gate · `64` usage
error. This follows the established audit-tool split: Lynis, Trivy, semgrep,
and checkov all default to exit 0 with findings present, because a scanner
that exits non-zero on findings cannot be cron'd or CI'd safely. The
findings-gate (`--fail-on` → exit 2) is opt-in, mirroring semgrep `--error`,
Trivy `--exit-code`, checkov `--hard-fail-on`. Error and findings codes are
never conflated (the acknowledged gitleaks mistake). `64` is sysexits
`EX_USAGE`, matching Lynis.

The exit code is the awk filter's own exit status — the last command of the
one pipeline in the program, so POSIX's lack of `pipefail` never matters.

## Truncation detection

Each module run ends with an `\001rc=N` sentinel line (control-char
prefixed; genuine module output can never start with one). The filter
counts sentinels (`sent`) and module banners (`bcount`); either count
coming in below the scheduled module count forces exit 1. A survey that
died mid-module therefore cannot print "survey complete" — the two failure
channels (module failed with rc≠0, module never finished) are both
covered. `-E`/`-a` values reject control characters so a hostile value
can't forge sentinels or findings through the header.

## Root calibration

`[ -w ]` and `[ -r ]` are always true for root. Run as root, the PATH and
ld.so writability checks switch to mode-bit analysis (group/world-writable
bits), and SSH-key severity switches from readability to mode+ownership —
otherwise every root run would drown in false `!!` noise, which is how
reports get ignored.

## Secrets are paths, never contents

The secrets module reports file paths, modes, and sizes. The single
exception — credential indicators in package-manager configs — prints the
matching line because `password=` with nothing after it is useless as a
finding. File contents are never dumped.

## Output schema discipline

JSONL records are self-describing (schema version, timestamp, host,
engagement, auditor on every line — the osquery logging discipline) so they
survive concatenation and log shipping. The schema string is versioned
(`sysmap.finding/v1`) so a v2 can add fields without breaking v1 consumers.

## History

v1.0.0 grew out of a private lab tool. The check inventory draws on public
privesc methodology (HackTricks, GTFOBins, g0tmi1k) — the techniques are
common knowledge; the implementation, vocabulary, and structure are
original. Several early bugs were caught by adversarial review passes
before release: a byte-order error in the IPv4 hex decoder, a gawk-only
`strtonum` call that silently killed the `/proc/net` fallback on busybox,
and an exit-code inversion that made every clean root run look like a
failure.
