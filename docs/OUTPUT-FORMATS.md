# Output formats

sysmap renders both formats from a single internal stream — text and JSONL
can never disagree about counts or ordering.

## Text mode (default)

```text
=== sysmap v1.0.0 | 2026-10-23 14:03:55 CEST | web01 ===
    engagement: ACME-2026-041
    auditor: v0idsnail
    executed as: root (uid 0) | modules:  posture identity
    read-only survey — no changes made to this host

==[ hygiene ]==
·  vm.mmap_min_addr=65536
!  kernel.kptr_restrict=0 (kernel pointers exposed)
!!  world-writable dir without sticky bit: /tmp (mode 777)

=== summary ===
findings: !! 1   ! 1   · 1

notable (!!) findings:
  [hygiene] world-writable dir without sticky bit: /tmp (mode 777)
modules failed: 0
note: run as root for full coverage (...)
review and redact before sharing outside the engagement
=== survey complete — sysmap v1.0.0 ===
```

Marker spacing is normalized by the render filter — every finding line is
exactly `!! `, `!  `, or `·  ` followed by the text, so `grep '^!! '`
counts high findings reliably. `-q` drops the `·` lines.

## JSONL mode (`--json`)

One JSON object per line. Two record types:

### `sysmap.finding/v1` — one per finding

```json
{"schema":"sysmap.finding/v1","ts":"2026-10-23 14:03:33 CEST","host":"web01",
 "engagement":"ACME-2026-041","auditor":"v0idsnail","module":"hygiene",
 "severity":"high","msg":"world-writable dir without sticky bit: /tmp (mode 777)"}
```

| Field | Type | Notes |
|---|---|---|
| `schema` | string | Always `sysmap.finding/v1`. Versioned for forward-compat. |
| `ts` | string | Run-start timestamp (one per run, not per finding — findings within a run share it). |
| `host` | string | Hostname at run time. |
| `engagement` | string | From `-E`; empty string if not given. |
| `auditor` | string | From `-a`; empty string if not given. |
| `module` | string | Module banner the finding appeared under (`posture`, `identity-access`, `execution-surfaces`, `scheduled-work`, `network-surface`, `secrets`, `containers`, `hygiene`). |
| `severity` | string | `high` (`!!`) · `medium` (`!`) · `info` (`·`). |
| `msg` | string | The finding text, JSON-escaped: backslash, quote, tab, CR escaped (mawk-safe replacement form); other control characters stripped; invalid UTF-8 sequences replaced with `?`. |

### `sysmap.summary/v1` — final record

```json
{"schema":"sysmap.summary/v1","ts":"...","host":"web01","engagement":"...",
 "auditor":"...","modules_run":8,"findings":{"high":3,"medium":11,"info":64},
 "module_failures":0}
```

`modules_run` counts module banners that actually rendered — if it is less
than the modules you requested, the run was truncated and the exit code is 1.

### Working with the stream

```sh
# every high finding, one per line, jq-free
sysmap --json | grep '"severity":"high"'

# with jq: per-module severity table
sysmap --json | jq -rs '
  [.[] | select(.schema=="sysmap.finding/v1")]
  | group_by(.module)[] | {module: .[0].module,
      high: map(select(.severity=="high"))|length,
      medium: map(select(.severity=="medium"))|length}'

# ingest only the summary into a tracker
sysmap --json | tail -1
```

Records are self-describing (host + engagement + timestamp on every line) so
they survive log shipping and concatenation without context loss — the same
discipline osquery uses for its JSONL events.
