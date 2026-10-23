# sysmap

A read-only Linux host survey tool in one file of POSIX sh. It sweeps a live
system for privilege-escalation surfaces, network exposure, credential
exposure, container posture, and kernel-hardening gaps — and turns the result
into an evidence-grade report.

**Use it when:**

- you have a shell on a box (assessment, incident, inherited server) and need
  a structured baseline of what's weak before you touch anything
- you are hardening your own machines and want a repeatable before/after diff
- you are auditing systems and want machine-readable findings (JSONL) with a
  CI-friendly exit contract

Zero dependencies beyond `awk` and `grep`; runs under bash, dash, and busybox
ash — Arch, Debian, Alpine, containers, minimal appliances. Read-only by
design: nothing written, nothing reconfigured, no network calls.

```sh
./sysmap.sh                                          # any user, partial coverage
sudo ./sysmap.sh                                     # full coverage
sudo ./sysmap.sh -o report.txt -E ENG-2026-041 --fail-on warn
```

Docs: [README](docs/README.md) · [USAGE](docs/USAGE.md) · [MODULES](docs/MODULES.md) · [OUTPUT FORMATS](docs/OUTPUT-FORMATS.md) · [ENGAGEMENT GUIDE](docs/ENGAGEMENT-GUIDE.md) · [DESIGN](docs/DESIGN.md) · [CHANGELOG](docs/CHANGELOG.md)

MIT — use on systems you own or have written permission to assess.
