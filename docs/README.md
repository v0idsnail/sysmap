# sysmap

**A read-only Linux host survey tool in a single file of POSIX sh.**

sysmap surveys a live Linux system for configuration weaknesses and
access-control findings — privilege-escalation surfaces, network exposure,
credential exposure, container posture, kernel hardening — and produces an
evidence-grade report for defenders, consultants, and auditors.

- **Single file, zero dependencies** beyond `awk` and `grep` (both in busybox)
- **Runs everywhere**: bash, dash, busybox ash — Arch, Fedora, Rocky, Debian,
  Alpine, containers, minimal appliances
- **Read-only guarantee**: no files written (except the `-o` file you request),
  no configuration touched, no processes signalled, no network calls
- **Two output formats**: human-readable text with severity markers, and
  JSONL (`sysmap.finding/v1`) for tooling and findings trackers
- **CI-safe exit contract**: findings are data, not failure — gate with
  `--fail-on` when you want otherwise

```
$ sudo sysmap -E ACME-2026-041 -a "v0idsnail" --fail-on warn
=== sysmap v1.0.1 | 2026-10-23 14:03:55 CEST | web01 ===
    engagement: ACME-2026-041
    auditor: v0idsnail
    executed as: root (uid 0) | modules: posture identity execsurf ...
    read-only survey — no changes made to this host

==[ execution-surfaces ]==
!!  /usr/bin/newuidmap cap_setuid=ep — broad capability grant
...
=== summary ===
findings: !! 3   ! 11   · 64
=== survey complete — sysmap v1.0.1 ===
```

## Quick start

```sh
# anywhere, as anyone (partial coverage)
./sysmap.sh

# full coverage — root widens every check
sudo ./sysmap.sh

# engagement report to file, CI gate on notable findings
sudo ./sysmap.sh -o report.txt -E ACME-2026-041 --fail-on warn

# machine-readable stream
sudo ./sysmap.sh --json -E ACME-2026-041 | your-tracker-import
```

## The eight modules

| Module | Surveys |
|---|---|
| `posture` | OS, kernel, init system, virtualization, container markers, defensive tooling presence, MAC status |
| `identity` | accounts, UID-0 anomalies, group memberships, sudo policy, shadow-family readability, sessions |
| `execsurf` | SUID/SGID binaries, file capabilities, PATH writability, dynamic-loader configuration |
| `sched` | cron spools (all distro layouts), systemd timers/units, rc.local, wildcard-injection candidates |
| `netsurf` | listening sockets (ss → netstat → /proc/net fallback), runtime sockets, resolvers, gateway |
| `secrets` | SSH keys, histories, docker/git credentials, cloud-init, config-file credential indicators |
| `contain` | container detection, capability sets, seccomp, mounts, orchestrator tokens, docker/lxd groups |
| `hygiene` | kernel hardening sysctls, NFS exports, sticky bits, world-writable files, mount options |

Each module degrades silently or announces its skip when a tool or file is
unavailable — the survey always completes.

## Documentation

| Doc | Contents |
|---|---|
| [USAGE.md](USAGE.md) | Complete CLI reference — every flag, module, exit code, and example |
| [MODULES.md](MODULES.md) | What each module checks, what findings mean, how to interpret them |
| [OUTPUT-FORMATS.md](OUTPUT-FORMATS.md) | Text markers and the JSONL schema, field by field |
| [ENGAGEMENT-GUIDE.md](ENGAGEMENT-GUIDE.md) | Running sysmap in contracted assessments: baselining, evidence, redaction |
| [DESIGN.md](DESIGN.md) | Architecture decisions and the conventions sysmap follows |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## License

MIT — see [LICENSE](../LICENSE). Sysmap is a defensive audit tool: use it on
systems you own or have written permission to assess.
