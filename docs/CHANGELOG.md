# Changelog

All notable changes to sysmap. Format follows Keep a Changelog; versioning
follows SemVer.


## [1.1.0] — 2026-10-25

False-positive sweep, decoder and output-format bug fixes, and coverage
gaps — from a ten-lens adversarial review. Severity recalibration changes
exit codes under `--fail-on` on hosts that were previously false-flagged;
`--fail-on info` now also counts `·` findings (previously it counted
only `!!` and `!` findings). If you gate CI on exit codes, re-baseline

### Fixed
- sched: every per-user crontab/at spool file was flagged `!! non-root-
  owned` on stock Debian/Ubuntu/RHEL/Fedora/Arch — the documented 1730/
  crontab exemption sat in an unreachable branch and tested the spool
  *directory's* mode. Per-user spools execute as their owner; only write
  bits are checked now. Debian's at-spool dirs (1770 root:crontab) join
  the exemption.
- secrets: SSH key mode check tested write bits while the message said
  readable — a world-readable 0644 key fell through to `· owner-only`;
  a non-root user's own mode-600 key was `!! readable` (readable by its
  owner, i.e. you). Read bits are the signal now; own keys are context.
- netsurf: `/proc/net` fallback decoded ports from 2 of 4 hex digits
  (port 22 read as 0) and IPv6 addresses without the kernel's little-
  endian 32-bit word swap (`::1` decoded to `::100:0`, escaping loopback
  classification). IPv4-mapped addresses render dotted.
- report: JSONL backslash escaping was a no-op on mawk ≤1.3.4-20200925
  (Debian 11/12, Ubuntu 20.04/22.04 default awk) — records with raw
  backslashes that jq rejects; fixed with a `&&` replacement. Metadata
  (host/engagement/auditor/ts) passed via environment, not `awk -v`,
  whose backslash-escape processing silently rewrote tags like
  `ENG\2026`. Invalid UTF-8 bytes in finding text become `?`.
- sched: wildcard-injection scan read field 6 as the command — the user
  field in 7-field system crontabs — so it was inert on exactly the
  root-executed schedules it targets. Format-aware now (system 7-field,
  anacrontab 4-field, `@`-forms) and the glob must be in an argument
  (`tar cf out.tar /src/*`), not the command word.
- hygiene: suid_dumpable=2 is the stock systemd-coredump/abrt default
  and safe (only =1 flags); ASLR =1 is partial, not "full ASLR off"; NFS
  `rw` must be an option token, not a path substring; fstab inventory
  skips swap and kernel interface filesystems (tmpfs entries retained —
  their nosuid/noexec options are the signal).
- contain: every stock container produced `! / mounted rw` +
  `! /proc mounted rw`; the escape-relevant signals are `/sys` and
  `/host` rw. An rw `/proc/sys` (core_pattern) is now reported even when
  the survey runs non-root.
- execsurf: stock shadow-utils newuidmap/newgidmap demoted from `!!`
  (exact-path match — planted copies still flag); cap_net_raw and common
  distro caps to `·`.
- identity: shadow/sudo checks silently skipped on NSS-backed hosts
  (SSSD/FreeIPA, `docker run -u <uid>`); uid falls back to the real
  effective uid. nfsnobody home-ownership false positive on RHEL7
  excluded. Screen sockets no longer double-listed via /var/run.
- report: `--fail-on info` never counted info-severity findings.

### Added
- execsurf: SUID/SGID and capability scans enumerate real filesystems
  from /proc/self/mountinfo (per-mount `-xdev` walks) — separately
  mounted /usr, /opt, /var were invisible to the single-root walk.
  Network filesystems are noted, never walked.
- sched: at-job spools probed (`/var/spool/cron/atjobs`, `/var/spool/at`).
- contain: k8s pods with a private cgroup namespace (cgroup v2) are
  detected via pid-1 environment; cap_dac_read_search decoded; readable
  kubelet kubeconfig/client credentials flag `!!`.
- secrets: systemd credential stores (`!!` when group/world-readable),
  `.netrc`, `.aws/credentials`, `.kube/config`, podman `auth.json`;
  docker config.json and cloud-init user-data are content-gated.
- hygiene: missing-yama note (ptrace unrestricted system-wide);
  unprivileged BPF raised to `!`.
- identity: docker/lxd membership raised to `!!` (no password gate),
  matching sec_contain; PATH audit as root flags user-owned writable
  directories.
- tests/: decode and format fixtures (`procnet-fixture.sh`,
  `cron-fixture.sh`) and a shell/awk matrix runner.

### Performance
- Batched stat for cron dirs and systemd unit files (find -exec stat +),
  single awk pass over all cron files, single grep over package-manager
  configs, one awk for CapEff+Seccomp+NoNewPrivs, one awk for the
  defensive-agent scan (also fixes substring false matches), merged
  passwd passes in identity, batched PATH stat, one uname, read instead
  of cat/grep for /proc reads. Dead code removed (`_hex_ip4`, unused
  local).

## [1.0.1] — 2026-10-23

### Fixed
- contain: core_pattern writability no longer trusts `[ -w ]` under uid 0 —
  mode bits claim writable while the container runtime (docker/runc)
  bind-mounts /proc/sys read-only. The covering mount's ro flag from
  /proc/self/mountinfo is now checked first; runtime-masked paths report
  `·` instead of a false `!!`. Found during pre-demo container testing.
- sched: Debian/Ubuntu's stock `/var/spool/cron/crontabs` (mode 1730,
  root:crontab) is no longer flagged `!!` group/world-writable — it is the
  documented setgid crontab(1) mechanism. The exemption keys on the
  resolved group name and exact mode; any other writable spool still
  rates `!!`. Found during Debian pre-demo testing.

## [1.0.0] — 2026-10-23

First public release.

### Added
- Eight survey modules: posture, identity, execsurf, sched, netsurf,
  secrets, contain, hygiene
- Dual output: human text (normalized `!! / ! / ·` markers, summary footer)
  and JSONL (`sysmap.finding/v1` + `sysmap.summary/v1` records)
- Engagement tagging (`-E`), auditor recording (`-a`), report-to-file
  (`-o`)
- CI-safe exit contract: 0 completed / 1 runtime failure / 2 `--fail-on`
  gate / 64 usage error
- Truncation detection: module sentinels + banner counting guarantee a
  truncated run exits 1 instead of printing "survey complete"
- Root-aware severity calibration (mode-bit analysis instead of `[ -w ]` /
  `[ -r ]` when running as uid 0)
- `--list-modules`, `--version`, `--help`, `--quiet`
- Read-only guarantee with documented execution surface and strace
  verification recipe
- Full IPv6 decode in the `/proc/net` fallback (RFC 5952 compression)
- Distro-portable cron spool probing (Debian, RHEL, Arch, Alpine layouts)
- btrfs snapper snapshot exclusion in the capability scan
