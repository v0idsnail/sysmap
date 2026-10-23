# Changelog

All notable changes to sysmap. Format follows Keep a Changelog; versioning
follows SemVer.

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
