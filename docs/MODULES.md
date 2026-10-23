# Modules — what each check means

Severity markers in every module:

| Marker | JSONL severity | Meaning |
|---|---|---|
| `!!` | `high` | Notable finding warranting immediate review |
| `!` | `medium` | Worth examining |
| `·` | `info` | Context — informational, not a finding to fix |

Severity reflects *attack value*, not certainty. A `!` on a hardened box may
be an accepted risk; a `!!` deserves a sentence in your report either way.

---

## posture

OS and platform identification: distribution (os-release with
redhat/alpine/debian fallbacks), kernel, architecture, init system (systemd
markers → `/proc/1/comm`), virtualization (openvz/virtuozzo markers,
`systemd-detect-virt`, hypervisor CPU flag), container environment
(`/.dockerenv`, `/run/.containerenv`, pid-1 cgroup placement, Kubernetes
environment), and the defensive stack: known EDR/AV agents in the process
list (falcon, mdatp, sentinelone, osquery, wazuh, clamav, auditd) and the
MAC framework state (SELinux mode, AppArmor, LSM label).

**Reading the output:** `! no defensive agents found` is the finding most
people skip — on a client server it means your assessment runs unobserved,
which is exactly what you should note. `! no selinux or apparmor markers`
on a RHEL-family box is unusual and worth chasing.

## identity

Current user and groups; the 13 privilege-relevant groups (wheel, sudo,
docker, lxd, disk, shadow, adm, staff, video, backup, operator, lp, mail)
with member lists — `disk` and `shadow` membership rate `!!` (direct
credential/raw-disk access), the admin/container groups rate `!`.
Additional UID-0 accounts (`!!`), system accounts keeping real shells,
home-directory ownership mismatches, shadow-family file existence and
readability by non-root (`!!`), `sudo -n -l` policy capture with
NOPASSWD/SETENV/broad-grant flagging, active sessions, and live
screen/tmux sockets (`!` — other users' sockets are worth checking).

**Reading:** `sudo present, password required to list` means the tool
couldn't read your sudo policy without a password — rerun as root for the
real check.

## execsurf

The classic local privilege-escalation surfaces:

- **SUID/SGID binaries** — one filesystem walk (`-xdev`), every hit matched
  against the interpreter/shell-escape set (awk, python, perl, less, find,
  env, tar, docker, … — the GTFOBins familiars). Known-interpreter SUID
  rates `!!`; everything else `!` for review. btrfs snapper snapshots
  (`/.snapshots/`) are excluded so each binary is reported once.
- **File capabilities** — `getcap -r /`, with `cap_setuid`, `cap_setgid`,
  `cap_sys_admin`, `cap_sys_ptrace`, the DAC overrides, and `cap_sys_module`
  rated `!!`. `cap_net_raw` noted as baseline (ping).
- **PATH audit** — writable directories in PATH. Privilege-calibrated:
  as root, judged by group/world-writable mode bits instead of `[ -w ]`.
- **Dynamic loader** — `/etc/ld.so.preload` entries; writable
  `/etc/ld.so.conf.d` or group/other-writable loader configs.

## sched

Everything that executes on a schedule, across every distro layout: the
eleven cron spool locations (`/etc/crontab`, `/etc/cron.d`, the periodic
dirs, `/var/spool/cron/crontabs`, `/var/spool/cron`, `/etc/crontabs` for
Alpine, `/etc/periodic`, `/etc/anacrontab`), per-file ownership and
write-bit analysis — root-scheduled programs that are non-root-owned or
group/world-writable rate `!!` — Debian/Ubuntu's stock `1730 root:crontab`
spool is recognized as the setgid `crontab(1)` mechanism and reported `·`,
but any other group with write access to a cron spool still rates `!!`.
systemd timers and running services (when
systemd is booted), writable unit files under `/etc/systemd/system`, and
`rc.local` variants. A wildcard-injection scan flags cron commands passing
glob arguments to tar/rsync/cp/chown/zip — the classic
`--checkpoint-action` planting ground — while ignoring schedule-field
wildcards (`* * * * *`).

## netsurf

Listening sockets through a three-tier fallback: `ss` → `netstat` → direct
`/proc/net/{tcp,tcp6,udp,udp6}` parsing with full hex decode (including
RFC-5952-compressed IPv6 — no raw hex in reports). Classification per
listener: all-interfaces binds `!!` unless loopback context justifies them,
specific-address binds `!`, loopback `·`. Container runtime sockets
(docker/containerd/crio/podman) under /run, /var/run, /tmp with
writability analysis. Resolvers, default gateway (decoded from
`/proc/net/route`), and firewall-tool presence — noted, never executed.

**Reading:** `!! udp 0.0.0.0:5355 (systemd-resolved)` — LLMNR on all
interfaces is a name-poisoning surface (Responder-class); on a server it is
usually just disabled in resolved.conf.

## secrets

Credential-bearing material, reported by **path and mode — file contents are
never printed**. SSH private keys under /root, /home, /etc/ssh with
mode-based severity (group/world-readable `!!`; readable-by-you as non-root
`!!`; owner-only as root `·` — that last one is normal). Application
configs that typically hold credentials (`.env`, `wp-config.php`,
`settings.py`, `database.yml`, `config.php`). Histories (sizes only).
Docker registry credential stores (`!!` — base64 auth), git-credentials
files, cloud-init user-data (`!!`), and credential indicators in fstab and
package-manager configs (the matching line, for triage).

**Reading:** this module is your to-triage list, not your to-fix list — a
`· ssh key present (mode 600, owner-only)` on the admin's own host is
correct hygiene.

## contain

Splits on container detection. **Inside a container:** effective capability
set decoded from `/proc/self/status` (sys_admin, sys_ptrace, sys_module,
dac_override → `!!`), seccomp/no_new_privs state, uid-map identity check,
writable `core_pattern` (`!!` — core_pattern-pipe escape; a read-only
`/proc/sys` runtime mount is detected and reported `·`), rw mounts of
`/`, `/host`, `/proc`, `/sys`, readable Kubernetes service-account tokens
(`!!`), visible kubelet data. **On a host:** docker/lxd group membership
(`!!` — both are root-equivalent through their daemons).

## hygiene

Kernel hardening knobs read directly from `/proc/sys` (no sysctl binary
needed): ASLR, yama ptrace_scope, unprivileged BPF, symlink/hardlink/regular
protections, mmap_min_addr, dmesg_restrict, kptr_restrict, suid_dumpable —
each compared against its recommended value. NFS exports with
`rw` + `no_root_squash` (`!!`). Sticky-bit check on /tmp and /var/tmp,
world-writable files under /etc, and a mount-option inventory (nosuid/noexec
coverage) from fstab with a `/proc/self/mountinfo` fallback.

**Reading:** `! kernel.kptr_restrict=0` and `! fs.suid_dumpable=2` are the
two most common workstation findings — both one-line sysctl fixes.
