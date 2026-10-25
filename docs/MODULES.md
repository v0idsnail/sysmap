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
with member lists — `disk`, `shadow`, `docker`, and `lxd` rate `!!` (raw
disk/credential access, or root-equivalence through the container daemon
with no password gate); `wheel`/`sudo` rate `!` (still need credentials).
The uid falls back to the real effective uid on NSS-backed hosts
(SSSD/FreeIPA) and `docker run -u <uid>`, where no passwd entry exists —
otherwise the shadow and `sudo -n -l` checks silently skipped. Additional
UID-0 accounts (`!!`), system accounts keeping real shells, home-directory
ownership mismatches (nobody/nfsnobody at uid 65534 excluded), shadow-family
file existence and readability by non-root (`!!`), `sudo -n -l` policy
capture with NOPASSWD/SETENV/broad-grant flagging, active sessions, and
live screen/tmux sockets (`!` — other users' sockets are worth checking).

**Reading:** `sudo present, password required to list` means the tool
couldn't read your sudo policy without a password — rerun as root for the
real check.

## execsurf

The classic local privilege-escalation surfaces:

- **SUID/SGID binaries** — real filesystems are enumerated from
  `/proc/self/mountinfo` and each is walked with `-xdev`, so SUID binaries
  on separately-mounted `/usr`, `/opt`, or `/var` are visible (a single
  `find / -xdev` stops at every mount boundary). Kernel-interface and
  `nosuid` mounts are skipped; network filesystems (NFS/CIFS/…) are noted,
  never walked — remote I/O, and the share should be audited server-side.
  Hits are matched against the interpreter/shell-escape set (awk, python,
  perl, less, find, env, tar, docker, plus the distro alias names —
  nvim, vim.basic, ncat, nc.openbsd, busybox, …). Known-interpreter SUID
  rates `!!`; everything else `!`. btrfs snapper snapshots are excluded
  from the capability scan so each binary is reported once.
- **File capabilities** — `getcap -r` per mount. `cap_setuid`, `cap_setgid`,
  `cap_sys_admin`, `cap_sys_ptrace`, the DAC overrides, `cap_sys_module`
  rate `!!` — except stock shadow-utils `newuidmap`/`newgidmap` (exact
  path match), which carry `cap_setuid`/`cap_setgid` by design for
  subordinate ranges and rate `·`. `cap_net_raw` (ping) and the common
  distro grants (`net_bind_service`, `ipc_lock`, `sys_nice`, `kill`) rate
  `·`; anything unknown keeps `!`.
- **PATH audit** — writable directories in PATH. Privilege-calibrated:
  as root, group/world-writable mode bits rate `!!` and a PATH directory
  writable by a non-root owner rates `!` (root executes whatever the
  owner plants there); non-root uses `[ -w ]`.
- **Dynamic loader** — `/etc/ld.so.preload` entries; writable
  `/etc/ld.so.conf.d` or group/other-writable loader configs.

## sched

Everything that executes on a schedule, across every distro layout: the
cron spool locations (`/etc/crontab`, `/etc/cron.d`, the periodic dirs,
`/var/spool/cron/crontabs`, `/var/spool/cron`, `/etc/crontabs` for
Alpine, `/etc/periodic`, `/etc/anacrontab`) plus the at-job spools
(`/var/spool/cron/atjobs`, `/var/spool/at`). Per-file ownership and
write-bit analysis, calibrated to what the file is: root-scheduled
programs that are non-root-owned or group/world-writable rate `!!`, but
per-user spool files are *supposed* to be user-owned — crond/atd execute
them as the owner — so only write bits are checked there (writable
root-owned `!!`, writable user-owned `!`). Debian/Ubuntu's stock
`1730`/`1770 root:crontab` spool directories are recognized as the setgid
`crontab(1)` mechanism and reported `·`, as is Debian's `daemon:daemon
1770` at-jobs spool (`at(1)` mechanism). systemd timers and running
services, writable unit files under `/etc/systemd/system`, and `rc.local`
variants. The wildcard-injection scan parses each file in its own format
(7-field system crontabs keep the user at field 6 — the command is field
7; anacrontab is 4-field; `@`-forms shift) and flags the tar/rsync/cp/
chown/zip family receiving glob *arguments* — the classic
`--checkpoint-action` planting ground — while ignoring schedule-field
wildcards (`* * * * *`). Periodic scripts are shell, scanned line-wise
for the same pattern.

## netsurf

Listening sockets through a three-tier fallback: `ss` → `netstat` → direct
`/proc/net/{tcp,tcp6,udp,udp6}` parsing with full hex decode (little-endian
word order, RFC-5952-compressed IPv6, IPv4-mapped addresses rendered
dotted — no raw hex in reports). Classification per
listener: all-interfaces binds `!!` unless loopback context justifies them,
specific-address binds `!`, loopback `·`. Container runtime sockets
(docker/containerd/crio/podman) under /run, /var/run, /tmp with
writability analysis. Resolvers, default gateway (decoded from
`/proc/net/route`), and firewall-tool presence — noted, never executed.

**Reading:** `!! udp 0.0.0.0:5355 (systemd-resolved)` — LLMNR on all
interfaces is a name-poisoning surface (Responder-class); on a server it is
usually just disabled in resolved.conf.

## secrets

Credential files are reported by **path and mode — their contents are
never printed**; the one exception is credential *indicators* in fstab
and package-manager configs, where the matching line is quoted for
triage (treat those lines as sensitive when sharing the report). SSH
private keys under /root, /home, /etc/ssh with mode-based severity
calibrated to read bits: group/world-readable `!!` (a mode-0644 key —
the canonical OpenSSH "Permissions 0644 are too open" case — is the
headline example); your own owner-only key as non-root, or any
owner-only key as root, is `·` — correct hygiene, listed for
completeness. Application configs that typically hold credentials
(`.env`, `wp-config.php`, `settings.py`, `database.yml`, `config.php`).
Histories (sizes only). Docker registry stores are content-gated: `!!`
only when `auths` is non-empty or `credsStore`/`credHelpers` is set — a
config.json holding only contexts or CLI preferences is `·`. systemd
credential stores (`/etc/credstore*`, `/run/credentials/*`) rate `!!`
when group/world-readable, `!` otherwise. `.netrc`, `.aws/credentials`,
`.kube/config`, and podman's `auth.json` are listed `!`.
git-credentials (with mode). cloud-init user-data `!!` only when the
content matches secret-looking patterns; every cloud image has the file.

**Reading:** this module is your to-triage list, not your to-fix list — a
`· ssh key present (mode 600, owner-only)` on the admin's own host is
correct hygiene.

## contain

Splits on container detection (env markers, pid-1 cgroup placement, and —
for pods with a private cgroup namespace on cgroup v2, where
`/proc/1/cgroup` reads `0::/` — `KUBERNETES_SERVICE_HOST` in pid 1's
environment). **Inside a container:** effective capability set decoded
from `/proc/self/status` (sys_admin, sys_ptrace, sys_module,
dac_override, dac_read_search → `!!`), seccomp/no_new_privs state, uid-map
identity check, writable `core_pattern` (`!!` — core_pattern-pipe escape;
a read-only `/proc/sys` runtime mount is detected and reported `·`; an rw
`/proc/sys` is `!!` regardless of the surveying uid), rw mounts of `/sys`
(privileged runtime) and `/host` (hostPath node root) — `/` and `/proc`
are rw in every stock container and are not findings — readable
Kubernetes service-account tokens (`!!`), readable kubelet kubeconfig and
client credentials (`!!`). **On a host:** docker/lxd group membership
(`!!` — both are root-equivalent through their daemons).

## hygiene

Kernel hardening knobs read directly from `/proc/sys` (no sysctl binary
needed): ASLR (partial =1 and off =0 both `!`, distinct messages), yama
ptrace_scope (scope 0 `!`; a missing yama module is noted — ptrace is
then unrestricted system-wide), unprivileged BPF (`!` when enabled — the
CVE-2021-3490 class), symlink/hardlink/regular protections,
mmap_min_addr, dmesg_restrict, kptr_restrict, suid_dumpable (=1
world-readable suid cores `!`; =2 is the stock systemd-coredump default
and safe). NFS exports where `rw` appears as an *option token* together
with `no_root_squash` (`!!`) — a path containing the letters "rw" under a
read-only export is not a finding; no option list means the exports(5)
default, rw. Sticky-bit check on /tmp and /var/tmp, world-writable files
under /etc, and a mount-option inventory (nosuid/noexec coverage) from
fstab with a `/proc/self/mountinfo` fallback (swap and kernel interface
filesystems excluded; tmpfs entries are retained — their nosuid/noexec
options are the hardening signal).

**Reading:** `! kernel.kptr_restrict=0` and
`! kernel.unprivileged_bpf_disabled=0` are the two most common findings —
both one-line sysctl fixes.
