#!/bin/sh
# SPDX-FileCopyrightText: 2026 v0idsnail
# SPDX-License-Identifier: MIT
#
# sysmap — read-only POSIX sh Linux host survey
#
# Surveys a live Linux system for configuration weaknesses and access-control
# findings: privilege-escalation surfaces, network exposure, credential
# exposure, container posture, kernel hardening. Authorized use on systems
# you own or have written permission to assess.
#
# Usage:
#   sysmap [OPTIONS] [MODULE ...]
#
# Modules (default: all):
#   posture   OS, kernel, init, virtualization, container, defensive tooling
#   identity  accounts, groups, sudo policy, shadow files, sessions
#   execsurf  SUID/SGID, capabilities, PATH, dynamic-loader config
#   sched     cron spools, systemd timers/units, rc.local, wildcard injection
#   netsurf   listeners, runtime sockets, resolvers, gateway
#   secrets   keys, histories, credential stores, cloud-init (paths only)
#   contain   container caps/seccomp/mounts, docker/lxd group membership
#   hygiene   kernel sysctls, NFS exports, sticky bits, mount options
#
# Options:
#   -o, --output FILE   write the text report to FILE (stdout stays for notes)
#   -E, --engagement ID tag all output with an engagement/case ID
#   -a, --auditor NAME  record the auditor name in the run header
#       --json          emit JSONL (one record per finding + summary) on stdout
#       --fail-on LVL   exit 2 if findings exist at/above the level:
#                        warn = !! findings · info = any finding
#   -q, --quiet         findings only — suppress · informational lines
#       --no-color      (output is plain text by default; reserved)
#       --list-modules  print module names, one per line, exit 0
#   -V, --version       print version and license, exit 0
#   -h, --help          print this header, exit 0
#
# Exit codes (findings are data, not failure):
#   0   survey completed (findings may exist — gate with --fail-on)
#   1   runtime error: a module failed or the run aborted
#   2   --fail-on gate tripped by findings at the chosen level
#   64  usage error: unknown option or module (sysexits EX_USAGE)
#
# Severity markers:  !!  notable finding   !   worth examining   ·   context
#
# Platform: POSIX sh (bash, dash, busybox ash) — Arch/Fedora/Rocky/Debian/Alpine.
#           Accepted extensions: `local`, find -maxdepth (universal on Linux).
# Read-only guarantee: no files are written (except the -o FILE you request),
#           no configuration touched, no processes signalled, no network calls.
#           External programs executed (all read-only forms): awk cat date
#           find getcap getenforce grep hostname id ls ps sed ss netstat stat
#           sudo systemctl systemd-detect-virt tr uname who.

VERSION="1.0.1"

set -u
LC_ALL=C
export LC_ALL

EUID_N=$(id -u 2>/dev/null) || EUID_N=-1

# ---------------------------------------------------------------------------
# 1. posture — OS, kernel, init, virtualisation, container, defensive tooling
# ---------------------------------------------------------------------------
sec_posture() {
    local os init virt ct m se pslist def t
    os=''; init=''; virt=''; ct=''; m=''; se=''; pslist=''; def=''
    printf '==[ posture ]==\n'
    if [ -r /etc/os-release ]; then
        os=$(awk -F= '$1=="PRETTY_NAME"{sub(/^[^=]*=/,"");gsub(/"/,"");print;exit}' \
             /etc/os-release 2>/dev/null)
    fi
    [ -z "$os" ] && [ -r /etc/redhat-release ]  && os=$(cat /etc/redhat-release 2>/dev/null)
    [ -z "$os" ] && [ -r /etc/alpine-release ]  && os="Alpine $(cat /etc/alpine-release 2>/dev/null)"
    [ -z "$os" ] && [ -r /etc/debian_version ]  && os="Debian $(cat /etc/debian_version 2>/dev/null)"
    [ -n "$os" ] && printf '· os: %s\n' "$os"
    printf '· kernel: %s (%s)\n' "$(uname -sr 2>/dev/null)" "$(uname -m 2>/dev/null)"
    if [ -d /run/systemd/system ]; then
        init="systemd"
    elif [ -r /proc/1/comm ]; then
        read -r init < /proc/1/comm || :
    fi
    printf '· init: %s\n' "${init:-unknown}"
    if [ -d /proc/vz ]; then
        virt="openvz/virtuozzo (/proc/vz)"
    elif [ -d /proc/bc ]; then
        virt="virtuozzo (/proc/bc)"
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        m=$(systemd-detect-virt 2>/dev/null) || m=""
        [ "$m" = "none" ] && m=""
        [ -n "$m" ] && virt="${virt:+$virt, }$m (systemd-detect-virt)"
    fi
    [ -z "$virt" ] && grep -qi hypervisor /proc/cpuinfo 2>/dev/null && virt="hypervisor cpu flag"
    printf '· virt: %s\n' "${virt:-none}"
    if [ -f /.dockerenv ]; then
        ct="docker"
    elif [ -f /run/.containerenv ]; then
        ct="podman"
    elif [ -r /proc/1/cgroup ]; then
        m=$(awk 'match($0,/docker|kubepods|libpod/){print substr($0,RSTART,RLENGTH);exit}' \
            /proc/1/cgroup 2>/dev/null)
        [ -n "$m" ] && ct="$m"
    fi
    [ -r /proc/1/environ ] && grep -q KUBERNETES_SERVICE_HOST /proc/1/environ 2>/dev/null && \
        ct="${ct:+$ct, }kubernetes (pid 1 env)"
    printf '· container: %s\n' "${ct:-none}"
    if command -v ps >/dev/null 2>&1; then
        pslist=$(ps aux 2>/dev/null) || pslist=""
    fi
    if [ -n "$pslist" ]; then
        for t in falcon-sensor mdatp sentinel_agent osqueryd wazuh clamd; do
            printf '%s\n' "$pslist" | grep -qi "$t" 2>/dev/null && def="${def:+$def }$t"
        done
        printf '%s\n' "$pslist" | grep -q '[ /]auditd' 2>/dev/null && def="${def:+$def }auditd"
        if [ -n "$def" ]; then
            printf '· defensive agents running: %s\n' "$def"
        else
            printf '! no defensive agents found in process list\n'
        fi
    fi
    if [ -d /sys/fs/selinux ]; then
        se=""
        command -v getenforce >/dev/null 2>&1 && se=$(getenforce 2>/dev/null)
        if [ -z "$se" ]; then
            for t in /usr/sbin/getenforce /sbin/getenforce; do
                [ -x "$t" ] && { se=$("$t" 2>/dev/null) || :; break; }
            done
        fi
        printf '· selinux: %s\n' "${se:-mounted, mode unknown}"
    fi
    if [ -d /sys/module/apparmor ] && [ -r /proc/self/attr/current ]; then
        m=$(cat /proc/self/attr/current 2>/dev/null) || m=""
        [ -n "$m" ] && printf '· apparmor: %s\n' "$m"
    fi
    if [ ! -d /sys/fs/selinux ] && [ ! -d /sys/module/apparmor ]; then
        printf '! no selinux or apparmor markers found\n'
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 2. identity — user, groups, accounts, sudo, sessions
# ---------------------------------------------------------------------------
sec_identity() {
    local cur_user cur_grps myuid extra0 sl sudobroad sudo_bin socks wsum
    local f g p l m n u s hu hp ou gn gm
    cur_user=''; cur_grps=''; myuid=''; sudo_bin=''
    printf '==[ identity-access ]==\n'
    if command -v id >/dev/null 2>&1; then
        cur_user=$(id -un 2>/dev/null)
        cur_grps=$(id -Gn 2>/dev/null | tr ',' ' ')
    fi
    myuid=$(awk -F: -v u="$cur_user" '$1==u{print $3; exit}' /etc/passwd 2>/dev/null)
    if [ "$myuid" = "0" ]; then
        printf '· running as uid 0 (%s)\n' "${cur_user:-unknown}"
    elif [ -n "$cur_user" ]; then
        printf '· current user %s (uid %s), groups: %s\n' \
               "$cur_user" "${myuid:-?}" "${cur_grps:-none}"
    fi
    [ "$myuid" = "0" ] || for g in $cur_grps; do
        case $g in
            shadow|disk)          printf '!! in the %s group\n' "$g" ;;
            wheel|sudo|docker|lxd) printf '! in the %s group\n' "$g" ;;
        esac
    done
    extra0=$(awk -F: '$3=="0"&&$1!="root"{print $1}' /etc/passwd 2>/dev/null)
    [ -n "$extra0" ] && printf '!! uid 0 besides root: %s\n' \
        "$(printf '%s\n' "$extra0" | awk '{printf "%s%s",(n++?" ":""),$0}')"
    awk -F: '$3>0&&$3<1000&&$7~/(sh|fish)$/{print $1,$3,$7}' /etc/passwd 2>/dev/null | \
        while read -r n u s; do printf '! system account %s (uid %s) shell %s\n' "$n" "$u" "$s"; done
    if command -v stat >/dev/null 2>&1; then
        awk -F: '$3>=1000&&$6!=""&&$6!="/"{print $3,$6}' /etc/passwd 2>/dev/null | \
            while read -r hu hp; do
                ou=$(stat -c '%u' "$hp" 2>/dev/null)
                [ -n "$ou" ] && [ "$ou" != "$hu" ] && \
                    printf '! home %s owned by uid %s (account uid %s)\n' "$hp" "$ou" "$hu"
            done
    fi
    awk -F: 'BEGIN{ng=split("wheel sudo docker lxd disk shadow adm staff video backup operator lp mail",a)}
        $4!=""{for(i=1;i<=ng;i++) if($1==a[i]){
          c=split($4,t,","); m=""
          for(j=1;j<=c;j++) if(t[j]!="root") m=m (m?",":"") t[j]
          if(m!="") print $1, m}}' /etc/group 2>/dev/null | \
        while read -r gn gm; do
            case $gn in
                shadow|disk)           m='!! ' ;;
                wheel|sudo|docker|lxd) m='!  ' ;;
                *)                     m='·  ' ;;
            esac
            printf '%sgroup %s members: %s\n' "$m" "$gn" "$gm"
        done
    for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
        [ -e "$f" ] || { case $f in *-) m='· ';; *) m='! ';; esac; printf '%s%s absent\n' "$m" "$f"; continue; }
        [ -n "$myuid" ] && [ "$myuid" != "0" ] && [ -r "$f" ] && \
            printf '!! %s readable by non-root uid %s\n' "$f" "$myuid"
    done
    for p in sudo /usr/bin/sudo /usr/sbin/sudo /sbin/sudo; do
        command -v "$p" >/dev/null 2>&1 && { sudo_bin=$p; break; }
    done
    if [ -n "$sudo_bin" ] && [ -n "$myuid" ]; then
        sl=$("$sudo_bin" -n -l 2>/dev/null || :)
        if [ "$myuid" != "0" ] && [ -n "$sl" ]; then
            sudobroad=$(printf '%s\n' "$sl" | grep -E 'NOPASSWD|SETENV|\(ALL|ALL$' 2>/dev/null || :)
            if [ -n "$sudobroad" ]; then
                printf '!! broad or passwordless sudo grants for %s:\n' "$cur_user"
                printf '%s\n' "$sudobroad" | awk 'NR<=8' | while read -r l; do printf '· %s\n' "$l"; done
            else
                printf '· sudo rules visible, no unrestricted grant seen\n'
            fi
        elif [ "$myuid" != "0" ]; then
            printf '· sudo present, password required to list\n'
        fi
    fi
    if command -v who >/dev/null 2>&1; then
        wsum=$(who -a 2>/dev/null | \
            awk '$0~/(tty[0-9]+|pts\/[0-9]+|console|:0)/&&$1!~/^(system|reboot|LOGIN|run-level)$/&&$1!~/\//{
                n++; if(!s[$1]++){u=u (u?" ":"") $1}} END{if(n)print n, u}')
        [ -n "$wsum" ] && printf '· active sessions: %s\n' "$wsum"
    fi
    socks=$(ls -1 /run/screen/S-* /var/run/screen/S-* /tmp/tmux-*/* 2>/dev/null || :)
    [ -n "$socks" ] && { printf '! live multiplexer session sockets:\n'
        printf '%s\n' "$socks" | while read -r l; do printf '· %s\n' "$l"; done; }
    return 0
}

# ---------------------------------------------------------------------------
# 3. execsurf — SUID/SGID, capabilities, PATH, ld.so
# ---------------------------------------------------------------------------
sec_execsurf() {
    local d p gc rest seen have_fa m
    printf '==[ execution-surfaces ]==\n'
    have_fa=""
    if command -v find >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
        have_fa=1
    else
        printf '· find or awk unavailable, permission-based scans skipped\n'
    fi
    if [ "$have_fa" ]; then
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | awk '
            BEGIN {
                n = split("awk python python3 perl php ruby node lua less more man \
vi vim vim.tiny find env cp mv tar gzip tee nmap nc socat gdb docker \
kubectl ssh wget curl base64 xxd", k, " ")
                for (i = 1; i <= n; i++) hot[k[i]] = 1
            }
            {
                b = $0; sub(/.*\//, "", b)
                if (b in hot)
                    printf "!! %s — interpreter/shell-escape risk when setuid\n", $0
                else
                    printf "! %s\n", $0
            }'
    fi
    gc=$(command -v getcap 2>/dev/null)
    if [ -z "$gc" ]; then
        for p in /sbin/getcap /usr/sbin/getcap /usr/bin/getcap; do
            [ -x "$p" ] && { gc="$p"; break; }
        done
    fi
    if [ -n "$gc" ] && [ "$have_fa" ]; then
        "$gc" -r / 2>/dev/null | awk '
            /^\/\.snapshots\// { next }   # snapper btrfs snapshots: same files, skip dupes
            /cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_dac_override|cap_dac_read_search|cap_sys_module/ {
                printf "!! %s — broad capability grant\n", $0; next }
            /cap_net_raw/ { printf "! %s (baseline, e.g. ping)\n", $0; next }
            { printf "! %s\n", $0 }'
    elif [ -z "$gc" ]; then
        printf '· getcap not found, capability scan skipped\n'
    fi
    seen=" "
    rest="$PATH:"
    while [ -n "$rest" ]; do
        d=${rest%%:*}; rest=${rest#*:}
        [ -z "$d" ] && d=.
        case "$seen" in *" $d "*) continue ;; esac
        seen="$seen$d "
        if [ -d "$d" ]; then
            if [ "$EUID_N" -eq 0 ]; then
                # root: [ -w ] is always true; judge by group/world write bits instead
                m=$(stat -c '%a' "$d" 2>/dev/null)
                while [ "${#m}" -lt 3 ]; do m="0$m"; done
                [ "${#m}" -eq 4 ] && m=${m#?}
                case $m in ?[2367]?|??[2367]) printf '!! group/world-writable dir in PATH: %s\n' "$d" ;; esac
            elif [ -w "$d" ]; then
                printf '!! writable directory in PATH: %s\n' "$d"
            fi
        fi
    done
    if [ -f /etc/ld.so.preload ] && [ "$have_fa" ]; then
        if [ -r /etc/ld.so.preload ]; then
            awk '!/^[[:space:]]*(#|$)/ { printf "! /etc/ld.so.preload entry: %s\n", $0 }' \
                /etc/ld.so.preload 2>/dev/null
        else
            printf '! /etc/ld.so.preload present, not readable\n'
        fi
    fi
    if [ -d /etc/ld.so.conf.d ] && [ -r /etc/ld.so.conf.d ]; then
        if [ "$EUID_N" -ne 0 ]; then
            [ -w /etc/ld.so.conf.d ] && printf '! /etc/ld.so.conf.d writable\n'
        else
            find /etc/ld.so.conf.d -maxdepth 1 -type f \( -perm -020 -o -perm -002 \) 2>/dev/null | \
                awk '{ printf "! group/other-writable loader config: %s\n", $0 }'
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 4. sched — cron, timers, service units, rc.local
# ---------------------------------------------------------------------------
_ssstat() {
    # $1=path  $2=y|n  (y = report clean entries)
    local s m mo r u w gn
    s=$(stat -c '%a %u %g %n' "$1" 2>/dev/null) || return 0
    m=${s%% *}; r=${s#* }; u=${r%% *}; mo=$m
    while [ "${#m}" -lt 3 ]; do m="0$m"; done
    [ "${#m}" -eq 4 ] && m=${m#?}
    w=0; case $m in ?[2367]?|??[2367]) w=1 ;; esac
    if [ "$u" != "0" ]; then
        printf '!! %s (non-root-owned)\n' "$s"
    elif [ "$w" -eq 1 ]; then
        gn=$(stat -c '%G' "$1" 2>/dev/null)
        if [ "$mo" = 1730 ] && [ "$gn" = crontab ]; then
            # stock Debian/Ubuntu: setgid crontab(1) writes user spools via
            # group 'crontab'; sticky + no world bits. Not a finding.
            [ "$2" = y ] && printf '· %s (debian crontab(1) spool mechanism)\n' "$s"
        else
            printf '!! %s (group/world-writable)\n' "$s"
        fi
    elif [ "$2" = "y" ]; then
        printf '· %s\n' "$s"
    fi
}
sec_sched() {
    local p f cands SCT c ln t w
    printf '==[ scheduled-work ]==\n'
    if ! command -v stat >/dev/null 2>&1; then
        printf '· stat unavailable — scheduled-work module skipped\n'
        return 0
    fi
    cands=''
    for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
              /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs \
              /var/spool/cron /etc/crontabs /etc/periodic /etc/anacrontab; do
        [ -e "$p" ] || continue; [ -L "$p" ] && continue
        _ssstat "$p" y
        if [ -f "$p" ]; then
            cands="$cands $p"
        elif [ -d "$p" ]; then
            for f in $(find "$p" -maxdepth 2 -type f 2>/dev/null); do
                case " $cands " in *" $f "*) continue ;; esac
                cands="$cands $f"; _ssstat "$f" n
            done
        fi
    done
    # Wildcard injection scan: awk extracts only the command field to avoid
    # false-positives on schedule-field wildcards in "* * * * * cmd" lines.
    # Subshell-wrapped so a mid-scan abort cannot leave globbing disabled.
    (
        set -f
        for f in $cands; do
            [ -f "$f" ] || continue
            awk -v fn="$f" '
                !/^[[:space:]]*(#|$)/ && !/^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/ {
                    cmd = ($1 ~ /^@/) ? $2 : (NF >= 6 ? $6 : $NF)
                    if (cmd ~ /[*]/) {
                        base = cmd; sub(/.*\//, "", base)
                        if (base ~ /^(tar|rsync|cp|chown|zip)$/)
                            printf "! wildcard cmd in %s line %d: %s\n", fn, NR, $0
                    }
                }' "$f" 2>/dev/null
        done
    )
    if [ -d /run/systemd/system ] && grep -q systemd /proc/1/comm 2>/dev/null; then
        SCT=''
        for c in "$(command -v systemctl 2>/dev/null)" /usr/sbin/systemctl /sbin/systemctl; do
            [ -n "$c" ] && [ -x "$c" ] && { SCT=$c; break; }
        done
        if [ -n "$SCT" ]; then
            "$SCT" list-timers --all --no-legend --no-pager 2>/dev/null | \
                while IFS= read -r t; do [ -n "$t" ] && printf '· timer %s\n' "$t"; done
            "$SCT" list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | \
                awk '{print "· svc " $1}'
            [ -d /etc/systemd/system ] && find /etc/systemd/system -type f 2>/dev/null | \
                while IFS= read -r f; do _ssstat "$f" n; done
        else
            printf '· systemd present but systemctl not executable — unit checks skipped\n'
        fi
    fi
    for p in /etc/rc.local /etc/rc.d/rc.local /etc/local.d/*.start; do
        [ -f "$p" ] && [ ! -L "$p" ] && _ssstat "$p" y
    done
    return 0
}

# ---------------------------------------------------------------------------
# 5. netsurf — listening sockets, runtime sockets, resolvers, gateway
# ---------------------------------------------------------------------------
_classify_addr() {
    # $1=addr  $2=port  $3=proto  $4=note(optional)
    local sev
    case "$1" in
        0.0.0.0|::|'*'|'::ffff:0.0.0.0')
            sev='!! ' ;;
        127.*|::1|'::ffff:127.'*)
            sev='·  ' ;;
        *)
            sev='!  ' ;;
    esac
    printf '%s%s %s:%s%s\n' "$sev" "$3" "$1" "$2" "${4:+ ($4)}"
}
sec_netsurf() {
    local ss_bin ns_bin proto la hex_addr hex_port addr port uid_n f m pf st v6
    printf '==[ network-surface ]==\n'
    ss_bin=''; ns_bin=''
    for p in ss /usr/sbin/ss /sbin/ss; do
        command -v "$p" >/dev/null 2>&1 && { ss_bin=$p; break; }
    done
    if [ -z "$ss_bin" ]; then
        for p in netstat /usr/sbin/netstat /sbin/netstat; do
            command -v "$p" >/dev/null 2>&1 && { ns_bin=$p; break; }
        done
    fi
    if [ -n "$ss_bin" ]; then
        "$ss_bin" -tunlp 2>/dev/null | awk '
            NR>1 && ($2=="LISTEN" || ($1~/^udp/ && $2=="UNCONN")) {
                la=$5; port=la; sub(/.*:/,"",port)
                addr=la; sub(/:[^:]*$/,"",addr); gsub(/\[|\]/,"",addr)
                proto=$1; sub(/[0-9].*/,"",proto)
                proc="-"
                if (match($0,/users:\(\([^)]+\)\)/)) {
                    p=substr($0,RSTART,RLENGTH)
                    gsub(/.*\(\("|",.*$/,"",p); proc=p }
                printf "%s %s %s %s\n", proto, addr, port, proc
            }' | while read -r proto addr port proc; do
                _classify_addr "$addr" "$port" "$proto" "$proc"
            done
    elif [ -n "$ns_bin" ]; then
        "$ns_bin" -tunlp 2>/dev/null | awk '
            /^(tcp|udp)/ && /LISTEN|UNCONN|0\.0\.0\.0:\*|:::\*/ {
                n=split($4,a,":"); port=a[n]; addr=""; for(i=1;i<n;i++) addr=addr (i>1?":":"") a[i]
                gsub(/\[|\]/,"",addr); proto=$1; sub(/[0-9].*/,"",proto)
                proc=NF>=7?$NF:"-"
                printf "%s %s %s %s\n", proto, addr, port, proc
            }' | while read -r proto addr port proc; do
                _classify_addr "$addr" "$port" "$proto" "$proc"
            done
    else
        printf '· ss and netstat unavailable, reading /proc/net directly\n'
        for pf in tcp tcp6 udp udp6; do
            [ -r "/proc/net/$pf" ] || continue
            case "$pf" in tcp*) st="0A" ;; *) st="07" ;; esac
            case "$pf" in *6) v6=1 ;; *) v6=0 ;; esac
            awk -v S="$st" -v V6="$v6" -v PF="$pf" '
                # procnet-decode
                function hx(c) { return index("0123456789abcdef", tolower(c)) - 1 }
                NR>1 && $4==S {
                    la=$2
                    split(la, hp, ":")
                    if (length(hp[2]) != 4) next
                    # port: all 4 hex digits (v1.0.1 read only the first 2)
                    p = hx(substr(hp[2],1,1))*4096 + hx(substr(hp[2],2,1))*256 \
                      + hx(substr(hp[2],3,1))*16 + hx(substr(hp[2],4,1))
                    if (V6) {
                        hex = hp[1]
                        if (length(hex) != 32) next
                        for (i = 1; i <= 32; i++)
                            if (hx(substr(hex,i,1)) < 0) next
                        # the kernel stores each 32-bit word little-endian;
                        # decode word k into two big-endian 16-bit groups
                        for (k = 1; k <= 4; k++) {
                            b = (k-1)*8
                            grp[k*2-1] = (hx(substr(hex,b+7,1))*16 + hx(substr(hex,b+8,1)))*256 \
                                       + hx(substr(hex,b+5,1))*16 + hx(substr(hex,b+6,1))
                            grp[k*2]   = (hx(substr(hex,b+3,1))*16 + hx(substr(hex,b+4,1)))*256 \
                                       + hx(substr(hex,b+1,1))*16 + hx(substr(hex,b+2,1))
                        }
                        # IPv4-mapped addresses: print the dotted form so
                        # loopback/all-interfaces classification can see it
                        if (grp[1]==0 && grp[2]==0 && grp[3]==0 && grp[4]==0 && \
                            grp[5]==0 && grp[6]==65535) {
                            addr = sprintf("::ffff:%d.%d.%d.%d", \
                                int(grp[7]/256), grp[7]%256, int(grp[8]/256), grp[8]%256)
                        } else {
                            bs=bl=cs=cl=0
                            for (i=1;i<=8;i++) {
                                if (grp[i]==0) { if(cl==0)cs=i; cl++; if(cl>bl){bl=cl;bs=cs} }
                                else cl=0
                            }
                            if (bl>=2) {
                                L=""; for(i=1;i<bs;i++) L=L (L?":":"") sprintf("%x",grp[i])
                                R=""; for(i=bs+bl;i<=8;i++) R=R (R?":":"") sprintf("%x",grp[i])
                                addr = L "::" R
                            } else {
                                addr = sprintf("%x",grp[1])
                                for(i=2;i<=8;i++) addr = addr ":" sprintf("%x",grp[i])
                            }
                        }
                    } else {
                        hex = hp[1]
                        if (length(hex) != 8) next
                        addr = sprintf("%d.%d.%d.%d", \
                            hx(substr(hex,7,1))*16+hx(substr(hex,8,1)), \
                            hx(substr(hex,5,1))*16+hx(substr(hex,6,1)), \
                            hx(substr(hex,3,1))*16+hx(substr(hex,4,1)), \
                            hx(substr(hex,1,1))*16+hx(substr(hex,2,1)))
                    }
                    printf "%s %s %d uid=%s\n", PF, addr, p, $8
                }
                # procnet-decode-end
            ' "/proc/net/$pf" 2>/dev/null | \
            while read -r proto addr port uid_n; do
                _classify_addr "$addr" "$port" "$proto" "$uid_n"
            done
        done
    fi
    if [ -r /proc/net/unix ]; then
        awk 'END{printf "· unix domain sockets in /proc/net/unix: %d\n", NR-1}' /proc/net/unix 2>/dev/null
    fi
    if command -v find >/dev/null 2>&1 && command -v stat >/dev/null 2>&1; then
        find /run /var/run /tmp -maxdepth 3 -type s -name '*.sock' 2>/dev/null | \
            grep -Ei 'docker|containerd|crio|podman' 2>/dev/null | \
            while IFS= read -r f; do
                m=$(stat -c '%a' "$f" 2>/dev/null)
                case "${m:-0}" in
                    *[2367]) printf '!! runtime socket group/world-writable (%s): %s\n' "$m" "$f" ;;
                    *)       printf '! runtime socket: %s (mode %s)\n' "$f" "${m:-?}" ;;
                esac
            done
    fi
    if [ -r /etc/resolv.conf ]; then
        awk '/^nameserver/{printf "· resolver: %s\n",$2}' /etc/resolv.conf 2>/dev/null
    else
        printf '! /etc/resolv.conf not readable\n'
    fi
    [ -r /etc/hosts ] && printf '· /etc/hosts readable\n'
    if [ -r /proc/net/route ]; then
        awk '$2=="00000000" && $3!="00000000" {
            hx="0123456789abcdef"; h=tolower($3)
            d1=(index(hx,substr(h,7,1))-1)*16+(index(hx,substr(h,8,1))-1)
            d2=(index(hx,substr(h,5,1))-1)*16+(index(hx,substr(h,6,1))-1)
            d3=(index(hx,substr(h,3,1))-1)*16+(index(hx,substr(h,4,1))-1)
            d4=(index(hx,substr(h,1,1))-1)*16+(index(hx,substr(h,2,1))-1)
            printf "· default gateway: %d.%d.%d.%d (iface %s)\n", d1, d2, d3, d4, $1
            exit }' /proc/net/route 2>/dev/null
    fi
    for t in iptables ip6tables nft; do
        command -v "$t" >/dev/null 2>&1 && printf '· firewall tool present: %s\n' "$t"
    done
    return 0
}

# ---------------------------------------------------------------------------
# 6. secrets — keys, history, credentials in configs
# ---------------------------------------------------------------------------
sec_secrets() {
    local f sz m mm have_find have_stat have_grep ln
    printf '==[ secrets ]==\n'
    have_find=0; command -v find >/dev/null 2>&1 && have_find=1
    have_stat=0; command -v stat >/dev/null 2>&1 && have_stat=1
    have_grep=0; command -v grep >/dev/null 2>&1 && have_grep=1
    if [ "$have_find" -eq 1 ]; then
        find /root /home /etc/ssh -maxdepth 3 -type f \
            \( -name 'id_*' -o -name 'identity' -o -name '*_rsa' -o -name '*_ed25519' \) \
            ! -name '*.pub' 2>/dev/null | \
        while IFS= read -r f; do
            m=''
            [ "$have_stat" -eq 1 ] && m=$(stat -c '%a' "$f" 2>/dev/null)
            mm="$m"
            while [ "${#mm}" -lt 3 ]; do mm="0$mm"; done
            [ "${#mm}" -eq 4 ] && mm=${mm#?}
            case $mm in
                ??[2367]|?[2367]?)
                    printf '!! ssh private key group/world-readable (mode %s): %s\n' "${m:-?}" "$f" ;;
                *)
                    if [ "$EUID_N" -ne 0 ]; then
                        if [ -r "$f" ]; then
                            printf '!! ssh private key readable (mode %s): %s\n' "${m:-?}" "$f"
                        else
                            printf '· ssh key present, not readable: %s\n' "$f"
                        fi
                    else
                        printf '· ssh key present (mode %s, owner-only): %s\n' "${m:-?}" "$f"
                    fi ;;
            esac
        done
        find /var/www /srv /opt /home -maxdepth 4 -type f \
            \( -name '.env' -o -name 'wp-config.php' -o -name 'settings.py' \
               -o -name 'database.yml' -o -name 'config.php' \) 2>/dev/null | \
        while IFS= read -r f; do
            case "$f" in
                */.env) printf '! env file: %s\n' "$f" ;;
                *)      printf '! app config may hold credentials: %s\n' "$f" ;;
            esac
        done
    fi
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -f "$f" ] && printf '· authorized_keys: %s\n' "$f"
    done
    for f in /root/.*history /home/*/.*history; do
        [ -f "$f" ] && [ -r "$f" ] && [ -s "$f" ] || continue
        sz=''
        [ "$have_stat" -eq 1 ] && sz=$(stat -c '%s' "$f" 2>/dev/null)
        printf '· history (%s bytes): %s\n' "${sz:-?}" "$f"
    done
    for f in /root/.docker/config.json /home/*/.docker/config.json; do
        [ -r "$f" ] && printf '!! registry credential store readable: %s\n' "$f"
    done
    for f in /root/.git-credentials /home/*/.git-credentials; do
        [ -f "$f" ] && printf '! git credentials file: %s\n' "$f"
    done
    [ -r /var/lib/cloud/instance/user-data.txt ] && \
        printf '!! cloud-init user-data readable: /var/lib/cloud/instance/user-data.txt\n'
    for f in /run/cloud-init/*.json; do
        [ -f "$f" ] && printf '· cloud-init state: %s\n' "$f"
    done
    if [ "$have_grep" -eq 1 ]; then
        for f in /etc/fstab /etc/yum.conf /etc/apt/apt.conf.d/* /etc/yum.repos.d/*; do
            [ -f "$f" ] || continue
            grep -Ein 'password|pass=|user:.*@' "$f" 2>/dev/null | \
                while IFS= read -r ln; do printf '! credential indicator %s: %s\n' "$f" "$ln"; done
        done
    fi
    for f in /var/backups/*; do
        [ -e "$f" ] && printf '· /var/backups: %s\n' "$f"
    done
    return 0
}

# ---------------------------------------------------------------------------
# 7. contain — container / Docker/Kubernetes posture
# ---------------------------------------------------------------------------
sec_contain() {
    local in_ct cmark c val uid user pgid grp gline gid members cpro
    in_ct=0; cmark=""
    [ -f /.dockerenv ]        && in_ct=1 && cmark="docker env marker"
    [ -f /run/.containerenv ] && in_ct=1 && cmark="podman env marker"
    if [ "$in_ct" -eq 0 ] && [ -r /proc/1/cgroup ] && \
       grep -qsE '(docker|containerd|kubepods|libpod|lxc|crio)' /proc/1/cgroup 2>/dev/null; then
        in_ct=1; cmark="cgroup placement"
    fi
    printf '==[ containers ]==\n'
    if [ "$in_ct" -eq 1 ]; then
        printf '· container environment detected (%s)\n' "$cmark"
        for c in $(awk '/^CapEff:/{
            s=tolower($2); n=length(s); hx="0123456789abcdef"
            d0=n>=1?index(hx,substr(s,n,1))-1:0
            d4=n>=5?index(hx,substr(s,n-4,1))-1:0
            d5=n>=6?index(hx,substr(s,n-5,1))-1:0
            if(d4%2) print "sys_module"
            if(int(d0/2)%2) print "dac_override"
            if(int(d4/8)%2) print "sys_ptrace"
            if(int(d5/2)%2) print "sys_admin"
            exit}' /proc/self/status 2>/dev/null); do
            printf '!! high-impact capability in effective set: %s\n' "$c"
        done
        val=$(awk '/^Seccomp:/{s=$2} /^NoNewPrivs:/{n=$2} END{
            if(s==""&&n=="") exit
            m=s==2?"filter":(s==1?"strict":"off")
            printf "seccomp=%s(%s) no_new_privs=%s",s,m,n}' /proc/self/status 2>/dev/null)
        [ -n "$val" ] && printf '· %s\n' "$val"
        [ -r /proc/self/uid_map ] && \
            awk 'NR==1{f=($1==$2)} END{exit(f?0:1)}' /proc/self/uid_map 2>/dev/null && \
            printf '· uid map is identity-mapped (no namespace remap)\n'
        # [ -w ] as root sees mode bits only; container runtimes bind-mount
        # /proc/sys read-only — trust the covering mount's ro flag first
        cpro=$(awk '$5=="/proc/sys/kernel/core_pattern"{l=28}
            $5=="/proc/sys" && l<10 {l=10}
            $5=="/proc" && l<6 {l=6}
            l>m {m=l; ro=($6 ~ /^ro/)}
            END {if (m) printf "%s", (ro ? "ro" : "rw")}' /proc/self/mountinfo 2>/dev/null)
        if [ "$cpro" = ro ]; then
            printf '· core_pattern on read-only mount (runtime-masked)\n'
        elif [ -w /proc/sys/kernel/core_pattern ]; then
            printf '!! kernel core_pattern is writable\n'
        fi
        awk '{mp=$5;o=$6;sep=0;for(i=7;i<=NF;i++) if($i=="-"){sep=i;break}
            fs=sep>0?$(sep+1):"?"
            if(mp=="/"||mp=="/host"||mp=="/proc"||mp=="/sys"){
                if(o=="rw"||substr(o,1,3)=="rw,") printf "! %s mounted rw (%s)\n",mp,fs
                else printf "· %s mounted ro (%s)\n",mp,fs}}' \
            /proc/self/mountinfo 2>/dev/null
        [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ] && \
            printf '!! orchestrator service-account token readable\n'
        [ -e /var/lib/kubelet ] && printf '· kubelet data directory visible\n'
        printf '· runtime socket writability: see network section\n'
    else
        if [ -r /proc/self/status ] && [ -r /etc/passwd ] && [ -r /etc/group ]; then
            uid=$(awk '/^Uid:/{print $2;exit}' /proc/self/status 2>/dev/null)
            user=$(awk -F: -v u="$uid" '$3==u{print $1;exit}' /etc/passwd 2>/dev/null)
            pgid=$(awk -F: -v u="$user" '$1==u{print $4;exit}' /etc/passwd 2>/dev/null)
            if [ -n "$user" ]; then
                for grp in docker lxd; do
                    gline=$(awk -F: -v g="$grp" '$1==g{print $3";"$4;exit}' /etc/group 2>/dev/null)
                    [ -n "$gline" ] || continue
                    gid=${gline%%;*}; members=${gline#*;}
                    if [ "$pgid" = "$gid" ]; then
                        printf '!! user %s has %s as primary group (root equivalent)\n' "$user" "$grp"
                    else
                        case ",$members," in
                            *",$user,"*) printf '!! user %s is in %s group (root equivalent)\n' "$user" "$grp" ;;
                        esac
                    fi
                done
            fi
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 8. hygiene — kernel parameters, MAC, NFS, filesystem hardening
# ---------------------------------------------------------------------------
sec_hygiene() {
    local v d m kn f ln
    printf '==[ hygiene ]==\n'
    if read -r v < /proc/sys/kernel/randomize_va_space 2>/dev/null; then
        [ "$v" = "2" ] || printf '! kernel.randomize_va_space=%s (full ASLR off)\n' "$v"
    fi
    if read -r v < /proc/sys/kernel/yama/ptrace_scope 2>/dev/null; then
        [ "$v" = "0" ] && printf '! kernel.yama.ptrace_scope=0 (unrestricted trace)\n'
    fi
    if read -r v < /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null; then
        [ "$v" = "0" ] && printf '· kernel.unprivileged_bpf_disabled=0\n'
    fi
    for kn in protected_symlinks protected_hardlinks protected_regular; do
        if read -r v < "/proc/sys/fs/$kn" 2>/dev/null; then
            case $v in 1|2) ;; *) printf '· fs.%s=%s\n' "$kn" "$v" ;; esac
        fi
    done
    read -r v < /proc/sys/vm/mmap_min_addr 2>/dev/null && printf '· vm.mmap_min_addr=%s\n' "$v"
    if read -r v < /proc/sys/kernel/dmesg_restrict 2>/dev/null; then
        [ "$v" = "0" ] && printf '· kernel.dmesg_restrict=0\n'
    fi
    if read -r v < /proc/sys/kernel/kptr_restrict 2>/dev/null; then
        [ "$v" = "0" ] && printf '! kernel.kptr_restrict=0 (kernel pointers exposed)\n'
    fi
    if read -r v < /proc/sys/fs/suid_dumpable 2>/dev/null; then
        [ "$v" = "0" ] || printf '! fs.suid_dumpable=%s\n' "$v"
    fi
    if command -v getenforce >/dev/null 2>&1; then
        printf '· SELinux: %s\n' "$(getenforce 2>/dev/null)"
    elif [ -d /sys/fs/selinux ]; then
        printf '· SELinux: filesystem present\n'
    elif [ -d /sys/kernel/security/apparmor ]; then
        printf '· AppArmor: filesystem present\n'
    else
        if read -r v < /proc/self/attr/current 2>/dev/null && [ -n "$v" ]; then
            printf '· LSM: %s\n' "$v"
        else
            printf '· no SELinux/AppArmor indicators found\n'
        fi
    fi
    if [ -r /etc/exports ]; then
        grep -Ev '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null | while IFS= read -r ln; do
            case "$ln" in
                *rw*) case "$ln" in *no_root_squash*) printf '!! NFS rw+no_root_squash: %s\n' "$ln" ;; esac ;;
            esac
        done
    fi
    for d in /tmp /var/tmp; do
        [ -d "$d" ] || continue
        m=$(stat -c '%a' "$d" 2>/dev/null) || continue
        printf '%s %s\n' "$d" "$m" | awk '{
            ww=substr($2,length($2),1)
            st=(length($2)==4)?substr($2,1,1):""
            if(ww~/[2367]/ && st!~/[1357]/)
                printf "!! world-writable dir without sticky bit: %s (mode %s)\n",$1,$2}'
    done
    if [ -d /etc ]; then
        find /etc -xdev -type f -perm -0002 2>/dev/null | while IFS= read -r f; do
            printf '!! world-writable file in /etc: %s\n' "$f"
        done
    fi
    if [ -r /etc/fstab ]; then
        awk '$1!~/^[[:space:]]*#/ && NF>=2 {
            opts=$4; n=split(opts,a,","); ns=nx=0
            for(i=1;i<=n;i++){if(a[i]=="nosuid")ns=1;if(a[i]=="noexec")nx=1}
            printf "· fstab %s (%s)%s%s\n",$2,opts,(ns?"":" no-nosuid"),(nx?"":" no-noexec")
        }' /etc/fstab 2>/dev/null
    elif [ -r /proc/self/mountinfo ]; then
        awk '$5!~/^\/(proc|sys|dev)/{
            m=$5;o=$6;n=split(o,a,",");ns=nx=0
            for(j=1;j<=n;j++){if(a[j]=="nosuid")ns=1;if(a[j]=="noexec")nx=1}
            printf "· mount %s (%s)%s%s\n",m,o,(ns?"":" no-nosuid"),(nx?"":" no-noexec")
        }' /proc/self/mountinfo 2>/dev/null
    fi
    return 0
}

# ---------------------------------------------------------------------------
# main — CLI, runner, render filter, summary, exit contract
# ---------------------------------------------------------------------------
ALL="posture identity execsurf sched netsurf secrets contain hygiene"

usage_err() {
    printf 'sysmap: %s\n' "$1" >&2
    printf 'Try sysmap --help for usage.\n' >&2
    exit 64
}

print_help() {
    sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

MODULES=""
OUT=""
ENG=""
AUDITOR=""
JSON=0
QUIET=0
FAILON=""

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)    [ $# -ge 2 ] || usage_err "option $1 needs a FILE argument"; OUT="$2"; shift 2 ;;
        -E|--engagement) [ $# -ge 2 ] || usage_err "option $1 needs an ID argument"
                        case "$2" in *[[:cntrl:]]*) usage_err "engagement ID must not contain control characters" ;; esac
                        ENG="$2"; shift 2 ;;
        -a|--auditor)   [ $# -ge 2 ] || usage_err "option $1 needs a NAME argument"
                        case "$2" in *[[:cntrl:]]*) usage_err "auditor name must not contain control characters" ;; esac
                        AUDITOR="$2"; shift 2 ;;
        --fail-on)      [ $# -ge 2 ] || usage_err "option $1 needs warn|info"; case "$2" in warn|info) ;; *) usage_err "--fail-on takes warn or info" ;; esac; FAILON="$2"; shift 2 ;;
        --json)         JSON=1; shift ;;
        -q|--quiet)     QUIET=1; shift ;;
        --no-color)     shift ;;
        --list-modules) printf '%s\n' $ALL; exit 0 ;;
        -V|--version)   printf 'sysmap %s\nSPDX-FileCopyrightText: 2026 v0idsnail\nLicense: MIT <https://spdx.org/licenses/MIT.html>\n' "$VERSION"; exit 0 ;;
        -h|--help)      print_help ;;
        -*)             usage_err "unknown option: $1" ;;
        *)              found=""
                        for m in $ALL; do [ "$m" = "$1" ] && found=1; done
                        [ "$found" ] || usage_err "unknown module: $1"
                        case " $MODULES " in *" $1 "*) ;; *) MODULES="$MODULES $1" ;; esac
                        shift ;;
    esac
done
[ -z "$MODULES" ] && MODULES="$ALL"

# dependency precheck — awk and grep are load-bearing everywhere
for dep in awk grep; do
    command -v "$dep" >/dev/null 2>&1 || { printf 'sysmap: missing dependency: %s\n' "$dep" >&2; exit 1; }
done

# -o: redirect report stream (stderr stays on the terminal).
# Probe first: a failed exec redirect exits the shell on dash/ash before the handler runs.
if [ -n "$OUT" ] && [ "$OUT" != "-" ]; then
    : > "$OUT" 2>/dev/null || { printf 'sysmap: cannot write %s\n' "$OUT" >&2; exit 1; }
    exec > "$OUT"
    printf 'sysmap: report writing to %s\n' "$OUT" >&2
fi

trap 'printf "sysmap: aborted — report incomplete\n" >&2; exit 130' INT TERM HUP

HN=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown')
NOW=$(date '+%Y-%m-%d %H:%M:%S %Z')
set -- $MODULES
NMOD=$#


# survey producer: header, modules with rc sentinels (\001rc=N), nothing else
run_survey() {
    printf '=== sysmap v%s | %s | %s ===\n' "$VERSION" "$NOW" "$HN"
    [ -n "$ENG" ] && printf '    engagement: %s\n' "$ENG"
    [ -n "$AUDITOR" ] && printf '    auditor: %s\n' "$AUDITOR"
    printf '    executed as: %s (uid %s) | modules: %s\n' \
        "$(id -un 2>/dev/null || printf '?')" "$EUID_N" "$MODULES"
    printf '    read-only survey — no changes made to this host\n'
    printf '\n'
    for m in $MODULES; do
        sec_"$m"
        printf '\001rc=%s\n' "$?"
        printf '\n'
    done
}

# render filter: one consumer for both modes.
#   text mode — normalizes marker spacing, honors -q, counts severities,
#               prints summary footer, strips rc sentinels (tracking failures)
#   json mode — one JSONL record per finding + header + summary records
# Exit status of the filter IS the survey exit contract:
#   0 ok · 1 module failure · 2 --fail-on gate tripped
ROOTNOTE=0
[ "$EUID_N" -ne 0 ] && ROOTNOTE=1
# metadata reaches the filter via ENVIRON, not -v: awk processes backslash
# escapes in -v values, silently rewriting tags like "ENG\2026" (octal
# escape interpretation, verified end-to-end). Environment passing is literal.
run_survey 2>/dev/null | \
SM_HOST="$HN" SM_ENG="$ENG" SM_AUD="$AUDITOR" SM_TS="$NOW" awk \
    -v MODE="$JSON" -v QUIET="$QUIET" -v FAILON="$FAILON" -v NMOD="$NMOD" \
    -v VER="$VERSION" -v ROOTNOTE="$ROOTNOTE" \
'
    BEGIN {
        HOST = ENVIRON["SM_HOST"]
        ENG  = ENVIRON["SM_ENG"]
        AUD  = ENVIRON["SM_AUD"]
        TS   = ENVIRON["SM_TS"]
        for (i = 0; i < 256; i++) T[sprintf("%c", i)] = i
    }
    function u8clean(s,   i, n, b, len, j, c, ok, out) {
        # LC_ALL=C: one byte per char. Keep valid UTF-8 sequences,
        # replace anything else with ? so JSONL stays parseable by
        # strict consumers (python json rejects raw Latin-1 bytes).
        out = ""; n = length(s)
        for (i = 1; i <= n; i++) {
            b = T[substr(s, i, 1)] + 0
            if (b < 128) { out = out substr(s, i, 1); continue }
            if (b >= 194 && b <= 223) len = 1
            else if (b >= 224 && b <= 239) len = 2
            else if (b >= 240 && b <= 244) len = 3
            else { out = out "?"; continue }
            ok = (i + len <= n)
            for (j = 1; ok && j <= len; j++) {
                c = T[substr(s, i + j, 1)] + 0
                if (c < 128 || c > 191) ok = 0
            }
            if (ok) { out = out substr(s, i, 1 + len); i += len }
            else out = out "?"
        }
        return out
    }
    function esc(s) {
        s = u8clean(s)
        gsub(/\\/, "&&", s)
        gsub(/"/, "\\\"", s)
        gsub(/\t/, "\\t", s)
        gsub(/\r/, "\\r", s)
        gsub(/[\001-\037]/, "", s)
        return s
    }
    /^\001rc=/ {
        sent++
        if (substr($0, 5) != "0") modfail++
        next
    }
    /^==\[ / { mod = $0; sub(/^==\[ /, "", mod); sub(/ \]==$/, "", mod); bcount++ }
    {
        sev = ""
        line = $0
        if (sub(/^!! */, "", line)) { sev = "high"; marker = "!! " }
        else if (sub(/^![^!] */, "", line)) { sev = "medium"; marker = "!  " }
        else if (sub(/^· */, "", line)) { sev = "info"; marker = "·  " }
        if (sev != "") {
            if (sev == "high") { hi++; himsg[++nhi] = "[" mod "] " line }
            else if (sev == "medium") med++
            else info++
            if (MODE == 1) {
                printf "{\"schema\":\"sysmap.finding/v1\",\"ts\":\"%s\",\"host\":\"%s\",\"engagement\":\"%s\",\"auditor\":\"%s\",\"module\":\"%s\",\"severity\":\"%s\",\"msg\":\"%s\"}\n", \
                    esc(TS), esc(HOST), esc(ENG), esc(AUD), esc(mod), sev, esc(line)
            } else {
                if (sev == "info" && QUIET == 1) next
                print marker line
            }
            next
        }
        if (MODE == 0) print
    }
    END {
        if (MODE == 1) {
            printf "{\"schema\":\"sysmap.summary/v1\",\"ts\":\"%s\",\"host\":\"%s\",\"engagement\":\"%s\",\"auditor\":\"%s\",\"modules_run\":%d,\"findings\":{\"high\":%d,\"medium\":%d,\"info\":%d},\"module_failures\":%d}\n", \
                esc(TS), esc(HOST), esc(ENG), esc(AUD), bcount+0, hi+0, med+0, info+0, modfail+0
        } else {
            printf "\n=== summary ===\n"
            printf "findings: !! %d   ! %d   · %d\n", hi+0, med+0, info+0
            if (nhi+0 > 0) {
                printf "\nnotable (!!) findings:\n"
                cap = nhi; if (cap > 20) cap = 20
                for (i = 1; i <= cap; i++) printf "  %s\n", himsg[i]
                if (nhi > cap) printf "  ... and %d more (see module sections)\n", nhi - cap
            }
            printf "modules failed: %d\n", modfail+0
            if (ROOTNOTE == 1)
                printf "note: run as root for full coverage (/etc/shadow, capabilities, all socket owners, root crontab)\n"
            printf "review and redact before sharing outside the engagement\n"
            printf "=== survey complete — sysmap v%s ===\n", VER
        }
        if (sent+0 != NMOD+0 || bcount+0 != NMOD+0) exit 1
        if (modfail+0 > 0) exit 1
        if (FAILON == "warn" && hi+0 > 0) exit 2
        if (FAILON == "info" && (hi+0 > 0 || med+0 > 0 || info+0 > 0)) exit 2
        exit 0
    }
'
rc=$?
exit "$rc"
