#!/usr/bin/env bash
# Read-only capability probe for an eBPF deployment target.
#
# Makes no changes. Safe to run on a production host.
#
#   scp probe-target.sh server:/tmp/
#   ssh server 'bash /tmp/probe-target.sh' | tee target-report.txt
#
# Run as root where possible; unprivileged still answers most questions but
# cannot read the kernel config on some distros or list loaded BPF programs.

set -uo pipefail

ok()   { printf '  \033[32m%-4s\033[0m %s\n' 'YES' "$1"; }
no()   { printf '  \033[31m%-4s\033[0m %s\n' 'NO'  "$1"; }
warn() { printf '  \033[33m%-4s\033[0m %s\n' '??'  "$1"; }
info() { printf '  %-4s %s\n' '' "$1"; }
hdr()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

KCONF=""
for c in "/boot/config-$(uname -r)" /proc/config.gz; do
    [ -r "$c" ] && KCONF="$c" && break
done

# Read a CONFIG_ value from whichever source exists. Prints nothing if unknown.
kconf() {
    [ -z "$KCONF" ] && return 1
    if [ "$KCONF" = /proc/config.gz ]; then
        zcat /proc/config.gz 2>/dev/null | grep -E "^$1=" | cut -d= -f2
    else
        grep -E "^$1=" "$KCONF" 2>/dev/null | cut -d= -f2
    fi
}

check_kconf() {
    local val
    val=$(kconf "$1")
    case "$val" in
        y|m) ok  "$1=$val  $2" ;;
        "")  warn "$1 unknown (no readable kernel config)  $2" ;;
        *)   no  "$1=$val  $2" ;;
    esac
}

# Minimum kernel version test: ver_ge 5 8
ver_ge() {
    local maj min
    maj=$(uname -r | cut -d. -f1)
    min=$(uname -r | cut -d. -f2 | tr -cd '0-9')
    [ "$maj" -gt "$1" ] || { [ "$maj" -eq "$1" ] && [ "$min" -ge "$2" ]; }
}

echo "eBPF target capability report"
echo "generated $(date -Is) on $(hostname)"

hdr "Host"
info "kernel   $(uname -r)"
info "arch     $(uname -m)"
info "distro   $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown)"
info "uptime   $(uptime -p 2>/dev/null || echo unknown)"
info "cpus     $(nproc 2>/dev/null || echo '?')"
info "memory   $(awk '/MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo 2>/dev/null)"
[ "$(id -u)" -eq 0 ] && info "running as root" || warn "not root - some checks will be incomplete"
[ -n "$KCONF" ] && info "kernel config: $KCONF" || warn "no readable kernel config"

hdr "BTF and CO-RE"
# Without this, a BPF object compiled on the dev box cannot relocate here.
if [ -r /sys/kernel/btf/vmlinux ]; then
    ok "/sys/kernel/btf/vmlinux ($(stat -c %s /sys/kernel/btf/vmlinux) bytes)"
else
    no "/sys/kernel/btf/vmlinux MISSING - CO-RE will not work, this is a blocker"
fi
check_kconf CONFIG_DEBUG_INFO_BTF "vmlinux BTF"
check_kconf CONFIG_DEBUG_INFO_BTF_MODULES "per-module BTF"
n=$(ls /sys/kernel/btf/ 2>/dev/null | wc -l)
info "module BTF blobs present: $n"

hdr "Core BPF"
check_kconf CONFIG_BPF_SYSCALL "bpf() syscall"
check_kconf CONFIG_BPF_JIT     "JIT compiler"
check_kconf CONFIG_BPF_EVENTS  "attach to tracepoints/kprobes"
check_kconf CONFIG_KPROBES     "kprobes"
check_kconf CONFIG_FTRACE_SYSCALLS "syscall tracepoints"

ver_ge 5 8  && ok "kernel >= 5.8  - BPF ring buffer available" \
            || no "kernel < 5.8   - no ring buffer, must fall back to perf buffer"
ver_ge 5 5  && ok "kernel >= 5.5  - fentry/fexit trampolines available" \
            || no "kernel < 5.5   - kprobes only, higher overhead"
ver_ge 5 7  && ok "kernel >= 5.7  - BPF LSM hooks exist in kernel" \
            || no "kernel < 5.7   - BPF LSM not available at all"

hdr "BPF LSM (enforcement capability)"
# Ubuntu compiles BPF LSM in but does NOT enable it in the default boot cmdline.
if [ -r /sys/kernel/security/lsm ]; then
    active=$(cat /sys/kernel/security/lsm)
    info "active LSMs: $active"
    if echo "$active" | grep -qw bpf; then
        ok "bpf LSM is ACTIVE - enforcement phase is possible as-is"
    else
        no "bpf LSM compiled but NOT ACTIVE"
        info "to enable, append to the kernel cmdline and reboot:"
        info "    lsm=$active,bpf"
        info "on Ubuntu: edit GRUB_CMDLINE_LINUX in /etc/default/grub,"
        info "then 'update-grub' and reboot"
    fi
else
    warn "/sys/kernel/security/lsm unreadable (securityfs not mounted?)"
fi
check_kconf CONFIG_BPF_LSM "BPF LSM compiled in"
info "boot cmdline: $(cat /proc/cmdline 2>/dev/null)"

hdr "Permissions and hardening"
v=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo '?')
info "kernel.unprivileged_bpf_disabled = $v  (needs root/CAP_BPF unless 0)"
v=$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo '?')
info "kernel.perf_event_paranoid = $v"
v=$(sysctl -n net.core.bpf_jit_harden 2>/dev/null || echo '?')
info "net.core.bpf_jit_harden = $v"
v=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo '?')
info "kernel.kptr_restrict = $v"
if [ -d /sys/kernel/security/lockdown ]; then
    info "lockdown: $(cat /sys/kernel/security/lockdown 2>/dev/null)"
fi

hdr "cgroups (container attribution depends on this)"
t=$(stat -fc %T /sys/fs/cgroup 2>/dev/null)
case "$t" in
    cgroup2fs) ok "unified cgroup v2 - bpf_get_current_cgroup_id() maps cleanly to containers" ;;
    tmpfs)     no "cgroup v1 or hybrid - attribution needs the v1 path walk instead" ;;
    *)         warn "unrecognised cgroup fs: $t" ;;
esac
[ -r /sys/fs/cgroup/cgroup.controllers ] && \
    info "controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"

hdr "Tracepoints the monitor needs"
TP=/sys/kernel/debug/tracing/events
[ -d "$TP" ] || TP=/sys/kernel/tracing/events
if [ -d "$TP" ]; then
    info "tracefs at ${TP%/events}"
    for t in sched/sched_process_exec sched/sched_process_exit \
             syscalls/sys_enter_execve syscalls/sys_enter_connect; do
        [ -d "$TP/$t" ] && ok "$t" || no "$t"
    done
else
    warn "tracefs not mounted - mount -t tracefs none /sys/kernel/tracing"
    info "(BPF attach still works without it; this only affects manual inspection)"
fi

hdr "Kernel functions for kprobes"
if [ -r /proc/kallsyms ]; then
    for f in tcp_v4_connect tcp_v6_connect udp_sendmsg security_bprm_check \
             security_file_open commit_creds; do
        grep -qw "$f" /proc/kallsyms && ok "$f" || no "$f"
    done
else
    warn "/proc/kallsyms unreadable (need root)"
fi

hdr "Tooling on target"
for t in bpftool clang llvm-strip docker podman; do
    if command -v "$t" >/dev/null 2>&1; then
        ok "$t  ($("$t" --version 2>/dev/null | head -1 | cut -c1-60))"
    else
        no "$t not installed"
    fi
done
# Only the loader needs to ship; clang/bpftool on target are conveniences.
info "note: with CO-RE, only the compiled loader binary needs to deploy"

hdr "Container runtime"
if command -v docker >/dev/null 2>&1; then
    docker info --format 'cgroup driver: {{.CgroupDriver}}
cgroup version: {{.CgroupVersion}}
storage driver: {{.Driver}}
containers: {{.Containers}} ({{.ContainersRunning}} running)' 2>/dev/null \
        | sed 's/^/  /' || warn "docker present but not queryable as this user"
    echo
    docker ps --format '  {{.Names}}\t{{.Image}}' 2>/dev/null | head -30
fi

hdr "Already-loaded BPF programs"
if command -v bpftool >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    n=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]')
    info "$n programs currently loaded"
    bpftool prog show 2>/dev/null | grep -E '^[0-9]+:' | head -10 | sed 's/^/  /'
else
    info "install bpftool or run as root to list"
fi

hdr "Verdict"
BLOCKERS=0
[ -r /sys/kernel/btf/vmlinux ] || { echo "  BLOCKER: no BTF, CO-RE impossible"; BLOCKERS=1; }
ver_ge 5 8 || echo "  DEGRADED: no ring buffer, use perf buffer instead"
ver_ge 5 7 || echo "  DEGRADED: no BPF LSM, enforcement phase impossible"
[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] || \
    echo "  DEGRADED: cgroup v1, attribution is harder"
if [ -r /sys/kernel/security/lsm ] && ! grep -qw bpf /sys/kernel/security/lsm; then
    echo "  ACTION:   append ',bpf' to lsm= in the kernel cmdline for enforcement"
fi
[ "$BLOCKERS" -eq 0 ] && echo "  No blockers found."
echo
