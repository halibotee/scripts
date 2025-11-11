#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="2.2-final-mod4"
BACKUP_DIR="/etc/sysopt_lowmem_backup"
LOG_FILE="/var/log/sysopt_lowmem.log"
TOUCHED_SERVICES_FILE="${BACKUP_DIR}/touched_services.txt"
export DEBIAN_FRONTEND=noninteractive

FN_TRIM_SERVICES_LIST=(
    "apt-daily.timer"
    "apt-daily-upgrade.timer"
    "unattended-upgrades.service"
    "motd-news.service"
    "man-db.timer"
    "sysstat.service"
    "whoopsie.service"
    "apport.service"
    "snapd.service"
    "snapd.socket"
    "avahi-daemon.service"
    "bluetooth.service"
    "cups.service"
    "cups-browsed.service"
    "ModemManager.service"
    "ssh-askpass.service"
    "e2scrub_reap.timer"
    "cloud-init.service"
    "cloud-init-local.service"
    "cloud-config.service"
    "cloud-final.service"
    "packagekit.service"
    "thermald.service"
    "qemu-guest-agent.service"
    "atop.service"
    "atopacctd.service"
)

mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"
touch "$TOUCHED_SERVICES_FILE"

fn_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%F %T')
    printf '%s [%s] %s\n' "$ts" "$level" "$msg" | tee -a "$LOG_FILE"
}

fn_check_root() {
    if [ "$EUID" -ne 0 ]; then
        fn_log "错误" "本脚本必须以 root 权限运行。"
        exit 1
    fi
}

fn_check_apt_lock() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        fn_log "警告" "检测到 APT 锁 (可能已有其他 apt/dpkg 进程在运行)。"
        return 1
    fi
    return 0
}

fn_wait_for_apt_lock() {
    local max_wait=120
    local count=0
    fn_log "信息" "检查 APT 锁..."
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ "$count" -ge "$max_wait" ]; then
            fn_log "错误" "等待 APT 锁超时 (120 秒)。APT 操作可能失败。"
            return 1
        fi
        fn_log "警告" "检测到 APT 锁，等待 5 秒... ($count/$max_wait)"
        sleep 5
        count=$((count + 5))
    done
    fn_log "信息" "APT 锁已释放。"
    return 0
}

fn_detect_os() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_PRETTY="$PRETTY_NAME"
        OS_ID="$ID"
        OS_VER="$VERSION_ID"
        fn_log "信息" "检测到操作系统: $OS_PRETTY"
    else
        fn_log "错误" "无法检测到操作系统 (/etc/os-release 不存在)。"
        exit 1
    fi

    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}' || echo 0)
    MEM_MB=$(( MEM_KB / 1024 ))
    fn_log "信息" "物理内存: ${MEM_MB} MB"

    if ! command -v systemctl >/dev/null 2>&1; then
        fn_log "错误" "未找到 Systemd。本脚本需要 systemd。"
        exit 1
    fi
}

fn_backup_state() {
    fn_log "信息" "正在创建备份于 $BACKUP_DIR ..."
    mkdir -p "$BACKUP_DIR"
    cp -an /etc/fstab "${BACKUP_DIR}/fstab.bak" 2>/dev/null || true
    cp -an /etc/systemd/resolved.conf "${BACKUP_DIR}/resolved.conf.bak" 2>/dev/null || true
    cp -an /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak" 2>/dev/null || true
    cp -ran /etc/sysctl.d "${BACKUP_DIR}/sysctl.d.bak" 2>/dev/null || true
    cp -ran /etc/systemd/journald.conf.d "${BACKUP_DIR}/journald.conf.d.bak" 2>/dev/null || true
    [ -f /etc/selinux/config ] && cp -an /etc/selinux/config "${BACKUP_DIR}/selinux.config.bak" 2>/dev/null || true
    sysctl -n net.ipv4.tcp_congestion_control > "${BACKUP_DIR}/sysctl_con_algo.bak" 2>/dev/null || true
    sysctl -n net.core.default_qdisc > "${BACKUP_DIR}/sysctl_q_algo.bak" 2>/dev/null || true
    systemctl list-unit-files --type=service --state=enabled > "${BACKUP_DIR}/enabled_services.before.txt" 2>/dev/null || true
    echo "# 由 sysOpt 脚本接触过的服务" > "$TOUCHED_SERVICES_FILE"
    fn_log "信息" "备份完成。"
}

fn_fix_apt_sources_if_needed() {
    fn_log "信息" "检查 APT 源健康状况..."
    if fn_check_apt_lock; then
        if apt-get update -qq >/dev/null 2>&1; then
            fn_log "成功" "APT 源正常。"
            return 0
        else
            fn_log "警告" "apt-get update 失败。将尝试保守替换 /etc/apt/sources.list"
            if command -v lsb_release >/dev/null 2>&1; then
                codename=$(lsb_release -cs)
            else
                codename=$(grep VERSION_CODENAME /etc/os-release 2>/dev/null | cut -d= -f2 || true)
            fi
            if [ -z "${codename:-}" ]; then
                fn_log "错误" "无法确定发行版代号，跳过自动替换源。"
                return 1
            fi
            cp -an /etc/apt/sources.list "${BACKUP_DIR}/apt.sources.list.bak" 2>/dev/null || true
            if [ "$OS_ID" = "debian" ]; then
                cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian/ $codename main contrib non-free
deb http://deb.debian.org/debian/ $codename-updates main contrib non-free
deb http://deb.debian.org/debian/ $codename-security main contrib non-free
EOF
            elif [ "$OS_ID" = "ubuntu" ]; then
                cat > /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu/ $codename main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $codename-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $codename-security main restricted universe multiverse
EOF
            else
                fn_log "错误" "此操作系统不支持自动替换源。"
                return 1
            fi
            if apt-get update -qq >/dev/null 2>&1; then
                fn_log "成功" "APT 源替换并刷新成功。"
                return 0
            else
                fn_log "错误" "替换源后 APT update 仍然失败。"
                return 1
            fi
        fi
    else
        fn_log "警告" "APT 似乎已锁定，跳过源健康检查。"
        return 1
    fi
}

fn_setup_journald_volatile() {
    fn_log "信息" "配置 journald 为 volatile (内存) 模式 (RuntimeMaxUse=16M)..."
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/10-volatile.conf <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=16M
MaxRetentionSec=1month
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    fn_log "成功" "journald 已配置为 volatile 模式。"
}

fn_setup_sysctl_lowmem() {
    fn_log "信息" "应用 sysctl 低内存网络调优 (包含 BBR+FQ)..."
    cat > /etc/sysctl.d/99-vps-lowmem.conf <<'EOF'
vm.swappiness = 10
vm.vfs_cache_pressure = 100
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.netdev_max_backlog = 2500
net.core.somaxconn = 1024
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_fin_timeout = 15
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1 || fn_log "警告" "sysctl 应用时出现警告。"
    fn_log "成功" "sysctl 自适应调优 (含 BBR) 已应用。"
}

fn_trim_services_auto() {
    fn_log "信息" "服务精简: 自动屏蔽 (mask) 非必要服务。"
    for svc in "${FN_TRIM_SERVICES_LIST[@]}"; do
        if systemctl list-unit-files --quiet "$svc"; then
            fn_log "信息" "正在屏蔽 (mask) $svc"
            systemctl mask --now "$svc" | tee -a "$LOG_FILE" || true
            echo "$svc" >> "$TOUCHED_SERVICES_FILE"
        else
            fn_log "信息" "服务 $svc 不存在，跳过。"
        fi
    done

    if systemctl list-unit-files --quiet "rsyslog.service"; then
        fn_log "信息" "正在屏蔽 (mask) rsyslog.service (日志将由 journald 处理)"
        systemctl mask --now rsyslog.service | tee -a "$LOG_FILE" || true
        echo "rsyslog.service" >> "$TOUCHED_SERVICES_FILE"
    else
        fn_log "信息" "rsyslog.service 未安装，跳过。"
    fi
}

fn_setup_zram_adaptive() {
    fn_log "信息" "尝试启用 ZRAM (自适应大小, lz4)。"

    if ! dpkg -s systemd-zram-generator >/dev/null 2>&1; then
        fn_log "信息" "systemd-zram-generator 未安装，正在尝试安装..."
        apt-get install -y systemd-zram-generator | tee -a "$LOG_FILE" || fn_log "警告" "systemd-zram-generator 安装失败，稍后将使用 Swap 回退。"
    fi

    mem_mb="$MEM_MB"
    zram_mb=$(( mem_mb < 512 ? 512 : mem_mb ))
    [ "$zram_mb" -gt "$mem_mb" ] && zram_mb="$mem_mb"
    fn_log "信息" "计算 ZRAM 大小: ${zram_mb}MB (物理内存: ${mem_mb}MB)"

    cat > /etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = ${zram_mb}M
compression-algorithm = lz4
swap-priority = 100
EOF

    modprobe zram || true
    systemctl daemon-reexec || true
    systemctl restart systemd-zram-setup@zram0.service || fn_log "警告" "ZRAM 服务启动失败，将尝试 Swap 回退。"

    if [ -b /dev/zram0 ] && swapon -s | grep -q 'zram'; then
        fn_log "成功" "ZRAM 已激活。"
        systemctl enable systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
        echo "systemd-zram-setup@zram0.service" >> "$TOUCHED_SERVICES_FILE"
        return 0
    else
        fn_log "信息" "启用 ZRAM 失败，创建 Swap 回退..."
        fn_setup_zram_fallback "ZRAM 激活失败"
    fi
}

fn_setup_zram_fallback() {
    local reason="$1"
    fn_log "警告" "$reason。使用 swapfile 回退方案。"

    mem_mb="$MEM_MB"
    swapsize=$(( mem_mb > 512 ? 512 : mem_mb ))
    [ "$swapsize" -lt 256 ] && swapsize=256

    swapfile="/swapfile_zram"
    if [ -f "$swapfile" ]; then
        swapon "$swapfile" >/dev/null 2>&1 || true
    else
        fallocate -l "${swapsize}M" "$swapfile" >/dev/null 2>&1 || dd if=/dev/zero of="$swapfile" bs=1M count="$swapsize" >/dev/null 2>&1
        chmod 600 "$swapfile"
        mkswap "$swapfile" >/dev/null 2>&1 || true
        swapon "$swapfile" >/dev/null 2>&1 || true
        echo "$swapfile" >> "${BACKUP_DIR}/created_swapfiles.txt"
    fi

    if swapon -s | grep -q "$(basename "$swapfile")"; then
        fn_log "成功" "Swapfile 已启用 (${swapsize}MB)。"
        return 0
    else
        fn_log "错误" "Swapfile 启用失败。"
        return 1
    fi
}

fn_prioritize_network_services_auto() {
    fn_log "信息" "为网络核心服务设置持久化高优先级。"
    local changes_made=0
    for svc in xray hysteria2 hysteria udp2raw kcptun; do
        if systemctl list-unit-files --quiet "${svc}.service"; then
            fn_log "信息" "为 $svc 设置 Nice=-5, CPUQuota=70%."
            mkdir -p "/etc/systemd/system/${svc}.service.d"
            cat > "/etc/systemd/system/${svc}.service.d/90-sysopt-lowmem.conf" <<EOF
[Service]
Nice=-5
CPUQuota=70%
EOF
            echo "${svc}.service" >> "$TOUCHED_SERVICES_FILE"
            changes_made=1
        fi
    done

    [ "$changes_made" -eq 1 ] && systemctl daemon-reload
}

fn_show_status_report() {
    clear
    echo "==================== 系统优化状态 ===================="
    [ -f /etc/os-release ] && source /etc/os-release
    printf "系统: %s\n" "${PRETTY_NAME:-unknown}"
    printf "内存: %s MB\n" "$MEM_MB"
    printf "内核: %s\n" "$(uname -r)"
    echo "------------------------------------------------------"

    echo "1. 网络优化 (Sysctl):"
    printf "  %-35s %s\n" "TCP 拥塞控制 (BBR)" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'n/a')"
    printf "  %-35s %s\n" "网络队列算法 (FQ)" "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'n/a')"
    printf "  %-35s %s\n" "Swappiness" "$(sysctl -n vm.swappiness 2>/dev/null || echo 'n/a')"
    printf "  %-35s %s\n" "VFS 缓存压力" "$(sysctl -n vm.vfs_cache_pressure 2>/dev/null || echo 'n/a')"

    echo "2. 日志 (Journald):"
    journalctl_storage=$(systemd-analyze cat-config systemd/journald.conf | grep -i '^Storage=' | tail -n 1 | cut -d= -f2 2>/dev/null || echo "disk")
    printf "  %-35s %s\n" "Journald 存储模式" "$journalctl_storage"

    echo "3. 交换空间 (Swap/ZRAM):"
    if swapon -s | grep -q 'zram'; then
        echo "  ZRAM 状态: [ 已激活 ]"
    elif swapon -s | grep -q "$(basename /swapfile_zram)"; then
        echo "  Swapfile 状态: [ 已激活 (回退方案) ]"
    else
        echo "  Swap 状态: [ 未激活 ]"
    fi
    echo "------------------------------------------------------"

    echo "4. 系统服务精简:"
    for svc in "${FN_TRIM_SERVICES_LIST[@]}"; do
        status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        printf "  %-35s %s\n" "$svc" "${status:-not-found}"
    done

    echo "5. 网络服务提权 (Drop-in):"
    for svc in xray hysteria2 hysteria udp2raw kcptun; do
        if [ -f "/etc/systemd/system/${svc}.service.d/90-sysopt-lowmem.conf" ]; then
            echo "  $svc -> Drop-in 设置已存在"
        fi
    done
    echo "======================================================"
}

fn_optimize_auto() {
    fn_check_root
    fn_detect_os
    fn_wait_for_apt_lock
    fn_fix_apt_sources_if_needed
    fn_backup_state
    fn_setup_journald_volatile
    fn_setup_sysctl_lowmem
    fn_trim_services_auto
    fn_setup_zram_adaptive
    fn_prioritize_network_services_auto
    fn_log "信息" "系统优化完成。"
    fn_show_status_report
}

fn_optimize_auto
