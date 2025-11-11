#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="2.3"
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
    fn_log "信息" "尝试启用 ZRAM (100% 比例, lz4)。"

    mem_mb="$MEM_MB"
    if [ -z "${mem_mb:-}" ] || [ "$mem_mb" -lt 1 ]; then
        mem_mb=512
    fi
    
    zram_mb=$(( mem_mb ))
    
    if [ "$zram_mb" -lt 512 ]; then
        zram_mb=512
    fi
    if [ "$zram_mb" -gt "$mem_mb" ]; then
        zram_mb="$mem_mb"
    fi
    fn_log "信息" "计算 ZRAM 大小: ${zram_mb}MB (物理内存: ${mem_mb}MB)"

    fn_log "信息" "尝试安装 systemd-zram-generator..."
    if apt-get install -y systemd-zram-generator | tee -a "$LOG_FILE"; then
        cat > /etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = ${zram_mb}M
compression-algorithm = lz4
swap-priority = 100
EOF
        systemctl daemon-reload
        systemctl enable --now systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
        sleep 1
        if swapon -s | grep -q 'zram'; then
            fn_log "成功" "ZRAM 已通过 zram-generator 启用。"
            echo "systemd-zram-setup@zram0.service" >> "$TOUCHED_SERVICES_FILE"
            return 0
        else
            fn_log "警告" "zram-generator 安装了但未成功激活 zram。"
        fi
    else
        fn_log "警告" "systemd-zram-generator 安装失败或不可用。"
    fi

    fn_log "警告" "ZRAM 安装失败。将创建小型 swapfile 作为最终回退方案。"
    swapfile="/swapfile_sysopt_lowmem"
    
    local swapsize_mb
    if [ "$zram_mb" -gt 512 ]; then
        swapsize_mb=512
    else
        swapsize_mb="$zram_mb"
    fi
    
    if [ -f "$swapfile" ]; then
        fn_log "信息" "Swapfile 已存在，尝试启用它。"
        swapon "$swapfile" >/dev/null 2>&1 || true
    else
        fallocate -l "${swapsize_mb}M" "$swapfile" >/dev/null 2>&1 || dd if=/dev/zero of="$swapfile" bs=1M count="$swapsize_mb" >/dev/null 2>&1
        chmod 600 "$swapfile"
        mkswap "$swapfile" >/dev/null 2>&1 || true
        swapon "$swapfile" >/dev/null 2>&1 || true
        echo "$swapfile" >> "${BACKUP_DIR}/created_swapfiles.txt"
    fi
    if swapon -s | grep -q "$(basename "$swapfile")"; then
        fn_log "成功" "Swapfile 已作为回退方案启用 (${swapsize_mb}MB)。"
        return 0
    else
        fn_log "错误" "启用 swapfile 回退方案失败。"
        return 1
    fi
}

fn_prioritize_network_services_auto() {
    fn_log "信息" "为网络核心服务设置持久化高优先级。"
    local changes_made=0
    for svc in xray hysteria2 hysteria udp2raw kcptun; do
        if systemctl list-unit-files --quiet "${svc}.service"; then
            fn_log "信息" "为 $svc 设置 Nice=-5, CPUQuota=70%。"
            
            local svc_conf_dir="/etc/systemd/system/${svc}.service.d"
            mkdir -p "$svc_conf_dir"
            cat > "${svc_conf_dir}/90-sysopt-lowmem.conf" <<EOF
[Service]
Nice=-5
CPUQuota=70%
EOF
            echo "${svc}.service" >> "$TOUCHED_SERVICES_FILE"
            changes_made=1
        fi
    done

    if [ "$changes_made" -eq 1 ]; then
        fn_log "信息" "重载 systemd daemon 以应用服务优先级。"
        systemctl daemon-reload
    fi
}

fn_restore_zram_and_swap() {
    fn_log "信息" "恢复 ZRAM / swap 状态: 禁用服务并移除创建的文件。"
    systemctl disable --now vps-zram.service >/dev/null 2>&1 || true
    systemctl disable --now zramswap.service >/dev/null 2>&1 || true
    systemctl disable --now systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/vps-zram.service
    rm -f /etc/systemd/zram-generator.conf
    rm -f /etc/default/zramswap
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -f "${BACKUP_DIR}/created_swapfiles.txt" ]; then
        while read -r sf; do
            [ -z "$sf" ] && continue
            if swapon -s | grep -q "$(basename "$sf")"; then
                swapoff "$sf" >/dev/null 2>&1 || true
            fi
            rm -f "$sf" || true
            fn_log "信息" "已移除 swapfile $sf"
        done < "${BACKUP_DIR}/created_swapfiles.txt"
    fi
    swapoff -a >/dev/null 2>&1 || true
    modprobe -r zram >/dev/null 2>&1 || true
    fn_log "成功" "ZRAM / swap 恢复完成。"
}

fn_restore_all() {
    fn_log "警告" "开始执行撤销优化... 将从 $BACKUP_DIR 恢复备份。"
    
    fn_log "信息" "恢复 sysctl (并保留 BBR+FQ)..."
    
    rm -f /etc/sysctl.d/99-vps-lowmem.conf

    if [ -f "${BACKUP_DIR}/sysctl.conf.bak" ]; then
        cp -an "${BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf 2>/dev/null || true
    fi
    
    if [ -d "${BACKUP_DIR}/sysctl.d.bak" ]; then
        cp -ar "${BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/ 2>/dev/null || true
    fi

    cat > /etc/sysctl.d/98-bbr-retention.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl --system >/dev/null 2>&1 || true

    fn_log "信息" "恢复 journald..."
    if [ -d "${BACKUP_DIR}/journald.conf.d.bak" ]; then
        rm -rf /etc/systemd/journald.conf.d/
        cp -ar "${BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/ 2>/dev/null || true
        systemctl restart systemd-journald >/dev/null 2>&1 || true
    else
        rm -rf /etc/systemd/journald.conf.d/ || true
        systemctl restart systemd-journald >/dev/null 2>&1 || true
    fi

    if [ -f "${BACKUP_DIR}/apt.sources.list.bak" ]; then
        cp -an "${BACKUP_DIR}/apt.sources.list.bak" /etc/apt/sources.list 2>/dev/null || true
    fi

    fn_log "信息" "恢复服务: 正在解除(unmask)所有被屏蔽的服务..."
    if [ -f "$TOUCHED_SERVICES_FILE" ]; then
        while read -r svc; do
            [ -z "$svc" ] && continue
            if [[ "$svc" == *.service ]] || [[ "$svc" == *.timer ]] || [[ "$svc" == *.socket ]]; then
                 systemctl unmask "$svc" >/dev/null 2>&1 || true
            fi
        done < <(grep -v '^#' "$TOUCHED_SERVICES_FILE")
    fi

    if [ -f "${BACKUP_DIR}/enabled_services.before.txt" ]; then
        fn_log "信息" "尝试从备份列表恢复服务启用状态..."
        while read -r s; do
            [ -z "$s" ] && continue
            systemctl enable "$s" >/dev/null 2>&1 || true
        done < "${BACKUP_DIR}/enabled_services.before.txt"
    fi

    if grep -q "^rsyslog.service$" "${BACKUP_DIR}/enabled_services.before.txt" 2>/dev/null; then
        systemctl enable --now rsyslog.service >/dev/null 2>&1 || true
    fi

    if [ -f "${BACKUP_DIR}/fstab.bak" ]; then
        cp -an "${BACKUP_DIR}/fstab.bak" /etc/fstab 2>/dev/null || true
        swapon -a >/dev/null 2>&1 || true
    fi

    fn_restore_zram_and_swap

    fn_log "信息" "恢复服务优先级 (移除 drop-in 文件)..."
    local configs_removed=0
    if [ -f "$TOUCHED_SERVICES_FILE" ]; then
        while read -r svc; do
            [ -z "$svc" ] && continue
            if [[ "$svc" == *.service ]]; then
                local svc_conf_dir="/etc/systemd/system/${svc}.d"
                if [ -d "$svc_conf_dir" ]; then
                    rm -rf "$svc_conf_dir"
                    fn_log "信息" "已移除 $svc_conf_dir"
                    configs_removed=1
                fi
            fi
        done < <(grep -v '^#' "$TOUCHED_SERVICES_FILE")
    fi
    
    if [ "$configs_removed" -eq 1 ]; then
        systemctl daemon-reload
    fi

    fn_log "成功" "撤销优化 (除 BBR 外) 已完成。请查看 $LOG_FILE 日志。"
}

fn_show_status_report() {
    clear
    echo "==================== 系统优化状态 ===================="
    [ -f /etc/os-release ] && source /etc/os-release
    printf "系统: %s\n" "${PRETTY_NAME:-unknown}"
    printf "内存: %s MB\n" "$MEM_MB"
    printf "内核: %s\n" "$(uname -r)"
    echo "------------------------------------------------------"

    fn_print_check() {
        local name="$1"
        local expected="$2"
        local actual="$3"
        local status_msg="[ 未优化 ]"
        local details="(预期: $expected, 实际: $actual)"

        if [ "$actual" == "$expected" ] || { [ "$expected" == "disabled" ] && [ "$actual" == "masked" ]; }; then
            status_msg="[ 已优化 ]"
            details="(状态: $actual)"
        elif [ "$expected" == "disabled" ] && [ "$actual" == "static" ]; then
            status_msg="[ 已优化 ]"
            details="(状态: static)"
        elif [ -z "$actual" ] || [ "$actual" == "not-found" ]; then
             actual="未设置"
             details="(预期: $expected, 实际: 未设置)"
             if [ "$expected" == "disabled" ]; then
                status_msg="[ 已优化 ]"
                details="(未安装)"
             fi
        fi
        printf "  %-35s %s %s\n" "$name" "$status_msg" "$details"
    }

    echo "1. 网络优化 (Sysctl):"
    fn_print_check "TCP 拥塞控制 (BBR)" "bbr" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'n/a')"
    fn_print_check "网络队列算法 (FQ)" "fq" "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'n/a')"

    echo "2. 日志 (Journald):"
    local journal_storage
    journal_storage=$(systemd-analyze cat-config systemd/journald.conf | grep -i '^Storage=' | tail -n 1 | cut -d= -f2 2>/dev/null || echo "disk")
    fn_print_check "Journald 存储模式" "volatile" "${journal_storage:-disk}"
    
    echo "3. 交换空间 (Swap/ZRAM):"
    if swapon -s | grep -q 'zram'; then
        echo "  ZRAM 状态: [ 已激活 ]"
    elif swapon -s | grep -q 'swapfile'; then
        echo "  Swapfile 状态: [ 已激活 (回退方案) ]"
    else
        echo "  Swap 状态: [ 未激活 ]"
    fi
    echo "--- 当前内存与 Swap ---"
    free -h
    swapon -s || true
    echo "------------------------"

    echo "4. 系统服务精简:"
    local svc_status
    for svc in "${FN_TRIM_SERVICES_LIST[@]}"; do
        svc_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        if [ "$svc_status" != "not-found" ]; then
            fn_print_check "服务: $svc" "disabled" "$svc_status"
        fi
    done
    svc_status=$(systemctl is-enabled "rsyslog.service" 2>/dev/null || echo "not-found")
    fn_print_check "服务: rsyslog.service" "disabled" "$svc_status"

    echo "5. 网络服务提权 (Drop-in):"
    local drop_in_found="no"
    for svc in xray hysteria2 hysteria udp2raw kcptun; do
        if [ -f "/etc/systemd/system/${svc}.service.d/90-sysopt-lowmem.conf" ]; then
            echo "  提权配置: ${svc} [ 已配置 ]"
            drop_in_found="yes"
        fi
    done
    if [ "$drop_in_found" == "no" ]; then
         echo "  (未检测到受支持的网络服务提权配置)"
    fi
    
    echo "======================================================"
}

fn_optimize_auto() {
    fn_backup_state

    fn_log "信息" "步骤 1/7: 等待 APT 锁并更新软件包列表..."
    if ! fn_wait_for_apt_lock; then
        fn_log "错误" "等待 APT 锁超时。脚本将继续，但 ZRAM 安装可能失败。"
    else
        apt-get update -qq | tee -a "$LOG_FILE" || fn_log "警告" "apt update 失败，但仍将继续..."
    fi

    fn_log "信息" "步骤 2/7: 检查并修复 APT 源..."
    fn_fix_apt_sources_if_needed || fn_log "警告" "APT 修复步骤出现问题，但仍继续。"

    fn_log "信息" "步骤 3/7: 配置 journald 为内存模式..."
    fn_setup_journald_volatile

    fn_log "信息" "步骤 4/7: 应用 sysctl 调优 (BBR+FQ)..."
    fn_setup_sysctl_lowmem

    fn_log "信息" "步骤 5/7: 精简非必要服务 (使用 mask)..."
    fn_trim_services_auto

    fn_log "信息" "步骤 6/7: 启用 ZRAM (100% 比例)..."
    if fn_setup_zram_adaptive; then
        fn_log "成功" "ZRAM / Swap 设置成功。"
    else
        fn_log "错误" "ZRAM / Swap 设置失败。"
    fi

    fn_log "信息" "步骤 7/7: 提升网络服务优先级..."
    fn_prioritize_network_services_auto

    fn_log "成功" "=== 优化已完成 ==="
    fn_show_status_report
    fn_log "重要" "请检查 $LOG_FILE 获取详细日志。建议在方便时重启系统以应用所有更改。"
}

fn_show_menu() {
    clear
    echo "==============================================="
    echo " VPS 低内存自动优化脚本 (sysOpt_lowmem)"
    echo " 脚本版本: $SCRIPT_VERSION"
    echo " 备份目录: $BACKUP_DIR"
    echo " 日志文件: $LOG_FILE"
    echo "==============================================="
    echo " 1) 执行系统优化 (全自动)"
    echo " 2) 撤销优化 (保留BBR)"
    echo " 3) 显示系统优化状态"
    echo " 0) 退出"
    echo "==============================================="
    read -rp "请选择: " CH
    case "$CH" in
        1) fn_optimize_auto ;;
        2) fn_restore_all ;;
        3) fn_show_status_report; read -rp "按回车返回菜单..." dummy ;;
        0) fn_log "信息" "退出。"; exit 0 ;;
        *) fn_log "错误" "无效选项。"; sleep 1; fn_show_menu ;;
    esac
    read -rp "按回车返回主菜单..." dummy
    fn_show_menu
}

fn_check_root
fn_detect_os

fn_show_menu
