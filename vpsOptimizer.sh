#!/bin/bash
# =========================================================
# Prime Optimizer v6.1 (Hotfix)
#
# 支持系统: Debian 10, 11, 12 | Ubuntu 20.04, 22.04, 24.04
# =========================================================

# --- [全局变量] ---
VERSION="6.1"
OS_ID=""
OS_VERSION_ID=""
BACKUP_DIR=""
LOG_FILE="/dev/null"
TOUCHED_SERVICES_FILE=""

# “安全裁剪”服务列表 
FN_TRIM_SERVICES_LIST=(
    "apparmor.service"
    "atop.service"
    "atopacct.service"
    "cloud-config.service"
    "cloud-final.service"
    "cloud-init-local.service"
    "cloud-init.service"
    "getty@tty1.service"
    "console-setup.service"
    "keyboard-setup.service"
    "e2scrub_reap.service"
    "systemd-pstore.service"
    "rsyslog.service"
    "qemu-guest-agent.service"
    "unattended-upgrades.service"
    "motd-news.service"
)

# --- [1. 辅助功能 (日志与检测)] ---

fn_log() {
    local color_cyan="\033[0;36m"
    local color_green="\033[0;32m"
    local color_red="\033[0;31m"
    local color_yellow="\033[0;33m"
    local color_reset="\033[0m"
    local color
    case "$1" in
        INFO) color="$color_cyan" ;;
        SUCCESS) color="$color_green" ;;
        WARN) color="$color_yellow" ;;
        ERROR) color="$color_red" ;;
        *) color="$color_reset" ;;
    esac
    echo -e "[${color}$1${color_reset}] $2" | tee -a "$LOG_FILE"
}

fn_check_root() {
    if [ "$EUID" -ne 0 ]; then
        fn_log "ERROR" "此脚本必须以 root 权限运行。"
        exit 1
    fi
}

# OS 检测与支持验证
fn_detect_os() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_ID=$ID
        OS_VERSION_ID=$VERSION_ID
        fn_log "INFO" "检测到系统: $PRETTY_NAME"
    else
        fn_log "ERROR" "无法检测操作系统: /etc/os-release 不存在。"
        exit 1
    fi

    case "$OS_ID" in
        debian)
            case "$OS_VERSION_ID" in
                10|11|12) fn_log "SUCCESS" "Debian $OS_VERSION_ID 受支持。" ;;
                *) fn_log "ERROR" "Debian $OS_VERSION_ID 不受支持。"; exit 1 ;;
            esac
            ;;
        ubuntu)
            case "$OS_VERSION_ID" in
                20.04|22.04|24.04) fn_log "SUCCESS" "Ubuntu $OS_VERSION_ID 受支持。" ;;
                *) fn_log "ERROR" "Ubuntu $OS_VERSION_ID 不受支持。"; exit 1 ;;
            esac
            ;;
        centos|rhel|almalinux|rocky|fedora)
            fn_log "ERROR" "系统 $OS_ID ($PRETTY_NAME) 是基于 RHEL 的。"
            fn_log "ERROR" "此脚本专为 Debian/Ubuntu 优化 (apt, systemd-zram-generator)，不支持 RHEL 家族。"
            exit 1
            ;;
        *)
            fn_log "ERROR" "操作系统 '$OS_ID' 不受支持。"
            exit 1
            ;;
    esac
}

# --- [2. 核心功能 (备份, 优化, 恢复)] ---

fn_backup_state() {
    fn_log "INFO" "创建备份目录: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    cp /etc/fstab "${BACKUP_DIR}/fstab.bak"
    cp -r /etc/sysctl.d/ "${BACKUP_DIR}/sysctl.d.bak" 2>/dev/null || true
    cp /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak" 2>/dev/null || true
    cp -r /etc/systemd/journald.conf.d/ "${BACKUP_DIR}/journald.conf.d.bak" 2>/dev/null || true
    systemctl list-unit-files --type=service --state=enabled > "${BACKUP_DIR}/enabled_services.before.txt"
    echo "# Services disabled by optimizer" > "$TOUCHED_SERVICES_FILE"
}

# 动态服务裁剪
fn_trim_services() {
    fn_log "INFO" "[3/7] 裁剪非必要服务 (动态检测)..."
    for service in "${FN_TRIM_SERVICES_LIST[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            fn_log "INFO" "  -> 检测到: $service (已启用). 正在禁用..."
            systemctl disable --now "$service" >/dev/null 2>&1
            echo "$service" >> "$TOUCHED_SERVICES_FILE"
        elif systemctl is-active "$service" >/dev/null 2>&1; then
            fn_log "INFO" "  -> 检测到: $service (正在运行但未启用). 仅停止..."
            systemctl stop "$service" >/dev/null 2>&1
        fi
    done
    fn_log "SUCCESS" "服务裁剪完成。"
}

# ZRAM 安装
fn_setup_zram() {
    MEM_MB=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))
    ZRAM_SIZE_MB=$MEM_MB
    fn_log "INFO" "  -> 物理内存: ${MEM_MB}MB, ZRAM 将设置为: ${ZRAM_SIZE_MB}MB"

    # Debian 10 / Ubuntu 20.04
    if ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "10" ] ) || \
       ( [ "$OS_ID" = "ubuntu" ] && [ "$OS_VERSION_ID" = "20.04" ] ); then
        
        fn_log "INFO" "  -> 使用 'zram-tools' 适用于 $OS_ID $OS_VERSION_ID"
        apt-get update > /dev/null
        apt-get install -y zram-tools > /dev/null
        
        [ -f /etc/default/zramswap ] && cp /etc/default/zramswap "${BACKUP_DIR}/zramswap.bak"
        
        cat > /etc/default/zramswap <<EOF
# Configured by Prime Optimizer v$VERSION
ALGO=zstd
SIZE=${ZRAM_SIZE_MB}M
EOF
        systemctl enable --now zramswap.service
        
    # Debian 11+ / Ubuntu 22.04+
    else
        fn_log "INFO" "  -> 使用 'systemd-zram-generator' 适用于 $OS_ID $OS_VERSION_ID"
        apt-get update > /dev/null
        apt-get install -y systemd-zram-generator > /dev/null
        
        cat > /etc/systemd/zram-generator.conf <<EOF
[zram0]
zram-size = ${ZRAM_SIZE_MB}M
compression-algorithm = zstd
EOF
        systemctl daemon-reload
        systemctl enable --now systemd-zram-setup@zram0.service
    fi
}

# ZRAM 恢复
fn_restore_zram() {
    # Debian 10 / Ubuntu 20.04
    if ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "10" ] ) || \
       ( [ "$OS_ID" = "ubuntu" ] && [ "$OS_VERSION_ID" = "20.04" ] );
    then
        fn_log "INFO" "  -> 正在禁用 'zramswap.service'..."
        systemctl disable --now zramswap.service 2>/dev/null
        rm /etc/default/zramswap 2>/dev/null
        if [ -f "${USER_BACKUP_DIR}/zramswap.bak" ]; then
            cp "${USER_BACKUP_DIR}/zramswap.bak" /etc/default/zramswap
        fi
    # Debian 11+ / Ubuntu 22.04+
    else
        fn_log "INFO" "  -> 正在禁用 'systemd-zram-setup'..."
        systemctl disable --now systemd-zram-setup@zram0.service 2>/dev/null
        rm /etc/systemd/zram-generator.conf 2>/dev/null
    fi
}

# 菜单 1: 自动优化
fn_optimize_auto() {
    if [ -f "/etc/systemd/zram-generator.conf" ] || [ -f "/etc/default/zramswap" ]; then
        fn_log "WARN" "检测到已存在的 ZRAM 配置。"
        fn_log "WARN" "如果您想重新优化，请先运行 [3] 恢复备份。"
        return 1
    fi

    BACKUP_DIR="/root/system_optimize_backup_$(date +%s)"
    LOG_FILE="${BACKUP_DIR}/optimize.log"
    TOUCHED_SERVICES_FILE="${BACKUP_DIR}/touched_services.txt"
    fn_log "SUCCESS" "开始自动优化... 日志将保存到: $LOG_FILE"
    
    fn_backup_state

    fn_log "INFO" "[1/7] 禁用现有文件 Swap..."
    swapoff -a
    sed -i.bak '/swap/s/^/#/' /etc/fstab

    fn_log "INFO" "[2/7] 安装与配置 ZRAM..."
    fn_setup_zram

    fn_trim_services

    fn_log "INFO" "[4/7] 配置 journald (RAM 内存日志)..."
    mkdir -p /etc/systemd/journald.conf.d/
    cat <<EOF > /etc/systemd/journald.conf.d/10-ram-only.conf
[Journal]
Storage=volatile
RuntimeMaxUse=32M
EOF
    systemctl restart systemd-journald

    fn_log "INFO" "[5/7] CPU 调速器持久化为 Performance 模式..."
    cat > /etc/systemd/system/cpugov-performance.service <<'EOF'
[Unit]
Description=Set CPU governor to performance
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c "for CPU in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $CPU 2>/dev/null; done"
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now cpugov-performance.service

    fn_log "INFO" "[6/7] 融合 Sysctl (TCP/UDP/Mem)..."
    cat > /etc/sysctl.d/99-prime-fused.conf <<'EOF'
# === Prime Optimizer v6.1 Fused Tuning (TCP/UDP/Mem) ===
vm.vfs_cache_pressure = 50
vm.swappiness = 10
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 32768
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 10000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_fastopen = 3
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
    sysctl -p /etc/sysctl.d/99-prime-fused.conf

    fn_log "INFO" "[7/7] 优化报告..."
    echo "--- 内存与 Swap (ZRAM) 状态:" | tee -a "$LOG_FILE"
    free -h | tee -a "$LOG_FILE"
    swapon --show | tee -a "$LOG_FILE"
    echo "--- CPU 调速器状态:" | tee -a "$LOG_FILE"
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor | tee -a "$LOG_FILE"

    fn_log "SUCCESS" "自动优化完成！"
    fn_log "IMPORTANT" "备份数据保存在: $BACKUP_DIR"
    fn_log "IMPORTANT" "建议立即重启 (reboot) 以应用所有更改。"
}

# 菜单 2: 手动优化
fn_optimize_manual() {
    fn_log "INFO" "手动优化提示"
    echo "-----------------------------------------------------"
    echo "手动优化涉及自行编辑配置文件。以下是关键文件："
    echo
    echo "1. 网络栈: /etc/sysctl.d/99-custom.conf"
    echo "2. 日志:   /etc/systemd/journald.conf.d/10-ram.conf"
    echo "3. 磁盘IO: /etc/fstab (添加 noatime,nodiratime 选项)"
    echo "4. 服务:   使用 'systemctl disable <service.name>' 禁用服务"
    echo
    fn_log "INFO" "未执行任何自动更改。"
}

# 菜单 3: 恢复备份
fn_restore_state() {
    fn_log "WARN" "开始恢复流程..."
    
    echo "--- 可用的备份 ---"
    ls -d /root/system_optimize_backup_* 2>/dev/null || echo "未找到任何备份。"
    echo "---------------------"
    
    echo "请输入您要恢复的完整备份目录路径："
    echo "(例如: /root/system_optimize_backup_1678886666)"
    read -r USER_BACKUP_DIR

    if [ ! -d "$USER_BACKUP_DIR" ] || [ ! -f "${USER_BACKUP_DIR}/fstab.bak" ]; then
        fn_log "ERROR" "无效的备份目录: $USER_BACKUP_DIR"
        return 1
    fi

    LOG_FILE="${USER_BACKUP_DIR}/restore.log"
    fn_log "INFO" "正在从 $USER_BACKUP_DIR 恢复... 日志: $LOG_FILE"

    fn_log "INFO" "[1/6] 禁用 ZRAM..."
    fn_restore_zram

    fn_log "INFO" "[2/6] 恢复 /etc/fstab..."
    cp "${USER_BACKUP_DIR}/fstab.bak" /etc/fstab
    fn_log "INFO" "尝试重新激活旧的 Swap..."
    swapon -a

    fn_log "INFO" "[3/6] 恢复 journald 配置..."
    rm -rf /etc/systemd/journald.conf.d/
    [ -d "${USER_BACKUP_DIR}/journald.conf.d.bak" ] && cp -r "${USER_BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/
    systemctl restart systemd-journald

    fn_log "INFO" "[4/6] 恢复 Sysctl 配置..."
    rm /etc/sysctl.d/99-prime-fused.conf 2>/dev/null
    rm -rf /etc/sysctl.d/
    [ -d "${USER_BACKUP_DIR}/sysctl.d.bak" ] && cp -r "${USER_BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/
    [ -f "${USER_BACKUP_DIR}/sysctl.conf.bak" ] && cp "${USER_BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf
    sysctl --system > /dev/null

    fn_log "INFO" "[5/6] 恢复 CPU 默认模式..."
    systemctl disable --now cpugov-performance.service 2>/dev/null
    rm /etc/systemd/system/cpugov-performance.service 2>/dev/null
    fn_log "INFO" "  -> CPU governor 将在重启后恢复为系统默认值。"

    fn_log "INFO" "[6/6] 恢复被禁用的服务 (根据备份日志)..."
    local touched_services_file="${USER_BACKUP_DIR}/touched_services.txt"
    
    if [ -f "$touched_services_file" ]; then
        grep -vE '^(#|$)' "$touched_services_file" | while read -r service; do
            if [ -n "$service" ]; then
                fn_log "INFO" "  -> 正在重新启用: $service"
                systemctl enable "$service" >/dev/null 2>&1
            fi
        done
    else
        fn_log "WARN" "未找到 'touched_services.txt'. 跳过服务恢复。"
    fi
    
    # 关键: 确保 networking.service 被重新启用 (如果它在恢复日志中)
    # 并且，即使用户之前手动恢复，也要确保它被启用，因为它现在被认为是关键服务
    fn_log "INFO" "  -> 确保 'networking.service' (关键服务) 已启用..."
    systemctl enable networking.service >/dev/null 2>&1
    
    systemctl daemon-reload

    fn_log "SUCCESS" "恢复完成！"
    fn_log "IMPORTANT" "建议立即重启 (reboot) 以使所有原始服务生效。"
}

# --- [3. 主菜单] ---

fn_show_menu() {
    clear
    echo "============================================================"
    echo " Prime Optimizer v$VERSION (Hotfix, 稳定性优先)"
    echo " 支持: Debian 10-12, Ubuntu 20.04-24.04"
    echo "============================================================"
    echo "  1) 自动优化 (推荐)"
    echo "  2) 手动优化 (查看提示)"
    echo "  3) 恢复备份 (撤销优化)"
    echo "  Q) 退出"
    echo "============================================================"
    echo
    echo "请选择:"
    read -r choice

    case $choice in
        1)
            fn_optimize_auto
            ;;
        2)
            fn_optimize_manual
            ;;
        3)
            fn_restore_state
            ;;
        [qQ])
            fn_log "INFO" "退出。"
            exit 0
            ;;
        *)
            fn_log "ERROR" "无效选择，请重试。"
            sleep 2
            fn_show_menu
            ;;
    esac
}

# --- 脚本入口 ---
fn_check_root
fn_detect_os
fn_show_menu
