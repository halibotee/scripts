#!/bin/bash
# =========================================================
# Prime Optimizer v15.0 (Hotfix)
#
# 变更 (V15.0):
# 1. 修复 (关键): 放弃 systemd-zram-generator (在 backports 中不可用)。
# 2. 变更: 强制 Debian 11 回退使用 'zram-tools' (在主源中可用)，
#    确保 ZRAM 在您的系统上安装成功。
# 3. 移除: 失败的 'fn_fix_apt_sources'。
#
# 支持系统: Debian 10, 11, 12 | Ubuntu 20.04, 22.04, 24.04
# =========================================================

# --- [全局变量] ---
VERSION="15.0"
OS_ID=""
OS_VERSION_ID=""
MEM_MB=0
BACKUP_DIR="/root/system_optimize_backup"
LOG_FILE="${BACKUP_DIR}/optimize.log"
TOUCHED_SERVICES_FILE="${BACKUP_DIR}/touched_services.txt"

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
    [ -n "$BACKUP_DIR" ] && mkdir -p "$BACKUP_DIR"
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
    mkdir -p "$BACKUP_DIR"
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_ID=$ID
        OS_VERSION_ID=$VERSION_ID
        fn_log "INFO" "检测到系统: $PRETTY_NAME"
    else
        fn_log "ERROR" "无法检测操作系统: /etc/os-release 不存在。"
        exit 1
    fi
    
    MEM_MB=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))
    fn_log "INFO" "检测到物理内存: ${MEM_MB}MB"

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
        *)
            fn_log "ERROR" "操作系统 '$OS_ID' 不受支持。"
            exit 1
            ;;
    esac
}

# --- [2. 核心功能 (备份, 优化, 恢复)] ---

fn_backup_state() {
    fn_log "INFO" "创建备份目录: $BACKUP_DIR"
    cp /etc/fstab "${BACKUP_DIR}/fstab.bak"
    cp -r /etc/sysctl.d/ "${BACKUP_DIR}/sysctl.d.bak" 2>/dev/null || true
    cp /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak" 2>/dev/null || true
    cp -r /etc/systemd/journald.conf.d/ "${BACKUP_DIR}/journald.conf.d.bak" 2>/dev/null || true
    [ -f /etc/selinux/config ] && cp /etc/selinux/config "${BACKUP_DIR}/selinux.config.bak"
    [ -f /etc/systemd/resolved.conf ] && cp /etc/systemd/resolved.conf "${BACKUP_DIR}/resolved.conf.bak"
    
    fn_log "INFO" "备份当前 sysctl 算法..."
    sysctl -n net.ipv4.tcp_congestion_control > "${BACKUP_DIR}/sysctl_con_algo.bak" 2>/dev/null
    sysctl -n net.core.default_qdisc > "${BACKUP_DIR}/sysctl_q_algo.bak" 2>/dev/null

    systemctl list-unit-files --type=service --state=enabled > "${BACKUP_DIR}/enabled_services.before.txt"
    echo "# Services touched by optimizer" > "$TOUCHED_SERVICES_FILE"
}

# 动态服务裁剪
fn_trim_services() {
    fn_log "INFO" "[5/10] 裁剪非必要服务 (动态检测)..."
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

# (V15.0 修复) 智能 ZRAM 安装
fn_setup_zram() {
    local ZRAM_SIZE_MB=$MEM_MB
    fn_log "INFO" "  -> 物理内存: ${MEM_MB}MB, ZRAM 将设置为: ${ZRAM_SIZE_MB}MB"
    local zram_config_content
    zram_config_content=$(cat <<EOF
[zram0]
zram-size = ${ZRAM_SIZE_MB}M
compression-algorithm = zstd
EOF
)
    local install_cmd=""
    local configure_zram_tools=false

    # 分支 1: Debian 10, 11 / Ubuntu 20.04 (zram-tools fallback)
    if ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "10" ] ) || \
       ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "11" ] ) || \
       ( [ "$OS_ID" = "ubuntu" ] && [ "$OS_VERSION_ID" = "20.04" ] ); then
        
        fn_log "INFO" "  -> 使用 'zram-tools' (稳定回退) 适用于 $OS_ID $OS_VERSION_ID"
        install_cmd="apt-get install -y zram-tools"
        configure_zram_tools=true
        
    # 分支 2: Debian 12+, Ubuntu 22.04+ (systemd-zram-generator from main)
    else
        fn_log "INFO" "  -> 使用 'systemd-zram-generator' (来自 Main Repo)"
        install_cmd="apt-get install -y systemd-zram-generator"
    fi

    # 执行安装
    $install_cmd > /dev/null
    if [ $? -ne 0 ]; then fn_log "ERROR" "ZRAM 软件包安装失败。"; return 1; fi

    # 执行配置
    if [ "$configure_zram_tools" = true ]; then
        [ -f /etc/default/zramswap ] && cp /etc/default/zramswap "${BACKUP_DIR}/zramswap.bak"
        cat > /etc/default/zramswap <<EOF
# Configured by Prime Optimizer v$VERSION
ALGO=zstd
SIZE=${ZRAM_SIZE_MB}M
EOF
        systemctl enable --now zramswap.service
    else
        echo "$zram_config_content" > /etc/systemd/zram-generator.conf
        systemctl daemon-reload
        systemctl enable --now systemd-zram-setup@zram0.service
    fi
    return 0
}

# ZRAM 恢复
fn_restore_zram() {
    # Debian 10, 11 / Ubuntu 20.04
    if ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "10" ] ) || \
       ( [ "$OS_ID" = "debian" ] && [ "$OS_VERSION_ID" = "11" ] ) || \
       ( [ "$OS_ID" = "ubuntu" ] && [ "$OS_VERSION_ID" = "20.04" ] );
    then
        fn_log "INFO" "  -> 正在禁用 'zramswap.service'..."
        systemctl disable --now zramswap.service 2>/dev/null
        rm /etc/default/zramswap 2>/dev/null
        if [ -f "${BACKUP_DIR}/zramswap.bak" ]; then
            cp "${BACKUP_DIR}/zramswap.bak" /etc/default/zramswap
        fi
    # Debian 12+ / Ubuntu 22.04+
    else
        fn_log "INFO" "  -> 正在禁用 'systemd-zram-setup'..."
        systemctl disable --now systemd-zram-setup@zram0.service 2>/dev/null
        rm /etc/systemd/zram-generator.conf 2>/dev/null
    fi
}

# 动态检测 SELinux
fn_detect_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status
        selinux_status=$(getenforce)

        if [ "$selinux_status" != "Disabled" ]; then
            fn_log "WARN" "检测到 SELinux 状态为: $selinux_status"
            fn_log "WARN" "SELinux 会导致性能问题并可能与优化冲突。"
            echo "-----------------------------------------------------"
            echo "是否要将其永久禁用 (推荐)? (y/n)"
            read -r selinux_choice
            
            if [ "$selinux_choice" = "y" ] || [ "$selinux_choice" = "Y" ]; then
                fn_log "INFO" "正在禁用 SELinux..."
                setenforce 0 2>/dev/null
                if [ -f /etc/selinux/config ]; then
                    sed -i.bak 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
                    fn_log "SUCCESS" "SELinux 已永久禁用。需要重启生效。"
                else
                    fn_log "ERROR" "未找到 /etc/selinux/config，无法永久禁用。"
                fi
                echo "selinux" >> "$TOUCHED_SERVICES_FILE"
            else
                fn_log "WARN" "跳过禁用 SELinux。这可能导致后续步骤失败。"
            fi
        else
             fn_log "INFO" "SELinux 状态: Disabled (良好)。"
        fi
    else
        fn_log "INFO" "未检测到 SELinux (正常)。"
    fi
}

# 状态报告
fn_show_status_report() {
    echo "--- [系统运行状态报告] ---"
    
    if [ -z "$PRETTY_NAME" ] && [ -f /etc/os-release ]; then
        source /etc/os-release
    fi
    
    local os_info="$PRETTY_NAME"
    local virt_info=$(systemd-detect-virt 2>/dev/null || echo "KVM")
    local arch_info=$(uname -m)
    local kernel_info=$(uname -r)
    
    local con_algo_post=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local q_algo_post=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    local bbr_status
    if [[ "$con_algo_post" == "bbr" ]]; then
        bbr_status="已启用 BBR 加速 (BBR + FQ)"
    else
        if grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            bbr_status="BBR 可用, 但未启用 (当前: $con_algo_post)"
        else
            bbr_status="内核不支持 BBR"
        fi
    fi

    echo "  系统信息: $os_info $virt_info $arch_info $kernel_info"
    echo "  当前状态: $bbr_status"
    echo "  当前拥塞控制算法为: $con_algo_post"
    echo "  当前队列算法为: $q_algo_post"
    echo "-----------------------------------------------------"
}


# 菜单 1: 自动优化
fn_optimize_auto() {
    mkdir -p "$BACKUP_DIR"
    
    fn_log "INFO" "将使用固定备份目录: $BACKUP_DIR"
    
    if [ -f "${BACKUP_DIR}/fstab.bak" ]; then
        fn_log "WARN" "检测到旧备份...正在强制删除以创建新备份。"
        rm -rf "${BACKUP_DIR:?}/"*
    fi

    fn_log "SUCCESS" "开始自动优化... 日志将保存到: $LOG_FILE"
    
    # 步骤 0: 备份
    fn_backup_state

    # 步骤 1: 刷新 APT (V15.0)
    fn_log "INFO" "[1/10] 刷新 APT 软件源..."
    apt-get update > /dev/null 2>&1 || fn_log "WARN" "  -> 'apt-get update' 失败，将继续尝试安装..."

    # 步骤 2: SELinux
    fn_log "INFO" "[2/10] 动态检测 SELinux..."
    fn_detect_selinux

    # 步骤 3: 禁用 Swap
    fn_log "INFO" "[3/10] 禁用现有文件 Swap..."
    swapoff -a
    sed -i.bak '/swap/s/^/#/' /etc/fstab

    # 步骤 4: ZRAM (V15.0)
    fn_log "INFO" "[4/10] 安装与配置 ZRAM (稳定回退)..."
    if ! fn_setup_zram; then
        fn_log "ERROR" "ZRAM 安装失败。正在中止优化。"
        return 1
    fi

    # 步骤 5: Fail2ban
    fn_log "INFO" "[5/10] 安装并启用 Fail2ban..."
    apt-get install -y fail2ban > /dev/null
    if [ $? -ne 0 ]; then 
        fn_log "ERROR" "Fail2ban 安装失败。请检查 apt。"
        return 1
    fi
    systemctl enable --now fail2ban.service
    echo "fail2ban.service" >> "$TOUCHED_SERVICES_FILE"
    fn_log "SUCCESS" "  -> Fail2ban 已安装并启动。"

    # 步骤 6: 裁剪服务
    fn_trim_services

    # 步骤 7: Journald
    fn_log "INFO" "[7/10] 配置 journald (动态 RAM 限制)..."
    local journald_ram_limit="32M" # 默认 (RAM < 1.5G)
    if [ "$MEM_MB" -gt 4096 ]; then
        journald_ram_limit="128M"
    elif [ "$MEM_MB" -gt 1536 ]; then
        journald_ram_limit="64M"
    fi
    fn_log "INFO" "  -> RAM: ${MEM_MB}MB, Journald 限制: $journald_ram_limit"
    
    mkdir -p /etc/systemd/journald.conf.d/
    cat <<EOF > /etc/systemd/journald.conf.d/10-ram-only.conf
[Journal]
Storage=volatile
RuntimeMaxUse=$journald_ram_limit
EOF
    systemctl restart systemd-journald

    # 步骤 8: CPU
    fn_log "INFO" "[8/10] CPU 调速器持久化 (动态检测)..."
    if echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null; then
        fn_log "INFO" "  -> CPU governor 写入权限已确认。"
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
        fn_log "SUCCESS" "  -> CPU Performance 模式已持久化。"
    else
        fn_log "WARN" "  -> 无法写入 CPU governor (权限拒绝或 KVM/LXC 限制)。"
        fn_log "WARN" "  -> 跳过 CPU Performance 服务创建。这是正常现象。"
        echo "#skipped-cpugov" >> "$TOUCHED_SERVICES_FILE"
    fi

    # 步骤 9: Sysctl
    fn_log "INFO" "[9/10] 融合 Sysctl (TCP/UDP/Mem/IPv6/BBR)..."
    cat > /etc/sysctl.d/99-prime-fused.conf <<'EOF'
# === Prime Optimizer v15.0 Fused Tuning ===

# 1. Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# 2. Enable BBR + FQ
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 3. Memory & ZRAM
vm.vfs_cache_pressure = 50
vm.swappiness = 10

# 4. TCP/UDP Tuning
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

    # 步骤 10: DNS
    fn_log "INFO" "[10/10] 配置 DNS (systemd-resolved 动态检测)..."
    if systemctl is-active --quiet systemd-resolved.service && [ -f /etc/systemd/resolved.conf ]; then
        fn_log "INFO" "  -> 检测到 systemd-resolved。正在配置 8.8.8.8 & 1.1.1.1..."
        # 备份已在 fn_backup_state 中完成
        sed -i 's/#DNS=.*/DNS=8.8.8.8 1.1.1.1/g' /etc/systemd/resolved.conf
        sed -i 's/#FallbackDNS=.*/FallbackDNS=/g' /etc/systemd/resolved.conf
        
        if ! grep -q "^DNS=" /etc/systemd/resolved.conf; then
            sed -i '/\[Resolve\]/a DNS=8.8.8.8 1.1.1.1' /etc/systemd/resolved.conf
        fi
        
        systemctl restart systemd-resolved.service
        fn_log "SUCCESS" "  -> systemd-resolved DNS 已更新。"
    else
        fn_log "WARN" "  -> 未检测到 systemd-resolved.service 或 resolved.conf。"
        fn_log "WARN" "  -> 跳过 DNS 自动配置以确保稳定。"
    fi

    fn_log "SUCCESS" "自动优化完成！"
    fn_log "IMPORTANT" "备份数据保存在: $BACKUP_DIR"
    fn_log "IMPORTANT" "建议立即重启 (reboot) 以应用所有更改。"
    
    echo ""
    fn_show_status_report
}

# 菜单 2: 撤销优化 (智能检测)
fn_restore_state() {
    fn_log "WARN" "开始撤销优化..."
    
    local USER_BACKUP_DIR="/root/system_optimize_backup"

    if [ ! -d "$USER_BACKUP_DIR" ] || [ ! -f "${USER_BACKUP_DIR}/fstab.bak" ]; then
        fn_log "ERROR" "未找到备份目录: $USER_BACKUP_DIR"
        fn_log "ERROR" "无法撤销。请先运行 [1] 自动优化。"
        return 1
    fi
        
    fn_log "INFO" "检测到唯一的备份: $USER_BACKUP_DIR"
    echo "-----------------------------------------------------"
    echo "是否确认使用此备份进行恢复? (y/n)"
    read -r confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        fn_log "INFO" "操作已取消。"
        return 0
    fi

    # --- 开始恢复流程 ---
    
    LOG_FILE="${USER_BACKUP_DIR}/restore.log"
    fn_log "INFO" "正在从 $USER_BACKUP_DIR 恢复... 日志: $LOG_FILE"

    fn_log "INFO" "[1/9] 禁用 ZRAM..."
    fn_restore_zram

    fn_log "INFO" "[2/9] 恢复 /etc/fstab..."
    cp "${USER_BACKUP_DIR}/fstab.bak" /etc/fstab
    fn_log "INFO" "尝试重新激活旧的 Swap..."
    swapon -a

    fn_log "INFO" "[3/9] 恢复 journald 配置..."
    rm -rf /etc/systemd/journald.conf.d/
    [ -d "${USER_BACKUP_DIR}/journald.conf.d.bak" ] && cp -r "${USER_BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/
    systemctl restart systemd-journald

    # BBR 恢复提示
    fn_log "INFO" "[4/9] 恢复 Sysctl 配置 (含IPv6/BBR)..."
    local algo_bak=$(cat "${USER_BACKUP_DIR}/sysctl_con_algo.bak" 2>/dev/null || echo "cubic")
    local algo_now=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local restore_sysctl=true

    if [ "$algo_now" = "bbr" ] && [ "$algo_bak" != "bbr" ]; then
        fn_log "WARN" "检测到 BBR 已启用 (原始算法: $algo_bak)。"
        echo "-----------------------------------------------------"
        echo "是否要禁用 BBR 并恢复为 $algo_bak? (y/n)"
        read -r restore_choice
        if [ "$restore_choice" != "y" ] && [ "$restore_choice" != "Y" ]; then
            restore_sysctl=false
            fn_log "INFO" "跳过 Sysctl 恢复，BBR 将保持启用。"
        fi
    fi

    if [ "$restore_sysctl" = true ]; then
        fn_log "INFO" "  -> 正在恢复原始 Sysctl (BBR 将被禁用)..."
        rm /etc/sysctl.d/99-prime-fused.conf 2>/dev/null
        rm -rf /etc/sysctl.d/
        [ -d "${USER_BACKUP_DIR}/sysctl.d.bak" ] && cp -r "${USER_BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/
        [ -f "${USER_BACKUP_DIR}/sysctl.conf.bak" ] && cp "${USER_BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf
        sysctl --system > /dev/null
    fi

    fn_log "INFO" "[5/9] 恢复 DNS (systemd-resolved)..."
    if [ -f "${USER_BACKUP_DIR}/resolved.conf.bak" ]; then
        fn_log "INFO" "  -> 正在恢复 systemd-resolved 原始配置..."
        cp "${USER_BACKUP_DIR}/resolved.conf.bak" /etc/systemd/resolved.conf
        systemctl restart systemd-resolved.service
    fi

    fn_log "INFO" "[6/9] 恢复 CPU 默认模式..."
    systemctl disable --now cpugov-performance.service 2>/dev/null
    rm /etc/systemd/system/cpugov-performance.service 2>/dev/null
    fn_log "INFO" "  -> CPU governor 将在重启后恢复为系统默认值。"
    
    fn_log "INFO" "[7/9] 恢复 SELinux..."
    if [ -f "${USER_BACKUP_DIR}/selinux.config.bak" ]; then
        fn_log "INFO" "  -> 正在恢复 SELinux 原始配置..."
        cp "${USER_BACKUP_DIR}/selinux.config.bak" /etc/selinux/config
    fi

    fn_log "INFO" "[8/9] 禁用 Fail2ban..."
    systemctl disable --now fail2ban.service 2>/dev/null
    fn_log "INFO" "  -> Fail2ban 已禁用 (未卸载)。"

    fn_log "INFO" "[9/9] 恢复被禁用的服务 (根据备份日志)..."
    local touched_services_file="${USER_BACKUP_DIR}/touched_services.txt"
    
    if [ -f "$touched_services_file" ]; then
        grep -vE '^(#|$|selinux|skipped-cpugov|fail2ban.service)' "$touched_services_file" | while read -r service; do
            if [ -n "$service" ]; then
                fn_log "INFO" "  -> 正在重新启用: $service"
                systemctl enable "$service" >/dev/null 2>&1
            fi
        done
    else
        fn_log "WARN" "未找到 'touched_services.txt'. 跳过服务恢复。"
    fi
    
    systemctl daemon-reload

    fn_log "SUCCESS" "撤销优化完成！"
    fn_log "IMPORTANT" "建议立即重启 (reboot) 以使所有原始服务生效。"
}

# --- [3. 主菜单] ---

fn_show_menu() {
    clear
    mkdir -p "$BACKUP_DIR"
    
    echo "============================================================"
    echo " Prime Optimizer v$VERSION (ZRAM 稳定回退)"
    echo " 支持: Debian 10-12, Ubuntu 20.04-24.04"
    echo "============================================================"
    echo "  1) 自动优化 (推荐)"
    echo "  2) 撤销优化"
    echo "  0) 退出"
    echo "============================================================"
    
    echo ""
    fn_show_status_report
    echo ""
    
    echo "请选择:"
    read -r choice

    case $choice in
        1)
            fn_optimize_auto
            ;;
        2)
            fn_restore_state
            ;;
        [0])
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
