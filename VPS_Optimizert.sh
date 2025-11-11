#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.1"
BACKUP_DIR="/etc/sysopt_lowmem_backup"
LOG_FILE="/var/log/sysopt_lowmem.log"
TOUCHED_SERVICES_FILE="${BACKUP_DIR}/touched_services.txt"
export DEBIAN_FRONTEND=noninteractive

# Services list tuned for 1CPU/1GB scenario; rsyslog will be disabled explicitly
FN_TRIM_SERVICES_LIST=(
    "apt-daily.timer"
    "apt-daily-upgrade.timer"
    "apt-daily.service"
    "apt-daily-upgrade.service"
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
    "e2scrub_reap.service"
    "cloud-init.service"
    "cloud-init-local.service"
    "cloud-config.service"
    "cloud-final.service"
    "packagekit.service"
    "thermald.service"
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
        fn_log "ERROR" "This script must be run as root."
        exit 1
    fi
}

fn_check_apt_lock() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        fn_log "WARN" "APT lock detected (another apt/dpkg might be running)."
        return 1
    fi
    return 0
}

fn_detect_os() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_PRETTY="$PRETTY_NAME"
        OS_ID="$ID"
        OS_VER="$VERSION_ID"
        fn_log "INFO" "Detected OS: $OS_PRETTY"
    else
        fn_log "ERROR" "Cannot detect OS (/etc/os-release missing)."
        exit 1
    fi

    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}' || echo 0)
    MEM_MB=$(( MEM_KB / 1024 ))
    fn_log "INFO" "Physical memory: ${MEM_MB} MB"

    if ! command -v systemctl >/dev/null 2>&1; then
        fn_log "ERROR" "Systemd not found. This script requires systemd."
        exit 1
    fi
}

# Backup state
fn_backup_state() {
    fn_log "INFO" "Creating backup in $BACKUP_DIR ..."
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
    echo "# touched services by sysOpt_lowmem" > "$TOUCHED_SERVICES_FILE"
    fn_log "INFO" "Backup completed."
}

# Conservative apt sources fix: only replace when apt-get update fails
fn_fix_apt_sources_if_needed() {
    fn_log "INFO" "Checking APT sources health..."
    if fn_check_apt_lock; then
        if apt-get update -qq >/dev/null 2>&1; then
            fn_log "SUCCESS" "apt-get update succeeded; sources OK."
            return 0
        else
            fn_log "WARN" "apt-get update failed. Will attempt conservative replacement of /etc/apt/sources.list"
            # detect codename
            if command -v lsb_release >/dev/null 2>&1; then
                codename=$(lsb_release -cs)
            else
                codename=$(grep VERSION_CODENAME /etc/os-release 2>/dev/null | cut -d= -f2 || true)
            fi
            if [ -z "${codename:-}" ]; then
                fn_log "ERROR" "Cannot determine distro codename; skipping auto source replacement."
                return 1
            fi
            cp -an /etc/apt/sources.list "${BACKUP_DIR}/apt.sources.list.bak" 2>/dev/null || true
            if [ "$OS_ID" = "debian" ]; then
                cat > /etc/apt/sources.list <<EOF
# Configured by sysOpt_lowmem v$SCRIPT_VERSION
deb http://deb.debian.org/debian/ $codename main contrib non-free
deb http://deb.debian.org/debian/ $codename-updates main contrib non-free
deb http://deb.debian.org/debian/ $codename-security main contrib non-free
EOF
            elif [ "$OS_ID" = "ubuntu" ]; then
                cat > /etc/apt/sources.list <<EOF
# Configured by sysOpt_lowmem v$SCRIPT_VERSION
deb http://archive.ubuntu.com/ubuntu/ $codename main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $codename-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $codename-security main restricted universe multiverse
EOF
            else
                fn_log "ERROR" "OS not supported for automatic sources replacement."
                return 1
            fi
            if apt-get update -qq >/dev/null 2>&1; then
                fn_log "SUCCESS" "APT sources replaced and refreshed successfully."
                return 0
            else
                fn_log "ERROR" "APT update still failed after replacing sources."
                return 1
            fi
        fi
    else
        fn_log "WARN" "APT appears locked; skipping sources health check."
        return 1
    fi
}

# Journald memory mode
fn_setup_journald_volatile() {
    fn_log "INFO" "Configuring journald to volatile (memory) mode (RuntimeMaxUse=16M)..."
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/10-volatile.conf <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=16M
MaxRetentionSec=1month
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    fn_log "SUCCESS" "journald configured to volatile mode."
}

# Sysctl tuning (adaptive)
fn_setup_sysctl_lowmem() {
    fn_log "INFO" "Applying sysctl low-memory network tuning (with BBR+FQ)..."
    cat > /etc/sysctl.d/99-vps-lowmem.conf <<'EOF'
# sysOpt_lowmem adaptive tuning
vm.swappiness = 10
vm.vfs_cache_pressure = 100
# moderate network buffers for UDP-heavy apps (1 CPU / <2GB RAM)
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.netdev_max_backlog = 2500
net.core.somaxconn = 1024
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_fin_timeout = 15
# disable IPv6 if not used
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Enable BBR + FQ (retained on restore)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1 || fn_log "WARN" "sysctl apply had warnings."
    fn_log "SUCCESS" "sysctl adaptive tuning (with BBR) applied."
}

# Disable/stop services automatically
fn_trim_services_auto() {
    fn_log "INFO" "Service trimming: attempting to disable non-essential services."
    for svc in "${FN_TRIM_SERVICES_LIST[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}"; then
            fn_log "INFO" "Disabling $svc"
            systemctl disable --now "$svc" >/dev/null 2>&1 || true
            echo "$svc" >> "$TOUCHED_SERVICES_FILE"
        else
            fn_log "INFO" "Service $svc not present; skipping."
        fi
    done

    # rsyslog: explicitly disable (user requested)
    if systemctl list-unit-files | grep -q "^rsyslog.service"; then
        fn_log "INFO" "Disabling rsyslog.service"
        systemctl disable --now rsyslog.service >/dev/null 2>&1 || true
        echo "rsyslog.service" >> "$TOUCHED_SERVICES_FILE"
    else
        fn_log "INFO" "rsyslog.service not installed."
    fi
}

# ZRAM setup with adaptive calculation
fn_setup_zram_adaptive() {
    fn_log "INFO" "Attempting to enable ZRAM with adaptive sizing (prefer lz4)."

    # compute size: 50% memory, min 512MB, cap at physical memory
    mem_mb="$MEM_MB"
    if [ -z "${mem_mb:-}" ] || [ "$mem_mb" -lt 1 ]; then
        mem_mb=512
    fi
    zram_mb=$(( mem_mb / 2 ))
    if [ "$zram_mb" -lt 512 ]; then
        zram_mb=512
    fi
    if [ "$zram_mb" -gt "$mem_mb" ]; then
        zram_mb="$mem_mb"
    fi
    fn_log "INFO" "Calculated ZRAM size: ${zram_mb}MB (physical mem: ${mem_mb}MB)"

    # Try path 1: load zram kernel module and use custom systemd service
    if modprobe zram >/dev/null 2>&1; then
        fn_log "INFO" "zram module available. Creating custom vps-zram.service..."
        cat > /etc/systemd/system/vps-zram.service <<EOF
[Unit]
Description=Adaptive ZRAM service for sysOpt_lowmem
After=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/modprobe zram
ExecStart=/bin/sh -c 'zramctl --reset /dev/zram0 2>/dev/null || true; zramctl /dev/zram0 --size ${zram_mb}M --algorithm lz4; mkswap /dev/zram0; swapon /dev/zram0'
ExecStop=/bin/sh -c 'swapoff /dev/zram0 2>/dev/null || true; zramctl --reset /dev/zram0 2>/dev/null || true'
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now vps-zram.service >/dev/null 2>&1 || true
        sleep 1
        if swapon -s | grep -q 'zram'; then
            fn_log "SUCCESS" "ZRAM enabled via kernel module (vps-zram.service)."
            echo "vps-zram.service" >> "$TOUCHED_SERVICES_FILE"
            return 0
        else
            fn_log "WARN" "vps-zram.service did not activate zram. Continuing fallback attempts."
        fi
    else
        fn_log "WARN" "zram kernel module not available."
    fi

    # Try path 2: install zram-tools (if apt available)
    if fn_check_apt_lock; then
        fn_log "INFO" "Attempting to install zram-tools as fallback."
        apt-get update -qq >/dev/null 2>&1 || true
        if apt-get install -y zram-tools >/dev/null 2>&1; then
            fn_log "INFO" "zram-tools installed, attempting to enable zramswap.service"
            systemctl enable --now zramswap.service >/dev/null 2>&1 || true
            sleep 1
            if swapon -s | grep -q 'zram'; then
                fn_log "SUCCESS" "ZRAM enabled via zram-tools (zramswap.service)."
                echo "zramswap.service" >> "$TOUCHED_SERVICES_FILE"
                return 0
            else
                fn_log "WARN" "zramswap.service did not activate zram."
            fi
        else
            fn_log "WARN" "zram-tools install failed or not available."
        fi
    else
        fn_log "WARN" "APT locked or unavailable; skipping zram-tools attempt."
    fi

    # Try path 3: zram-generator
    if fn_check_apt_lock; then
        fn_log "INFO" "Attempting to install zram-generator as another fallback."
        apt-get update -qq >/dev/null 2>&1 || true
        if apt-get install -y zram-generator-defaults zram-generator >/dev/null 2>&1 || apt-get install -y zram-generator >/dev/null 2>&1; then
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
                fn_log "SUCCESS" "ZRAM enabled via zram-generator."
                echo "systemd-zram-setup@zram0.service" >> "$TOUCHED_SERVICES_FILE"
                return 0
            else
                fn_log "WARN" "zram-generator did not activate zram."
            fi
        else
            fn_log "WARN" "zram-generator install failed or not available."
        fi
    else
        fn_log "WARN" "APT locked or unavailable; skipping zram-generator attempt."
    fi

    # Final fallback: create on-disk swapfile (limited size)
    fn_log "WARN" "All ZRAM methods failed. Creating a small swapfile as fallback."
    swapfile="/swapfile_sysopt_lowmem"
    swapsize_mb=$(( zram_mb > 512 ? 512 : zram_mb ))
    if [ -f "$swapfile" ]; then
        fn_log "INFO" "Swapfile already exists; attempting to enable it."
        swapon "$swapfile" >/dev/null 2>&1 || true
    else
        fallocate -l "${swapsize_mb}M" "$swapfile" >/dev/null 2>&1 || dd if=/dev/zero of="$swapfile" bs=1M count="$swapsize_mb" >/dev/null 2>&1
        chmod 600 "$swapfile"
        mkswap "$swapfile" >/dev/null 2>&1 || true
        swapon "$swapfile" >/dev/null 2>&1 || true
        echo "$swapfile" >> "${BACKUP_DIR}/created_swapfiles.txt"
    fi
    if swapon -s | grep -q "$(basename "$swapfile")"; then
        fn_log "SUCCESS" "Swapfile enabled as fallback (${swapsize_mb}MB)."
        return 0
    else
        fn_log "ERROR" "Failed to enable swapfile fallback."
        return 1
    fi
}

# Revert ZRAM / swap / generator changes
fn_restore_zram_and_swap() {
    fn_log "INFO" "Restoring ZRAM / swap state: disabling services and removing created files."
    systemctl disable --now vps-zram.service >/dev/null 2>&1 || true
    systemctl disable --now zramswap.service >/dev/null 2>&1 || true
    systemctl disable --now systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
    # remove created service and configs
    rm -f /etc/systemd/system/vps-zram.service
    rm -f /etc/systemd/zram-generator.conf
    systemctl daemon-reload >/dev/null 2>&1 || true
    # remove created swapfiles
    if [ -f "${BACKUP_DIR}/created_swapfiles.txt" ]; then
        while read -r sf; do
            [ -z "$sf" ] && continue
            if swapon -s | grep -q "$(basename "$sf")"; then
                swapoff "$sf" >/dev/null 2>&1 || true
            fi
            rm -f "$sf" || true
            fn_log "INFO" "Removed swapfile $sf"
        done < "${BACKUP_DIR}/created_swapfiles.txt"
    fi
    # attempt to rmmod zram (may fail if in use)
    swapoff -a >/dev/null 2>&1 || true
    modprobe -r zram >/dev/null 2>&1 || true
    fn_log "SUCCESS" "ZRAM / swap restore completed."
}

# Apply CPU/IO prioritization for network daemons (automatic, persistent)
fn_prioritize_network_services_auto() {
    fn_log "INFO" "Setting persistent high priority for network daemons."
    local changes_made=0
    for svc in xray hysteria2 hysteria udp2raw kcptun; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            fn_log "INFO" "Setting Nice=-5 and CPUQuota=70% for $svc."
            
            local svc_conf_dir="/etc/systemd/system/${svc}.service.d"
            mkdir -p "$svc_conf_dir"
            cat > "${svc_conf_dir}/90-sysopt-lowmem.conf" <<EOF
[Service]
# Applied by sysOpt_lowmem
Nice=-5
CPUQuota=70%
EOF
            echo "${svc}.service" >> "$TOUCHED_SERVICES_FILE"
            changes_made=1
        fi
    done

    if [ "$changes_made" -eq 1 ]; then
        fn_log "INFO" "Reloading systemd daemon to apply service priorities."
        systemctl daemon-reload
    fi
}

# Restore backups
fn_restore_all() {
    fn_log "WARN" "Starting restore (撤销优化). This will restore backups from $BACKUP_DIR"
    
    # Restore sysctl (but retain BBR)
    fn_log "INFO" "Restoring sysctl (retaining BBR+FQ...)"
    
    # 1. Remove our optimization file
    rm -f /etc/sysctl.d/99-vps-lowmem.conf

    # 2. Restore main config file backup
    if [ -f "${BACKUP_DIR}/sysctl.conf.bak" ]; then
        cp -an "${BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf 2>/dev/null || true
    fi
    
    # 3. Restore other sysctl.d backups (if they existed)
    if [ -d "${BACKUP_DIR}/sysctl.d.bak" ]; then
        cp -ar "${BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/ 2>/dev/null || true
    fi

    # 4. Re-create a file *only* for BBR
    cat > /etc/sysctl.d/98-bbr-retention.conf <<'EOF'
# Retained by sysOpt_lowmem restore
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    # 5. Apply
    sysctl --system >/dev/null 2>&1 || true

    # Restore journald
    if [ -d "${BACKUP_DIR}/journald.conf.d.bak" ]; then
        rm -rf /etc/systemd/journald.conf.d/
        cp -ar "${BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/ 2>/dev/null || true
        systemctl restart systemd-journald >/dev/null 2>&1 || true
    else
        rm -rf /etc/systemd/journald.conf.d/ || true
        systemctl restart systemd-journald >/dev/null 2>&1 || true
    fi

    # Restore apt sources
    if [ -f "${BACKUP_DIR}/apt.sources.list.bak" ]; then
        cp -an "${BACKUP_DIR}/apt.sources.list.bak" /etc/apt/sources.list 2>/dev/null || true
    fi

    # Restore services: re-enable those in enabled_services.before.txt
    if [ -f "${BACKUP_DIR}/enabled_services.before.txt" ]; then
        fn_log "INFO" "Attempting to restore service enablement state from backup list."
        while read -r s; do
            [ -z "$s" ] && continue
            systemctl enable "$s" >/dev/null 2>&1 || true
        done < "${BACKUP_DIR}/enabled_services.before.txt"
    fi

    # Re-enable rsyslog if it existed previously
    if grep -q "^rsyslog.service$" "${BACKUP_DIR}/enabled_services.before.txt" 2>/dev/null; then
        systemctl enable --now rsyslog.service >/dev/null 2>&1 || true
    fi

    # Restore fstab (swap entries)
    if [ -f "${BACKUP_DIR}/fstab.bak" ]; then
        cp -an "${BACKUP_DIR}/fstab.bak" /etc/fstab 2>/dev/null || true
        swapon -a >/dev/null 2>&1 || true
    fi

    # Restore zram/swap
    fn_restore_zram_and_swap

    # Restore service priorities (remove drop-in configs)
    fn_log "INFO" "Restoring service priorities (removing drop-in files)..."
    local configs_removed=0
    if [ -f "$TOUCHED_SERVICES_FILE" ]; then
        while read -r svc; do
            [ -z "$svc" ] && continue
            # 检查是否是服务（以 .service 结尾）
            if [[ "$svc" == *.service ]]; then
                local svc_conf_dir="/etc/systemd/system/${svc}.d"
                if [ -d "$svc_conf_dir" ]; then
                    rm -rf "$svc_conf_dir"
                    fn_log "INFO" "Removed $svc_conf_dir"
                    configs_removed=1
                fi
            fi
        done < <(grep -v '^#' "$TOUCHED_SERVICES_FILE") # 过滤掉注释行
    fi
    
    if [ "$configs_removed" -eq 1 ]; then
        systemctl daemon-reload
    fi

    fn_log "SUCCESS" "Restore (撤销优化) attempts completed. Review logs at $LOG_FILE"
}

# Status report
fn_show_status_report() {
    echo "================ System Status ================"
    [ -f /etc/os-release ] && source /etc/os-release
    printf "OS: %s\n" "${PRETTY_NAME:-unknown}"
    printf "Memory: %s MB\n" "$MEM_MB"
    printf "Kernel: %s\n" "$(uname -r)"
    echo ""
    free -h
    echo ""
    swapon -s || true
    echo "================================================"
}

# Main optimize flow (AUTOMATIC)
fn_optimize_auto() {
    fn_backup_state

    fn_log "INFO" "Step 1/6: Checking and fixing APT sources..."
    fn_fix_apt_sources_if_needed || fn_log "WARN" "APT fix step had issues; continuing."

    fn_log "INFO" "Step 2/6: Configuring journald to volatile mode..."
    fn_setup_journald_volatile

    fn_log "INFO" "Step 3/6: Applying sysctl tuning (BBR+FQ included)..."
    fn_setup_sysctl_lowmem

    fn_log "INFO" "Step 4/6: Trimming non-essential services..."
    fn_trim_services_auto

    fn_log "INFO" "Step 5/6: Enabling adaptive ZRAM..."
    if fn_setup_zram_adaptive; then
        fn_log "SUCCESS" "ZRAM / swap setup succeeded."
    else
        fn_log "ERROR" "ZRAM / swap setup failed."
    fi

    fn_log "INFO" "Step 6/6: Prioritizing network services..."
    fn_prioritize_network_services_auto

    fn_log "SUCCESS" "Optimization completed. Please monitor memory/cpu."
    fn_show_status_report
    fn_log "IMPORTANT" "Check $LOG_FILE for detailed logs. Recommended: reboot to apply all changes."
}

fn_show_menu() {
    clear
    echo "==============================================="
    echo " sysOpt_lowmem.sh - VPS low-memory optimizer"
    echo " Version: $SCRIPT_VERSION"
    echo " Backup dir: $BACKUP_DIR"
    echo " Log: $LOG_FILE"
    echo "==============================================="
    echo " 1) 执行系统优化 (全自动)"
    echo " 2) 撤销优化 (恢复备份, 保留BBR)"
    echo " 3) 显示系统状态"
    echo " 0) 退出"
    echo "==============================================="
    read -rp "请选择: " CH
    case "$CH" in
        1) fn_optimize_auto ;; # <-- Changed function name
        2) fn_restore_all ;;
        3) fn_show_status_report; read -rp "按回车返回菜单..." dummy ;;
        0) fn_log "INFO" "Exit."; exit 0 ;;
        *) fn_log "ERROR" "Invalid choice."; sleep 1; fn_show_menu ;;
    esac
    read -rp "按回车返回主菜单..." dummy
    fn_show_menu
}

# Entry point
fn_check_root
fn_detect_os

# Run menu
fn_show_menu
