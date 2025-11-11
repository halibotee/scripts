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

fn_setup_zram_simple() {
MEM_MB=$(awk "/MemTotal/ {print int(\$2/1024)}" /proc/meminfo)
mem_mb="$MEM_MB"
[ -z "${mem_mb:-}" ] && mem_mb=512
zram_mb=$((mem_mb))
[ "$zram_mb" -lt 512 ] && zram_mb=512
[ "$zram_mb" -gt "$mem_mb" ] && zram_mb="$mem_mb"
fn_log "信息" "物理内存: ${MEM_MB} MB"
fn_log "信息" "设置 ZRAM 大小: ${zram_mb} MB"
swapoff -a || true
[ -e /sys/block/zram0 ] && echo 1 > /sys/block/zram0/reset
modprobe zram
echo $((zram_mb*1024*1024)) > /sys/block/zram0/disksize
mkswap /dev/zram0
swapon /dev/zram0 -p 100
swapon -s | tee -a "$LOG_FILE"
lsblk | grep zram | tee -a "$LOG_FILE"
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
[ "$changes_made" -eq 1 ] && systemctl daemon-reload
}

fn_restore_all() {
fn_log "警告" "开始执行撤销优化... 将从 $BACKUP_DIR 恢复备份。"
rm -f /etc/sysctl.d/99-vps-lowmem.conf
[ -f "${BACKUP_DIR}/sysctl.conf.bak" ] && cp -an "${BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf 2>/dev/null || true
[ -d "${BACKUP_DIR}/sysctl.d.bak" ] && cp -ar "${BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/ 2>/dev/null || true
cat > /etc/sysctl.d/98-bbr-retention.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl --system >/dev/null 2>&1 || true
[ -d "${BACKUP_DIR}/journald.conf.d.bak" ] && rm -rf /etc/systemd/journald.conf.d/ && cp -ar "${BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/ 2>/dev/null || true
systemctl restart systemd-journald >/dev/null 2>&1 || true
[ -f "${BACKUP_DIR}/apt.sources.list.bak" ] && cp -an "${BACKUP_DIR}/apt.sources.list.bak" /etc/apt/sources.list 2>/dev/null || true
if [ -f "$TOUCHED_SERVICES_FILE" ]; then
while read -r svc; do
[ -z "$svc" ] && continue
[[ "$svc" == *.service ]] || [[ "$svc" == *.timer ]] || [[ "$svc" == *.socket ]] && systemctl unmask "$svc" >/dev/null 2>&1 || true
done < <(grep -v '^#' "$TOUCHED_SERVICES_FILE")
fi
[ -f "${BACKUP_DIR}/enabled_services.before.txt" ] && while read -r s; do [ -z "$s" ] && continue; systemctl enable "$s" >/dev/null 2>&1 || true; done < "${BACKUP_DIR}/enabled_services.before.txt"
[ -f "${BACKUP_DIR}/fstab.bak" ] && cp -an "${BACKUP_DIR}/fstab.bak" /etc/fstab 2>/dev/null || true
swapoff -a >/dev/null 2>&1 || true
modprobe -r zram >/dev/null 2>&1 || true
fn_log "成功" "撤销优化完成。"
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
        local details=""

        if [ "$actual" == "$expected" ] || \
           { [ "$expected" == "disabled" ] && { [ "$actual" == "masked" ] || [ "$actual" == "static" ]; }; }; then
            status_msg="[ 已优化 ]"
        elif [ "$expected" == "disabled" ] && { [ "$actual" == "not-found" ] || [ -z "$actual" ]; }; then
            status_msg="[ 已优化 ]"
            details="(进程不存在)"
        else
            status_msg="[ 未优化 ]"
            if [ "$actual" == "not-found" ] || [ -z "$actual" ]; then
                details="(进程不存在)"
            else
                details="(状态: $actual)"
            fi
        fi
        
        printf "  %-35s %s %s\n" "$name" "$status_msg" "$details"
    }

    echo "1. 网络优化 (Sysctl):"
    fn_print_check "TCP 拥塞控制 (BBR)" "bbr" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'n/a')"
    fn_print_check "网络队列算法 (FQ)" "fq" "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'n/a')"
    fn_print_check "Swappiness" "10" "$(sysctl -n vm.swappiness 2>/dev/null || echo 'n/a')"
    fn_print_check "VFS 缓存压力" "100" "$(sysctl -n vm.vfs_cache_pressure 2>/dev/null || echo 'n/a')"
    fn_print_check "IPv6 (all.disable_ipv6)" "1" "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 'n/a')"

    echo "2. 日志 (Journald):"
    local journal_storage
    journal_storage=$(systemd-analyze cat-config systemd/journald.conf | grep -i '^Storage=' | tail -n 1 | cut -d= -f2 2>/dev/null || echo "disk")
    fn_print_check "Journald 存储模式" "volatile" "${journal_storage:-disk}"
    
    echo "3. 交换空间 (Swap/ZRAM):"
    if swapon -s | grep -q 'zram'; then
        echo "  ZRAM 状态: [ 已激活 ]"
    elif swapon -s | grep -q "$(basename /swapfile_zram)"; then
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
        fn_print_check "服务: $svc" "disabled" "$svc_status"
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
fn_wait_for_apt_lock
fn_fix_apt_sources_if_needed
fn_setup_journald_volatile
fn_setup_sysctl_lowmem
fn_trim_services_auto
fn_setup_zram_simple
fn_prioritize_network_services_auto
fn_log "成功" "系统优化完成。请重启系统以完全生效。"
fn_show_status_report
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
    echo "===============================================
"
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
