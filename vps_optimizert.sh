#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# [新增] 默认为交互模式
export FORCE_YES=0
# [新增] 解析 $1 (非交互式标志)
if [ "${1:-}" = "-y" ] || [ "${1:-}" = "--yes" ]; then
    FORCE_YES=1
fi

SCRIPT_VERSION="1.2.1"
BACKUP_DIR="/etc/vps_optimizert_backup"
LOG_FILE="/var/log/vps_optimizert.log"
ACTION_LOG="${BACKUP_DIR}/actions.log" # [新增] 状态日志
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

FN_NETWORK_SERVICES_LIST=(
"xray"
"hysteria2"
"hysteria"
"udp2raw"
"kcptun"
)

mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"
touch "$ACTION_LOG"

fn_log() {
    # [新增] 首次调用时记录 -y 状态
    if [ -z "${LOG_Y_RECORDED:-}" ]; then
        if [ $FORCE_YES -eq 1 ]; then
            # 直接写入，避免 fn_log 递归
            local ts=$(date '+%F %T')
            printf '%s [%s] %s\n' "$ts" "警告" "非交互模式 (-y) 已激活。将自动同意所有提示。" >> "$LOG_FILE"
        fi
        export LOG_Y_RECORDED=1 # 确保只记录一次
    fi
    
local level="$1"; shift
local msg="$*"
local ts
ts=$(date '+%F %T')
printf '%s [%s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE"
}

# [新增] 记录一个可逆向的操作到状态日志
# $1: 操作类型 (例如 MASK_SERVICE, CREATE_FILE)
# $2: 操作的值 (例如 "xray.service", "/etc/sysctl.d/99-vps_optimizert.conf")
fn_log_action() {
    local action="$1"
    local value="$2"
    # 格式: ACTION:VALUE
    echo "${action}:${value}" >> "$ACTION_LOG"
    fn_log "调试" "记录操作: ${action}:${value}"
}

fn_check_root() {
if [ "$EUID" -ne 0 ]; then
echo "错误: 本脚本必须以 root 权限运行。"
fn_log "错误" "本脚本必须以 root 权限运行。"
exit 1
fi
}

# [修改] 重命名并重构 fn_check_apt_lock
fn_check_pkg_lock() {
    if [ "$OS_ID" = "debian" ] || [ "$OS_ID" = "ubuntu" ]; then
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            fn_log "警告" "检测到 APT/DPKG 锁。"
            return 1
        fi
    elif [ "$OS_ID" = "fedora" ] || [ "$OS_ID" = "rhel" ] || [ "$OS_ID" = "centos" ] || [ "$OS_ID" = "almalinux" ] || [ "$OS_ID" = "rocky" ]; then
        if [ -f /var/cache/dnf/metadata_lock.pid ] && pgrep -F /var/cache/dnf/metadata_lock.pid >/dev/null 2>&1; then
            fn_log "警告" "检测到 DNF 锁。"
            return 1
        fi
    fi
    return 0
}

# [修改] 重命名并重构 fn_wait_for_apt_lock
fn_wait_for_pkg_lock() {
    local max_wait=120
    local count=0
    fn_log "信息" "检查包管理器锁..."
    # [修改] 使用新的 fn_check_pkg_lock
    while ! fn_check_pkg_lock; do
        if [ "$count" -ge "$max_wait" ]; then
            fn_log "错误" "等待包管理器锁超时 (120 秒)。操作可能失败。"
            return 1
        fi
        fn_log "警告" "检测到包管理器锁，等待 5 秒... ($count/$max_wait)"
        sleep 5
        count=$((count + 5))
    done
    fn_log "信息" "包管理器锁已释放。"
    return 0
}

# [修改] 替换为包含包管理器抽象化的版本
fn_detect_os() {
    # [新增] 定义全局包管理器变量
    export PKG_INSTALL=""
    export PKG_REMOVE=""
    export PKG_CHECK=""
    export PKG_UPDATE=""

    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_PRETTY="${PRETTY_NAME:-unknown}"
        OS_ID="${ID:-unknown}"
        OS_VER="${VERSION_ID:-unknown}"
        echo "检测到操作系统: $OS_PRETTY"
        fn_log "信息" "检测到操作系统: $OS_PRETTY"
    else
        echo "错误: 无法检测到操作系统 (/etc/os-release 不存在)。"
        fn_log "错误" "无法检测到操作系统 (/etc/os-release 不存在)。"
        exit 1
    fi

    # [新增] 根据 OS_ID 设置包管理器
    case "$OS_ID" in
        debian|ubuntu)
            PKG_INSTALL="apt-get install -y"
            PKG_REMOVE="apt-get remove -y --purge"
            PKG_CHECK="dpkg -s"
            PKG_UPDATE="apt-get update -qq"
            ;;
        fedora|rhel|centos|almalinux|rocky)
            PKG_INSTALL="dnf install -y"
            PKG_REMOVE="dnf remove -y"
            PKG_CHECK="rpm -q"
            PKG_UPDATE="dnf check-update -q --quiet"
            ;;
        *)
            echo "错误: 不支持的操作系统 $OS_ID。"
            fn_log "错误" "不支持的操作系统 $OS_ID。"
            exit 1
            ;;
    esac

    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}' || echo 0)
    MEM_MB=$(( MEM_KB / 1024 ))
    echo "物理内存: ${MEM_MB} MB"
    fn_log "信息" "物理内存: ${MEM_MB} MB"
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "错误: 未找到 Systemd。本脚本需要 systemd。"
        fn_log "错误" "未找到 Systemd。本脚本需要 systemd。"
        exit 1
    fi
}

fn_backup_state() {
fn_log "信息" "正在创建备份于 $BACKUP_DIR ..."
mkdir -p "$BACKUP_DIR" || { fn_log "错误" "无法创建 $BACKUP_DIR"; return 1; }
cp -an /etc/fstab "${BACKUP_DIR}/fstab.bak" 2>/dev/null || true
cp -an /etc/systemd/resolved.conf "${BACKUP_DIR}/resolved.conf.bak" 2>/dev/null || true
cp -an /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak" 2>/dev/null || true
cp -ran /etc/sysctl.d "${BACKUP_DIR}/sysctl.d.bak" 2>/dev/null || true
cp -ran /etc/systemd/journald.conf.d "${BACKUP_DIR}/journald.conf.d.bak" 2>/dev/null || true
[ -f /etc/selinux/config ] && cp -an /etc/selinux/config "${BACKUP_DIR}/selinux.config.bak" 2>/dev/null || true
sysctl -n net.ipv4.tcp_congestion_control > "${BACKUP_DIR}/sysctl_con_algo.bak" 2>/dev/null || true
sysctl -n net.core.default_qdisc > "${BACKUP_DIR}/sysctl_q_algo.bak" 2>/dev/null || true
systemctl list-unit-files --type=service --state=enabled > "${BACKUP_DIR}/enabled_services.before.txt" 2>/dev/null || true

# [修改] 创建/清空操作日志
echo "# vps_optimizert action log ($(date))" > "$ACTION_LOG"

fn_log "信息" "备份完成。"
return 0
}

fn_fix_apt_sources_if_needed() {
# [修改] 使用新的锁函数
fn_wait_for_pkg_lock || { fn_log "错误" "包管理器锁等待失败"; return 1; }
fn_log "信息" "检查包管理器源健康状况..."

# [修改] 使用 $PKG_UPDATE
if $PKG_UPDATE >/dev/null 2>&1; then
fn_log "成功" "包管理器源正常。"
return 0
else
fn_log "警告" "包管理器 update 失败。将尝试保守替换 sources.list (仅限 Debian/Ubuntu)"

# [修改] 仅为 debian/ubuntu 修复源
if [ "$OS_ID" = "debian" ] || [ "$OS_ID" = "ubuntu" ]; then
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
    fi
else
    fn_log "错误" "此操作系统不支持自动替换源。"
    return 1
fi

# [修改] 使用 $PKG_UPDATE
if $PKG_UPDATE >/dev/null 2>&1; then
    fn_log "成功" "APT 源替换并刷新成功。"
    return 0
else
    fn_log "错误" "替换源后 $PKG_UPDATE 仍然失败。"
    return 1
fi
fi
}

fn_handle_selinux() {
    fn_log "信息" "检查 SELinux 状态..."
    
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status
        selinux_status=$(getenforce)

        if [ "$selinux_status" != "Disabled" ]; then
            fn_log "警告" "检测到 SELinux 状态为: $selinux_status"
            echo "-----------------------------------------------------"
            echo "警告: 检测到 SELinux 状态为: $selinux_status"
            echo "SELinux 会导致性能问题并可能与优化冲突。"
            
            # [修改] 检查 FORCE_YES 标志
            local selinux_choice="n"
            if [ $FORCE_YES -eq 1 ]; then
                selinux_choice="y"
                echo "非交互模式: 自动同意禁用 SELinux。"
                fn_log "信息" "非交互模式: 自动同意禁用 SELinux。"
            else
                read -rp "是否要将其永久禁用 (推荐)? (y/n): " selinux_choice || true
            fi
            
            if [ "$selinux_choice" = "y" ] || [ "$selinux_choice" = "Y" ]; then
                echo "正在禁用 SELinux..."
                fn_log "信息" "正在禁用 SELinux..."
                setenforce 0 2>/dev/null || fn_log "警告" "setenforce 0 失败 (可能无权限或已禁用)。"
                if [ -f /etc/selinux/config ]; then
                    sed -i.bak 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
                    fn_log_action "MODIFY_FILE" "/etc/selinux/config" # [新增] 记录操作
                    echo "SELinux 已永久禁用。需要重启生效。"
                    fn_log "成功" "SELinux 已永久禁用。需要重启生效。"
                else
                    echo "错误: 未找到 /etc/selinux/config，无法永久禁用。"
                    fn_log "错误" "未找到 /etc/selinux/config，无法永久禁用。"
                fi
            else
                echo "跳过禁用 SELinux。"
                fn_log "警告" "跳过禁用 SELinux。这可能导致后续步骤失败。"
            fi
        else
             fn_log "信息" "SELinux 状态: Disabled (良好)。"
             return 2
        fi
    else
        fn_log "信息" "未检测到 SELinux (正常)。"
        return 2
    fi
    return 0
}

fn_setup_fail2ban() {
    fn_log "信息" "配置 Fail2ban..."
    
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        fn_log "信息" "Fail2ban 已安装并激活，跳过。"
        return 2
    fi
    
    # [修改] 使用 $PKG_CHECK
    if $PKG_CHECK fail2ban >/dev/null 2>&1; then
        fn_log "信息" "Fail2ban 已安装 (但未运行)。"
    else
        fn_log "信息" "正在安装 Fail2ban..."
        fn_wait_for_pkg_lock || { fn_log "错误" "包管理器锁等待失败"; return 1; }
        # [修改] 使用 $PKG_INSTALL
        $PKG_INSTALL fail2ban >>"$LOG_FILE" 2>&1 || { 
            fn_log "警告" "Fail2ban 安装失败。"; 
            return 1; 
        }
        fn_log_action "INSTALL_PKG" "fail2ban" # [新增] 记录操作
        fn_log "信息" "Fail2ban 安装完成。"
    fi
    
    fn_log "信息" "配置 Fail2ban backend 为 systemd (以修复 sshd jail 冲突)..."
    
    mkdir -p /etc/fail2ban/jail.d
    local conf_file="/etc/fail2ban/jail.d/99-vps_optimizert-systemd.conf" # [新增]
    cat > "$conf_file" <<'EOF'
[DEFAULT]
backend = systemd

[sshd]
backend = systemd
EOF
    fn_log_action "CREATE_FILE" "$conf_file" # [新增] 记录操作
    fn_log "调试" "已创建 /etc/fail2ban/jail.d/99-vps_optimizert-systemd.conf"
    
    (systemctl enable --now fail2ban) >> "$LOG_FILE" 2>&1
    
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        fn_log "成功" "Fail2ban 已激活。"
        return 0
    else
        fn_log "错误" "Fail2ban 启动失败 (即使在应用 systemd backend 修复后)。"
        return 1
    fi
}

fn_setup_journald_volatile() {
local journal_storage
journal_storage=$(systemd-analyze cat-config systemd/journald.conf | grep -i '^Storage=' | tail -n 1 | cut -d= -f2 2>/dev/null || echo "disk")
if [ "$journal_storage" == "volatile" ]; then
    fn_log "信息" "journald 已是 volatile 模式，跳过。"
    return 2
fi

fn_log "信息" "配置 journald 为 volatile (内存) 模式 (RuntimeMaxUse=16M)..."
mkdir -p /etc/systemd/journald.conf.d
local conf_file="/etc/systemd/journald.conf.d/10-volatile.conf" # [新增]
cat > "$conf_file" <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=16M
MaxRetentionSec=1month
EOF
fn_log_action "CREATE_FILE" "$conf_file" # [新增] 记录操作
systemctl restart systemd-journald >/dev/null 2>&1 || true
fn_log "成功" "journald 已配置为 volatile 模式。"
return 0
}

fn_setup_sysctl_lowmem() {
local conf_file="/etc/sysctl.d/99-vps_optimizert.conf" # [修改]
if [ -f "$conf_file" ]; then
    fn_log "信息" "sysctl 配置文件 $conf_file 已存在，跳过写入。"
    skipped=true
else
    fn_log "信息" "应用 sysctl 低内存网络调优 (包含 BBR+FQ)..."
    cat > "$conf_file" <<'EOF'
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
    fn_log_action "CREATE_FILE" "$conf_file" # [新增] 记录操作
    fn_log "成功" "sysctl 配置文件 $conf_file 已创建。"
fi

sysctl --system >/dev/null 2>/dev/null || fn_log "警告" "sysctl 应用时出现警告。"
fn_log "信息" "sysctl --system 已执行。"

if [ "$skipped" == "true" ]; then
    return 2
fi
return 0
}

fn_trim_services_auto() {
fn_log "信息" "系统服务精简: 自动屏蔽非必要服务..."
local masked_count=0
local services_to_trim=("${FN_TRIM_SERVICES_LIST[@]}")

# [修复] 修正 systemctl list-unit-files 的误报输出
if systemctl list-unit-files "rsyslog.service" >/dev/null 2>&1; then
services_to_trim+=("rsyslog.service")
fi

for svc in "${services_to_trim[@]}"; do
if systemctl list-unit-files "$svc" >/dev/null 2>&1; then
    local svc_status
    svc_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
    
    if [[ "$svc_status" == *"masked"* ]]; then
        fn_log "调试" "服务 $svc 已被屏蔽，跳过。"
    elif [[ "$svc_status" == "not-found" ]]; then
        fn_log "调试" "服务 $svc 不存在，跳过。"
    else
        fn_log "信息" "  正在屏蔽 (mask) $svc"
        (systemctl mask --now "$svc") >> "$LOG_FILE" 2>&1 || true
        fn_log_action "MASK_SERVICE" "$svc" # [新增] 记录操作
        masked_count=$((masked_count + 1))
    fi
else
    fn_log "调试" "服务 $svc 不存在，跳过。"
fi
done

if [ "$masked_count" -eq 0 ]; then
fn_log "信息" "未检测到需要新屏蔽的系统服务。"
return 2
else
fn_log "成功" "系统服务精简完成 (共屏蔽 ${masked_count} 个新服务)。"
fi
return 0
}

# [新增] ZRAM 激活成功后调用的内部辅助函数
# 假设 /dev/zram0 已经被确认是激活的
_fn_cleanup_fallback_swap() {
    local fallback_swap="/swapfile_zram"
    
    # 检查回退 swapfile 是否存在
    if [ ! -f "$fallback_swap" ]; then
        return 0
    fi

    # 检查回退 swapfile 是否仍被使用
    if swapon -s | grep -q "$fallback_swap"; then
        fn_log "信息" "ZRAM 已激活，正在自动清理不再需要的回退 swapfile..."
        (swapoff "$fallback_swap") >> "$LOG_FILE" 2>&1 || true
        (rm -f "$fallback_swap") >> "$LOG_FILE" 2>&1 || true
        fn_log "成功" "已自动清理回退 swapfile: $fallback_swap"
    
    # 检查它是否存在但未被使用 (孤立文件)
    elif [ -f "$fallback_swap" ]; then
         fn_log "调试" "检测到未激活的回退 swapfile，正在清理..."
         (rm -f "$fallback_swap") >> "$LOG_FILE" 2>&1 || true
    fi
    return 0
}

fn_setup_zram_adaptive() {
    fn_log "信息" "启用 ZRAM (systemd-zram-generator 方案)..."

    # [修改] 检查 ZRAM 是否已激活
    if [ -b /dev/zram0 ] && swapon -s | grep -q 'zram'; then
        fn_log "信息" "ZRAM 已激活，跳过。"
        _fn_cleanup_fallback_swap # <-- [新增] 调用清理
        return 2 # 返回 "跳过"
    fi
    
    # [修改] 使用 $PKG_CHECK
    if $PKG_CHECK systemd-zram-generator >/dev/null 2>&1; then
        fn_log "信息" "ZRAM (systemd-zram-generator) 已安装。"
    else
        fn_log "信息" "正在安装 ZRAM (systemd-zram-generator)..."
        fn_wait_for_pkg_lock || { fn_log "错误" "包管理器锁等待失败"; return 1; }
        # [修改] 使用 $PKG_INSTALL
        $PKG_INSTALL systemd-zram-generator >>"$LOG_FILE" 2>&1 || { 
            fn_log "警告" "安装失败"; 
            fn_setup_zram_fallback "安装失败"; 
            return 1; 
        }
        fn_log_action "INSTALL_PKG" "systemd-zram-generator" # [新增] 记录操作
        fn_log "信息" "ZRAM (systemd-zram-generator) 安装完成。"
    fi

    mem_mb="$MEM_MB"
    
    # [修改] 设置为 100% 物理内存
    zram_mb="$mem_mb"
    
    # [修改] 增加一个上限 (例如 4GB)，以防在大内存机器上失控
    [ "$zram_mb" -gt 4096 ] && zram_mb=4096
    
    fn_log "信息" "ZRAM 目标大小: ${zram_mb} MB (100% 物理内存)"

    local conf_file="/etc/systemd/zram-generator.conf" # [新增]
    rm -f "$conf_file"
    fn_log "调试" "已移除旧 ZRAM 配置 (如果存在)。"

    cat > "$conf_file" <<EOF
[zram0]
zram-size = ${zram_mb}M
compression-algorithm = lz4
swap-priority = 100
EOF
    fn_log_action "CREATE_FILE" "$conf_file" # [新增] 记录操作
    fn_log "调试" "已写入 $conf_file"

    modprobe zram || true
    fn_log "调试" "已执行 modprobe zram"
    systemctl daemon-reexec || true
    fn_log "调试" "已执行 systemctl daemon-reexec"
    
    # --- 尝试 1 ---
    (systemctl restart systemd-zram-setup@zram0.service) >> "$LOG_FILE" 2>&1 || true
    fn_log "调试" "已重启 systemd-zram-setup@zram0.service (尝试 1)，等待 3 秒..."
    sleep 3

    # [修改] 检查 1
    if [ -b /dev/zram0 ] && swapon -s | grep -q 'zram'; then
        fn_log "成功" "ZRAM 已激活 (尝试 1 成功)"
        (swapon -s) >> "$LOG_FILE" 2>&1
        systemctl enable systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
        _fn_cleanup_fallback_swap # <-- [新增] 调用清理
        return 0 # 返回 "成功"
    fi

    # --- [新增] 尝试 2：清理内核缓存后重试 ---
    fn_log "警告" "ZRAM 激活失败 (尝试 1)，将尝试清理内核缓存后重试..."
    (sync && echo 3 > /proc/sys/vm/drop_caches) 2>/dev/null || true
    fn_log "调试" "已清理内核缓存，等待 2 秒..."
    sleep 2

    (systemctl restart systemd-zram-setup@zram0.service) >> "$LOG_FILE" 2>&1 || true
    fn_log "调试" "已重启 systemd-zram-setup@zram0.service (尝试 2)，等待 3 秒..."
    sleep 3

    # [修改] 检查 2
    if [ -b /dev/zram0 ] && swapon -s | grep -q 'zram'; then
        fn_log "成功" "ZRAM 已激活 (尝试 2 成功)"
        (swapon -s) >> "$LOG_FILE" 2>&1
        systemctl enable systemd-zram-setup@zram0.service >/dev/null 2>&1 || true
        _fn_cleanup_fallback_swap # <-- [新增] 调用清理
        return 0 # 返回 "成功"
    else
        fn_log "错误" "ZRAM 激活失败 (尝试 2 仍失败)，使用 swapfile 回退"
        fn_log "信息" "这在100%内存设置下是正常行为，ZRAM 应在重启后生效。"
        fn_setup_zram_fallback "ZRAM 激活失败"
        return 1
    fi
}

fn_setup_zram_fallback() {
    local reason="$1"
    fn_log "警告" "$reason, 使用 swapfile 回退"

    local swapfile="/swapfile_zram"
    local swapsize_mb=$(( MEM_MB < 512 ? MEM_MB : 512 ))
    
    # [修改] 确保在回退时也清理旧的 swapfile
    if [ -f "$swapfile" ]; then
        fn_log "调试" "检测到旧的 swapfile，正在移除..."
        swapoff "$swapfile" 2>/dev/null || true
        rm -f "$swapfile" 2>/dev/null || true
    fi

    fn_log "调试" "创建 swapfile: $swapfile (大小: ${swapsize_mb}M)"
    (fallocate -l "${swapsize_mb}M" "$swapfile" || dd if=/dev/zero of="$swapfile" bs=1M count="$swapsize_mb") >> "$LOG_FILE" 2>&1
    fn_log_action "CREATE_FILE" "$swapfile" # [新增] 记录操作
    
    chmod 600 "$swapfile"
    (mkswap "$swapfile") >> "$LOG_FILE" 2>&1 || true
    fn_log "调试" "mkswap $swapfile"
    
    (swapon "$swapfile") >> "$LOG_FILE" 2>&1 || true
    fn_log "调试" "swapon $swapfile"
    
    if swapon -s | grep -q "$(basename "$swapfile")"; then
        fn_log "成功" "Swapfile 回退启用 (${swapsize_mb} MB)"
        (swapon -s) >> "$LOG_FILE" 2>&1
    else
        fn_log "错误" "Swapfile 回退启用失败。"
    fi
}

fn_prioritize_network_services_auto() {
local detected_svcs=()
local changes_made=0

local services_list_str
local IFS=','
services_list_str="${FN_NETWORK_SERVICES_LIST[*]}"
fn_log "信息" "正在检测网络代理服务 (${services_list_str})..."

for svc in "${FN_NETWORK_SERVICES_LIST[@]}"; do
if systemctl list-unit-files --quiet "${svc}.service"; then
    detected_svcs+=("$svc")
fi
done

if [ ${#detected_svcs[@]} -eq 0 ]; then
fn_log "信息" "未检测到网络代理服务，无需优化。"
return 2
fi

local detected_svcs_str
IFS=','
detected_svcs_str="${detected_svcs[*]}"
fn_log "信息" "检测到: ${detected_svcs_str}。开始应用服务优化..."

for svc in "${detected_svcs[@]}"; do
    local conf_file="/etc/systemd/system/${svc}.service.d/90-vps_optimizert.conf"
    if [ -f "$conf_file" ]; then
        fn_log "调试" "配置文件 $conf_file 已存在，跳过 $svc。"
        continue
    fi
    
    fn_log "调试" "为 $svc 设置 Nice=-5, CPUQuota=70%。"
    
    local svc_conf_dir="/etc/systemd/system/${svc}.service.d"
    mkdir -p "$svc_conf_dir"
    cat > "$conf_file" <<EOF
[Service]
Nice=-5
CPUQuota=70%
EOF
    fn_log_action "CREATE_FILE" "$conf_file" # [新增] 记录操作
    changes_made=1
done

if [ "$changes_made" -eq 0 ]; then
     fn_log "信息" "网络代理服务均已配置，无需刷新。"
     return 2
fi

if [ "$changes_made" -eq 1 ]; then
    fn_log "调试" "重载 systemd daemon..."
    (systemctl daemon-reload) >> "$LOG_FILE" 2>&1
fi
fn_log "成功" "网络服务优化成功 (${detected_svcs_str})。"
return 0
}

# [修改] 完全重构为状态化恢复
fn_restore_all() {
    echo "[任务] 开始执行撤销优化..."
    fn_log "警告" "开始执行撤销优化... 将从 $ACTION_LOG 恢复。"

    if [ ! -f "$ACTION_LOG" ] || [ $(grep -vc '^#' "$ACTION_LOG") -eq 0 ]; then
        echo "[失败] 未找到操作日志或日志为空: $ACTION_LOG。无法自动撤销。"
        fn_log "错误" "未找到 $ACTION_LOG 或其为空。"
        return 1
    fi

    # [核心] 使用 tac 命令倒序读取日志文件，确保按相反顺序撤销
    tac "$ACTION_LOG" | while read -r line; do
        [ -z "$line" ] && continue
        [[ "$line" == \#* ]] && continue # 跳过注释
        
        # 解析 "ACTION:VALUE"
        local action=$(echo "$line" | cut -d: -f1)
        local value=$(echo "$line" | cut -d: -f2-)

        case "$action" in
            MASK_SERVICE)
                echo "[撤销]   Unmasking $value"
                fn_log "信息" "[撤销] Unmasking $value"
                (systemctl unmask "$value") >> "$LOG_FILE" 2>&1 || true
                ;;
            CREATE_FILE)
                echo "[撤销]   Removing file/dir $value"
                fn_log "信息" "[撤销] Removing file/dir $value"
                rm -rf "$value" # 使用 rm -rf 来处理 .service.d 目录
                
                # [改进] 顺便清理 .service.d 的空父目录
                if [[ "$value" == *.service.d/*.conf ]]; then
                    rmdir "$(dirname "$value")" 2>/dev/null || true
                fi
                ;;
            INSTALL_PKG)
                echo "[撤销]   Purging package $value"
                fn_log "信息" "[撤销] Purging package $value"
                if [ -n "$PKG_REMOVE" ]; then
                    fn_wait_for_pkg_lock || fn_log "警告" "包管理器锁等待失败，跳过卸载 $value"
                    ($PKG_REMOVE "$value") >> "$LOG_FILE" 2>&1
                fi
                ;;
            MODIFY_FILE)
                # 对于文件修改，我们仍然依赖 .bak 备份
                if [ -f "${value}.bak" ]; then
                    echo "[撤销]   Restoring $value from ${value}.bak"
                    fn_log "信息" "[撤销] Restoring $value from ${value}.bak"
                    mv "${value}.bak" "$value" >> "$LOG_FILE" 2>&1
                else
                    echo "[跳过]   未找到 ${value}.bak，无法恢复 $value"
                    fn_log "警告" "未找到 ${value}.bak，无法恢复 $value"
                fi
                ;;
            *)
                fn_log "警告" "未知的撤销操作: $action"
                ;;
        esac
    done

    # [修改] 保留 BBR 和恢复 journald/fstab 的备份文件
    echo "[任务]   正在恢复 sysctl..."
    [ -f "${BACKUP_DIR}/sysctl.conf.bak" ] && cp -an "${BACKUP_DIR}/sysctl.conf.bak" /etc/sysctl.conf 2>/dev/null || true
    [ -d "${BACKUP_DIR}/sysctl.d.bak" ] && cp -ar "${BACKUP_DIR}/sysctl.d.bak" /etc/sysctl.d/ 2>/dev/null || true
    cat > /etc/sysctl.d/98-bbr-retention.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>/dev/null || true

    echo "[任务]   正在恢复 journald..."
    [ -d "${BACKUP_DIR}/journald.conf.d.bak" ] && rm -rf /etc/systemd/journald.conf.d/ && cp -ar "${BACKUP_DIR}/journald.conf.d.bak" /etc/systemd/journald.conf.d/ 2>/dev/null || true
    systemctl restart systemd-journald >/dev/null 2>/dev/null || true
    
    [ -f "${BACKUP_DIR}/fstab.bak" ] && cp -an "${BACKUP_DIR}/fstab.bak" /etc/fstab 2>/dev/null || true
    
    echo "[任务]   正在停用 ZRAM (如果存在)..."
    (systemctl disable --now systemd-zram-setup@zram0.service) >> "$LOG_FILE" 2>&1 || true
    swapoff -a >/dev/null 2>&1 || true
    modprobe -r zram >/dev/null 2>&1 || true

    (systemctl daemon-reload) >> "$LOG_FILE" 2>&1
    
    # [新增] 完成后清空日志，以便下次运行
    rm -f "$ACTION_LOG"
    
    echo "[完成] 撤销优化完成。"
    fn_log "成功" "撤销优化完成。"
}

fn_show_status_report() {
    if [ "${1:-}" != "noclear" ]; then
        clear
    fi
    
    echo "==================== 系统优化状态 ===================="
    [ -f /etc/os-release ] && source /etc/os-release
    printf "系统: %s\n" "${PRETTY_NAME:-unknown}"
    printf "内存: %s MB\n" "$MEM_MB"
    printf "内核: %s\n" "$(uname -r)"
    echo "------------------------------------------------------"

    fn_print_line() {
        local name="$1"
        local status="$2"
        local success_msg="$3"
        local fail_msg="$4"
        local details="${5:-}"
        local status_msg="$fail_msg"
        [ "$status" == "true" ] && status_msg="$success_msg"
        local details_str=""
        [ -n "$details" ] && details_str="$details"
        printf "  %-30s %-15s %s\n" "$name" "$status_msg" "$details_str"
    }

    local sysctl_conf_file="/etc/sysctl.d/99-vps_optimizert.conf"
    local sysctl_status="false"
    local bbr_status="false"
    [ -f "$sysctl_conf_file" ] && sysctl_status="true"
    
    if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ] && \
       [ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" == "fq" ]; then
        bbr_status="true"
    fi
    local bbr_details=""
    [ "$bbr_status" == "true" ] && bbr_details="(已启用BBR+FQ)"
    
    fn_print_line "网络调优 (BBR)" "$bbr_status" "[ 已启用 ]" "[ 未启用 ]" "$bbr_details"
    
    local swappiness_details=""
    [ "$sysctl_status" == "true" ] && swappiness_details="(当前: $(sysctl -n vm.swappiness 2>/dev/null))"
    fn_print_line "Swappiness (10)" "$sysctl_status" "[ 已优化 ]" "[ 未优化 ]" "$swappiness_details"

    local vfs_details=""
    [ "$sysctl_status" == "true" ] && vfs_details="(当前: $(sysctl -n vm.vfs_cache_pressure 2>/dev/null))"
    fn_print_line "VFS 缓存压力 (100)" "$sysctl_status" "[ 已优化 ]" "[ 未优化 ]" "$vfs_details"

    local ipv6_details=""
    [ "$sysctl_status" == "true" ] && ipv6_details="(当前: $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null))"
    fn_print_line "禁用IPv6" "$sysctl_status" "[ 已优化 ]" "[ 未优化 ]" "$ipv6_details"


    local selinux_line="SELinux"
    local selinux_status="false"
    local selinux_details="(未检测到)"
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_state
        selinux_state=$(getenforce)
        if [ "$selinux_state" == "Disabled" ]; then
            selinux_status="true"
            selinux_details="(已禁用)"
        else
            selinux_status="false"
            selinux_details="(状态: $selinux_state)"
        fi
    else
        selinux_status="false"
        selinux_details="(未检测到)"
    fi
    fn_print_line "$selinux_line" "$selinux_status" "[ 已优化 ]" "[ 未优化 ]" "$selinux_details"

    local f2b_line="Fail2ban"
    local f2b_status="false"
    local f2b_success_msg="[ 已激活 ]"
    local f2b_fail_msg="[ 未激活 ]"
    local f2b_details="(未安装)"
    # [修改] 使用 $PKG_CHECK
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        f2b_status="true"
        f2b_details="(已激活)"
    elif $PKG_CHECK fail2ban >/dev/null 2>&1; then
        f2b_status="false"
        f2b_details="(已安装/未运行)"
    fi
    fn_print_line "$f2b_line" "$f2b_status" "$f2b_success_msg" "$f2b_fail_msg" "$f2b_details"

    local journal_storage
    journal_storage=$(systemd-analyze cat-config systemd/journald.conf | grep -i '^Storage=' | tail -n 1 | cut -d= -f2 2>/dev/null || echo "disk")
    local journal_status="false"
    local journal_details="(模式: ${journal_storage:-disk})"
    if [ -f /etc/systemd/journald.conf.d/10-volatile.conf ] && [ "$journal_storage" == "volatile" ]; then
        journal_status="true"
        journal_details="(模式: 仅内存, 上限: 16M)"
    elif [ "$journal_storage" == "volatile" ]; then
        journal_status="true"
        journal_details="(模式: 仅内存, 未知配置)"
    fi
    fn_print_line "Journald 日志存储模式" "$journal_status" "[ 已优化 ]" "[ 未优化 ]" "$journal_details"

    local masked_count=0
    local services_to_check=("${FN_TRIM_SERVICES_LIST[@]}" "rsyslog.service")
    
    for svc in "${services_to_check[@]}"; do
        local svc_status
        svc_status=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        if [[ "$svc_status" == *"masked"* ]]; then
            masked_count=$((masked_count + 1))
        fi
    done
    local trim_status="false"
    local trim_details="(未屏蔽服务)"
    if [ "$masked_count" -gt 0 ]; then
        trim_status="true"
        trim_details="(已屏蔽 $masked_count 个服务)"
    fi
    fn_print_line "系统服务精简" "$trim_status" "[ 已优化 ]" "[ 未优化 ]" "$trim_details"

    local zram_status="false"
    local zram_details="(未激活)"
    if [ -f /etc/systemd/zram-generator.conf ] && swapon -s | grep -q 'zram'; then
        zram_status="true"
        local free_swap_line
        free_swap_line=$(free -h | grep '^Swap:')
        local swap_total
        swap_total=$(echo "$free_swap_line" | awk '{print $2}')
        local swap_used
        swap_used=$(echo "$free_swap_line" | awk '{print $3}')
        zram_details="(ZRAM: $swap_total, 已用: $swap_used)"
    elif swapon -s | grep -q 'swapfile_zram'; then
        zram_status="true"
        local free_swap_line
        free_swap_line=$(free -h | grep '^Swap:')
        local swap_total
        swap_total=$(echo "$free_swap_line" | awk '{print $2}')
        local swap_used
        swap_used=$(echo "$free_swap_line" | awk '{print $3}')
        zram_details="(Swapfile 回退: $swap_total, 已用: $swap_used)"
    fi
    fn_print_line "ZRAM/Swap" "$zram_status" "[ 已激活 ]" "[ 未激活 ]" "$zram_details"

    local drop_in_found=()
    for svc in "${FN_NETWORK_SERVICES_LIST[@]}"; do
        if [ -f "/etc/systemd/system/${svc}.service.d/90-vps_optimizert.conf" ]; then
            drop_in_found+=("$svc")
        fi
    done
    
    local net_prio_status="false"
    local net_prio_details="(未检测到网络代理服务)"
    if [ ${#drop_in_found[@]} -gt 0 ]; then
        net_prio_status="true"
        local IFS=','
        net_prio_details="(已配置: ${drop_in_found[*]})"
    fi
    fn_print_line "网络服务优化" "$net_prio_status" "[ 已配置 ]" "[ 未优化 ]" "$net_prio_details"

    echo "======================================================"
}

fn_optimize_auto() {
    local result
    
    echo "[任务 1 ] ：创建备份文件..."
    result=0
    fn_backup_state || result=$?
    if [ $result -ne 0 ]; then
        echo "[失败] 备份文件创建失败，退出优化。"
        fn_log "错误" "fn_backup_state 失败，退出。"
        return 1
    fi
    # [修改] 隐藏输出
    # echo "[完成] 备份文件创建成功: $BACKUP_DIR"
    # echo "--------------"
    
    echo "[任务 2 ] ：检查包管理器源..."
    result=0
    fn_fix_apt_sources_if_needed || result=$?
    if [ $result -ne 0 ]; then
        fn_log "错误" "fn_fix_apt_sources_if_needed 失败。"
    fi
    # [修改] 隐藏输出
    # echo "--------------"

    echo "[任务 3 ] ：检查 SELinux 状态..."
    result=0
    fn_handle_selinux || result=$?
    # [修改] 隐藏输出
    # if [ $result -eq 0 ]; then
    #     echo "[完成] SELinux 检查完成 (已操作)。"
    # elif [ $result -eq 2 ]; then
    #     echo "[跳过] SELinux 状态良好或未检测到。"
    # fi
    # echo "--------------"
    
    echo "[任务 4 ] ：配置 Journald (日志)..."
    result=0
    fn_setup_journald_volatile || result=$?
    # [修改] 隐藏输出
    # echo "--------------"

    echo "[任务 5 ] ：应用 sysctl 网络调优..."
    result=0
    fn_setup_sysctl_lowmem || result=$?
    # [修改] 隐藏输出
    # echo "--------------"

    echo "[任务 6 ] ：配置 ZRAM..."
    result=0
    fn_setup_zram_adaptive || result=$?
    # [修改] 隐藏输出
    # echo "--------------"

    echo "[任务 7 ] ：配置 Fail2ban..."
    result=0
    fn_setup_fail2ban || result=$?
    # [修改] 隐藏输出
    # echo "--------------"

    echo "[任务 8 ] ：优化网络代理服务..."
    result=0
    fn_prioritize_network_services_auto || result=$?
    # [修改] 隐藏输出
    # echo "--------------"
    
    echo "[任务 9 ] ：精简系统服务..."
    result=0
    fn_trim_services_auto || result=$?
    # [修改] 隐藏输出
    # echo "--------------"
    
    echo ""
    echo "系统优化完成。请重启系统以完全生效。"
    fn_log "成功" "系统优化完成。请重启系统以完全生效。"
    fn_show_status_report "noclear"
}

fn_get_detected_services_string() {
    local detected_svcs=()
    for svc in "${FN_NETWORK_SERVICES_LIST[@]}"; do
        if systemctl list-unit-files --quiet "${svc}.service"; then
            detected_svcs+=("$svc")
        fi
    done
    
    if [ ${#detected_svcs[@]} -gt 0 ]; then
        local IFS=','
        echo " (检测到: ${detected_svcs[*]})"
    else
        echo ""
    fi
}

fn_show_menu() {
    clear
    local detected_svcs_str
    detected_svcs_str=$(fn_get_detected_services_string)

    echo "==============================================="
    echo " VPS 自动优化脚本 (vps_optimizert)"
    echo " 版本: $SCRIPT_VERSION"
    echo " 备份目录: $BACKUP_DIR"
    echo " 日志文件: $LOG_FILE"
    echo "==============================================="
    echo " 1) 执行系统优化 (全自动)"
    echo " 2) 撤销优化 (保留BBR)"
    echo " 3) 显示系统优化状态"
    echo " 4) 优化网络代理服务${detected_svcs_str}"
    echo " 0) 退出"
    echo "===============================================
"
    read -rp "请选择: " CH || true
    case "$CH" in
        1) 
            fn_optimize_auto 
            read -rp "优化完成 (请重启)。按回车返回主菜单..." dummy || true
            ;;
        2) 
            fn_restore_all 
            read -rp "撤销完成。按回车返回主菜单..." dummy || true
            ;;
        3) 
            fn_show_status_report
            read -rp "按回车返回菜单..." dummy || true 
            ;;
        4) 
            echo "[任务] 正在优化网络代理服务..."
            result=0
            fn_prioritize_network_services_auto || result=$?
            if [ $result -eq 0 ]; then
                echo "[完成] 优化完成。"
            elif [ $result -eq 2 ]; then
                echo "[跳过] 未检测到服务或服务均已配置。"
            fi
            read -rp "按回车返回菜单..." dummy || true
            ;;
        0) 
            echo "退出。"
            fn_log "信息" "退出。"; exit 0 
            ;;
        *) 
            echo "错误: 无效选项。"
            fn_log "错误" "无效选项。"; sleep 1;
            ;;
    esac
    fn_show_menu
}

fn_check_root
fn_detect_os

# [修改] 移除了旧的 fn_cleanup_fallback_swap 调用
# 清理功能现已整合到 fn_setup_zram_adaptive 中

fn_show_menu
