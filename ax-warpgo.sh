#!/bin/bash

# ===========================================
# warp-go 一键安装 + systemd + 菜单 + 状态显示 + 版本号
# 单目录安装：可执行文件 + 配置 + systemd
# ===========================================

VERSION="1.0.0"
WARP_GO_INSTALL_DIR="/etc/warp-go"
SERVICE_NAME="warp-go.service"
SOCKS_PORT=40000

# 颜色输出
info() { echo -e "\033[1;32m$1\033[0m"; }
warn() { echo -e "\033[1;33m$1\033[0m"; }
error(){ echo -e "\033[1;31m$1\033[0m"; }

# ----------------------------
# 安装依赖
# ----------------------------
install_dependencies(){
    if ! command -v jq &>/dev/null; then
        info "检测到 jq 未安装，正在安装..."
        if [ -f /etc/debian_version ]; then
            apt update && apt install -y jq curl
        elif [ -f /etc/redhat-release ]; then
            yum install -y epel-release && yum install -y jq curl
        elif [ -f /etc/arch-release ]; then
            pacman -Sy --noconfirm jq curl
        else
            warn "未检测到受支持的包管理器，请手动安装 jq 和 curl"
        fi
        info "依赖安装完成"
    fi
    if ! command -v curl &>/dev/null; then
        warn "curl 未安装，请手动安装或确保网络通畅"
        exit 1
    fi
}

# ----------------------------
# 系统信息
# ----------------------------
get_sys_info(){
    SYS=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
    KERNEL=$(uname -r)
    ARCH=$(uname -m)
    VIRT=$(systemd-detect-virt)
    WAN4=$(curl -s4 ifconfig.me)
    WAN6=$(curl -s6 ifconfig.me)
    if [ "$WAN4" != "" ]; then
        read COUNTRY4 ASNORG4 <<<$(curl -s https://ipinfo.io/$WAN4 | jq -r '"\(.country) \(.org)"')
    else
        COUNTRY4="N/A"; ASNORG4="N/A"
    fi
    if [ "$WAN6" != "" ]; then
        read COUNTRY6 ASNORG6 <<<$(curl -s https://ipinfo.io/$WAN6 | jq -r '"\(.country) \(.org)"')
    else
        COUNTRY6="N/A"; ASNORG6="N/A"
    fi
}

# ----------------------------
# warp-go 状态
# ----------------------------
get_warp_status(){
    if systemctl is-active --quiet $SERVICE_NAME; then
        warp_STATUS="已开启"
        warp_SOCKS5=$SOCKS_PORT
        warp_WAN4=$(curl -s4 --socks5 127.0.0.1:$SOCKS_PORT ifconfig.me)
        warp_WAN6=$(curl -s6 --socks5 127.0.0.1:$SOCKS_PORT ifconfig.me)
        if [ "$warp_WAN4" != "" ]; then
            read warp_COUNTRY4 warp_ASNORG4 <<<$(curl -s https://ipinfo.io/$warp_WAN4 | jq -r '"\(.country) \(.org)"')
        else
            warp_COUNTRY4="N/A"; warp_ASNORG4="N/A"
        fi
        if [ "$warp_WAN6" != "" ]; then
            read warp_COUNTRY6 warp_ASNORG6 <<<$(curl -s https://ipinfo.io/$warp_WAN6 | jq -r '"\(.country) \(.org)"')
        else
            warp_COUNTRY6="N/A"; warp_ASNORG6="N/A"
        fi
    else
        warp_STATUS="已关闭"
    fi
}

# ----------------------------
# 安装 warp-go
# ----------------------------
install_warp(){
    mkdir -p $WARP_GO_INSTALL_DIR
    cd $WARP_GO_INSTALL_DIR || exit
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) URL="https://gitlab.com/fscarmen/warp/-/raw/main/warp-go-linux-amd64" ;;
        aarch64) URL="https://gitlab.com/fscarmen/warp/-/raw/main/warp-go-linux-arm64" ;;
        *) error "不支持的 CPU 架构: $ARCH"; exit 1 ;;
    esac
    info "正在下载 warp-go..."
    curl -L $URL -o warp-go
    chmod +x warp-go
    info "warp-go 下载完成"

    if [ ! -f "$WARP_GO_INSTALL_DIR/warp.conf" ]; then
        info "正在注册 WARP..."
        ./warp-go --register --config=warp.conf
        info "注册完成"
    fi

    # 创建 systemd 服务
    cat >/etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=Warp-Go Socks5 Service
After=network.target

[Service]
WorkingDirectory=$WARP_GO_INSTALL_DIR
ExecStart=$WARP_GO_INSTALL_DIR/warp-go --config=$WARP_GO_INSTALL_DIR/warp.conf --socks5=$SOCKS_PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    info "warp-go systemd 服务已创建"
}

# ----------------------------
# 启动 warp-go
# ----------------------------
start_warp(){ systemctl start $SERVICE_NAME; info "warp-go 已启动"; }

# ----------------------------
# 停止 warp-go
# ----------------------------
stop_warp(){ systemctl stop $SERVICE_NAME; info "warp-go 已停止"; }

# ----------------------------
# 修改 Socks5 端口
# ----------------------------
change_port(){
    read -p "请输入新的 Socks5 端口: " NEWPORT
    if [[ $NEWPORT =~ ^[0-9]+$ ]]; then
        SOCKS_PORT=$NEWPORT
        sed -i "s/--socks5=[0-9]\+/--socks5=$SOCKS_PORT/" /etc/systemd/system/$SERVICE_NAME
        systemctl daemon-reload
        systemctl restart $SERVICE_NAME
        info "端口已修改为 $SOCKS_PORT"
    else
        warn "端口输入不合法"
    fi
}

# ----------------------------
# 卸载 warp-go
# ----------------------------
uninstall_warp(){
    stop_warp
    systemctl disable $SERVICE_NAME
    rm -f /etc/systemd/system/$SERVICE_NAME
    rm -rf $WARP_GO_INSTALL_DIR
    systemctl daemon-reload
    info "warp-go 已卸载"
}

# ----------------------------
# 显示状态
# ----------------------------
show_status(){
    get_sys_info
    get_warp_status
    info "======== 系统状态 ========"
    info "版本: $VERSION"
    info "系统信息:"
    info "\t当前操作系统: $SYS"
    info "\t内核: $KERNEL"
    info "\t处理器架构: $ARCH"
    info "\t虚拟化: $VIRT"
    info "\tIPv4: $WAN4 $COUNTRY4 $ASNORG4"
    info "\tIPv6: $WAN6 $COUNTRY6 $ASNORG6"
    info "-------- warp-go 状态 --------"
    if [ "$warp_STATUS" = "已开启" ]; then
        info "\twarp-go $warp_STATUS\t 本地 Socks5: $warp_SOCKS5"
        info "\tIPv4: $warp_WAN4 $warp_COUNTRY4 $warp_ASNORG4"
        info "\tIPv6: $warp_WAN6 $warp_COUNTRY6 $warp_ASNORG6"
    else
        info "\twarp-go $warp_STATUS"
    fi
}

# ----------------------------
# 菜单
# ----------------------------
menu(){
    while true; do
        show_status
        echo ""
        echo "========== warp-go 菜单 =========="
        echo "1) 开启 warp-go Socks5 代理 (-o)"
        echo "2) 关闭 warp-go Socks5 代理 (-c)"
        echo "3) 修改 warp-go Socks5 端口 (-p)"
        echo "4) 卸载 warp-go (-u)"
        echo "0) 退出 (-q)"
        echo "=================================="
        read -p "请选择操作 [0-4]: " choice
        case $choice in
            1|-o) start_warp ;;
            2|-c) stop_warp ;;
            3|-p) change_port ;;
            4|-u) uninstall_warp; exit ;;
            0|-q) exit ;;
            *) warn "请输入有效选项";;
        esac
    done
}

# ----------------------------
# 主逻辑
# ----------------------------
install_dependencies
if [ ! -f "$WARP_GO_INSTALL_DIR/warp-go" ]; then
    install_warp
fi

menu
