#!/bin/bash

VERSION="1.0.1"
WARP_GO_INSTALL_DIR="/etc/warp-go"
WARP_BIN="$WARP_GO_INSTALL_DIR/warp-go"
WARP_CONF="$WARP_GO_INSTALL_DIR/warp.conf"
SERVICE_NAME="warp-go.service"
SOCKS_PORT=40000
STATUS=0  # 0-未安装;1-已安装未启动;2-已启动;3-脚本安装中

# 输出函数
info() { echo -e "\033[1;32m$1\033[0m"; }
warn() { echo -e "\033[1;33m$1\033[0m"; }
error(){ echo -e "\033[1;31m$1\033[0m"; }

# ----------------------------
# 安装依赖
# ----------------------------
install_dependencies(){
    for dep in jq curl; do
        if ! command -v $dep &>/dev/null; then
            info "检测到 $dep 未安装，正在安装..."
            if [ -f /etc/debian_version ]; then
                apt update && apt install -y $dep
            elif [ -f /etc/redhat-release ]; then
                yum install -y epel-release && yum install -y $dep
            elif [ -f /etc/arch-release ]; then
                pacman -Sy --noconfirm $dep
            else
                warn "请手动安装 $dep"
            fi
        fi
    done
}

# ----------------------------
# 检测 warp-go 安装状态
# STATUS: 0-未安装; 1-已安装未启动; 2-已安装启动中; 3-脚本安装中
# ----------------------------
check_install(){
    ARCHITECTURE=$(uname -m)
    if [ -s "$WARP_CONF" ]; then
        [[ "$(ip link show | awk -F': ' '{print $2}')" =~ "WARP" ]] && STATUS=2 || STATUS=1
    else
        STATUS=0
        STATUS=3
        {
            info "检测到未安装 warp-go，正在后台下载..."
            
            latest=$(wget -qO- -T2 -t1 https://gitlab.com/api/v4/projects/ProjectWARP%2Fwarp-go/releases \
                     | awk -F '"' '{for (i=0; i<NF; i++) if ($i=="tag_name") {print $(i+2); exit}}' \
                     | sed "s/v//")
            latest=${latest:-'1.0.8'}

            TMP_DIR=$(mktemp -d)
            URL="https://gitlab.com/fscarmen/warp/-/raw/main/warp-go/warp-go_${latest}_linux_${ARCHITECTURE}.tar.gz"

            if wget --no-check-certificate -T5 -qO- "$URL" | tar xz -C "$TMP_DIR" warp-go 2>/tmp/warp-go-error.log; then
                mkdir -p "$WARP_GO_INSTALL_DIR"
                mv "$TMP_DIR/warp-go" "$WARP_BIN"
                chmod +x "$WARP_BIN"
                rm -rf "$TMP_DIR"
                info "warp-go 下载完成: $latest"
            else
                error "warp-go 下载或解压失败，请检查网络或手动下载"
                STATUS=0
                rm -rf "$TMP_DIR"
                cat /tmp/warp-go-error.log
            fi
        }&
    fi
}

# ----------------------------
# 显示系统 + warp-go 状态
# ----------------------------
show_status(){
    SYS=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
    KERNEL=$(uname -r)
    ARCH=$(uname -m)
    VIRT=$(systemd-detect-virt)
    WAN4=$(curl -s4 ifconfig.me)
    WAN6=$(curl -s6 ifconfig.me)

    info "======== 系统状态 ========"
    info "版本: $VERSION"
    info "安装状态: $STATUS"
    info "系统信息:"
    info "\t当前操作系统: $SYS"
    info "\t内核: $KERNEL"
    info "\t处理器架构: $ARCH"
    info "\t虚拟化: $VIRT"
    info "\tIPv4: $WAN4"
    info "\tIPv6: $WAN6"

    warp_STATUS="已关闭"
    if systemctl is-active --quiet $SERVICE_NAME; then
        warp_STATUS="已开启"
    fi
    info "-------- warp-go 状态 --------"
    info "\twarp-go $warp_STATUS\t 本地 Socks5: $SOCKS_PORT"
}

# ----------------------------
# 菜单
# ----------------------------
menu(){
    while true; do
        check_install
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
            1|-o) systemctl start $SERVICE_NAME; info "warp-go 已启动";;
            2|-c) systemctl stop $SERVICE_NAME; info "warp-go 已停止";;
            3|-p) read -p "请输入新的 Socks5 端口: " NEWPORT
                  SOCKS_PORT=$NEWPORT
                  sed -i "s/--socks5=[0-9]\+/--socks5=$SOCKS_PORT/" /etc/systemd/system/$SERVICE_NAME
                  systemctl daemon-reload
                  systemctl restart $SERVICE_NAME
                  info "端口已修改为 $SOCKS_PORT";;
            4|-u) systemctl stop $SERVICE_NAME
                  systemctl disable $SERVICE_NAME
                  rm -f /etc/systemd/system/$SERVICE_NAME
                  rm -rf "$WARP_GO_INSTALL_DIR"
                  systemctl daemon-reload
                  info "warp-go 已卸载"; exit;;
            0|-q) exit;;
            *) warn "请输入有效选项";;
        esac
    done
}

# ----------------------------
# 主逻辑
# ----------------------------
install_dependencies
menu
