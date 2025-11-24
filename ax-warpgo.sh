#!/usr/bin/env bash

# ax-warpgo.sh - Simplified warp-go Socks5 Proxy Management Script
# Extracted from warp-go.sh for easy Socks5 proxy management
VERSION='1.0.0'

# 环境变量用于在Debian或Ubuntu操作系统中设置非交互式安装模式
export DEBIAN_FRONTEND=noninteractive

# Warp-go安装目录
WARP_DIR="/etc/warp-go"
WARP_CONF="$WARP_DIR/warp.conf"

# 清理函数
trap 'rm -f /tmp/ax-warpgo-* 2>/dev/null; exit 0' EXIT INT TERM

# ============ 颜色输出函数 ============
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m"; exit 1; }  # 红色并退出
info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
reading() { read -rp "$(info "$1")" "$2"; }

# ============ 检查root权限 ============
check_root() {
  [ "$(id -u)" != 0 ] && error "必须以root方式运行脚本，可以输入 sudo -i 后重新运行"
}

# ============ 检测操作系统 ============
check_operating_system() {
  if [ -s /etc/os-release ]; then
    SYS="$(grep -i pretty_name /etc/os-release | cut -d \" -f2)"
  elif [ $(type -p hostnamectl) ]; then
    SYS="$(hostnamectl | grep -i system | cut -d : -f2)"
  elif [ $(type -p lsb_release) ]; then
    SYS="$(lsb_release -sd)"
  elif [ -s /etc/lsb-release ]; then
    SYS="$(grep -i description /etc/lsb-release | cut -d \" -f2)"
  elif [ -s /etc/issue ]; then
    SYS="$(grep . /etc/issue | cut -d '\' -f1 | sed '/^[ ]*$/d')"
  fi

  # 判断是否为支持的系统
  if [[ ! "${SYS,,}" =~ debian|ubuntu ]]; then
    error "本脚本仅支持 Debian 和 Ubuntu 系统"
  fi
}

# ============ 检测处理器架构 ============
check_arch() {
  case "$(uname -m)" in
    aarch64 ) ARCHITECTURE=arm64 ;;
    x86_64 ) ARCHITECTURE=amd64 ;;
    * ) error "当前架构 $(uname -m) 暂不支持" ;;
  esac
}

# ============ 检测虚拟化 ============
check_virt() {
  if [ $(type -p systemd-detect-virt) ]; then
    VIRT=$(systemd-detect-virt)
  elif [ $(type -p hostnamectl) ]; then
    VIRT=$(hostnamectl | awk '/Virtualization:/{print $NF}')
  else
    VIRT="unknown"
  fi
}

# ============ 检测并安装依赖项 ============
check_dependencies() {
  local DEPS_CHECK=("curl" "jq")
  local DEPS_INSTALL=()

  # 检查缺失的依赖
  for dep in "${DEPS_CHECK[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      DEPS_INSTALL+=("$dep")
    fi
  done

  # 如果有缺失的依赖，则安装
  if [ ${#DEPS_INSTALL[@]} -gt 0 ]; then
    hint "\n检测到缺失的依赖项: ${DEPS_INSTALL[*]}"
    hint "正在安装依赖项...\n"
    
    # 更新包列表
    apt-get update -qq >/dev/null 2>&1
    
    # 安装依赖
    for dep in "${DEPS_INSTALL[@]}"; do
      if apt-get install -y "$dep" >/dev/null 2>&1; then
        info "✓ 已安装: $dep"
      else
        error "✗ 安装失败: $dep - 脚本无法继续运行"
      fi
    done
    
    echo ""
  fi
  
  # 验证 jq 必须可用
  if ! command -v jq >/dev/null 2>&1; then
    error "jq 未安装且安装失败，脚本无法运行"
  fi
}

# ============ 获取 IPv4 信息 ============
ip4_info() {
  unset WAN4 COUNTRY4 ASNORG4
  local TRACE4=$(curl --retry 2 -ks4m5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F '=' '/^warp=/{print $NF}')
  if [ -n "$TRACE4" ]; then
    WAN4=$(curl --retry 2 -ks4m5 -A Mozilla https://ipinfo.io/ip 2>/dev/null)
    if [ -n "$WAN4" ]; then
      local IP4_JSON=$(curl --retry 2 -ks4m3 --user-agent Mozilla https://ifconfig.co/json 2>/dev/null)
      if [ -n "$IP4_JSON" ]; then
        COUNTRY4=$(echo "$IP4_JSON" | jq -r '.country // empty' 2>/dev/null)
        ASNORG4=$(echo "$IP4_JSON" | jq -r '.asn_org // empty' 2>/dev/null)
      fi
    fi
  fi
}

# ============ 获取 IPv6 信息 ============
ip6_info() {
  unset WAN6 COUNTRY6 ASNORG6
  local TRACE6=$(curl --retry 2 -ks6m5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F '=' '/^warp=/{print $NF}')
  if [ -n "$TRACE6" ]; then
    WAN6=$(curl --retry 2 -ks6m5 -A Mozilla https://api-ipv6.ip.sb/geoip 2>/dev/null | jq -r '.ip // empty' 2>/dev/null)
    if [ -n "$WAN6" ]; then
      local IP6_JSON=$(curl --retry 2 -ks6m3 --user-agent Mozilla https://ifconfig.co/json -6 2>/dev/null)
      if [ -n "$IP6_JSON" ]; then
        COUNTRY6=$(echo "$IP6_JSON" | jq -r '.country // empty' 2>/dev/null)
        ASNORG6=$(echo "$IP6_JSON" | jq -r '.asn_org // empty' 2>/dev/null)
      fi
    fi
  fi
}

# ============ 检测 warp-go 状态 ============
check_warpgo_status() {
  WARPGO_STATUS="未开启"
  WARPGO_SOCKS5=""
  WARPGO_WAN4=""
  WARPGO_WAN6=""
  WARPGO_COUNTRY4=""
  WARPGO_COUNTRY6=""
  WARPGO_ASNORG4=""
  WARPGO_ASNORG6=""

  # 检查 warp-go 进程是否运行
  if pgrep -x "warp-go" >/dev/null 2>&1; then
    WARPGO_STATUS="已开启"
    
    # 获取 Socks5 端口
    if [ -s "$WARP_CONF" ]; then
      WARPGO_SOCKS5=$(grep -oP '^\s*Socks5\s*=\s*\K.*' "$WARP_CONF" 2>/dev/null)
      [ -z "$WARPGO_SOCKS5" ] && WARPGO_SOCKS5="127.0.0.1:40000"
    fi

    # 通过 Socks5 代理获取 WARP IP 信息
    local SOCKS_HOST=$(echo "$WARPGO_SOCKS5" | cut -d: -f1)
    local SOCKS_PORT=$(echo "$WARPGO_SOCKS5" | cut -d: -f2)
    
    # 获取 IPv4 信息
    WARPGO_WAN4=$(curl -x socks5h://${SOCKS_HOST}:${SOCKS_PORT} -4 --retry 2 -ksm5 https://api.ipify.org 2>/dev/null)
    if [ -n "$WARPGO_WAN4" ]; then
      local WARP_IP4_JSON=$(curl -x socks5h://${SOCKS_HOST}:${SOCKS_PORT} -4 --retry 2 -ksm3 --user-agent Mozilla https://ifconfig.co/json 2>/dev/null)
      if [ -n "$WARP_IP4_JSON" ]; then
        WARPGO_COUNTRY4=$(echo "$WARP_IP4_JSON" | jq -r '.country // empty' 2>/dev/null)
        WARPGO_ASNORG4=$(echo "$WARP_IP4_JSON" | jq -r '.asn_org // empty' 2>/dev/null)
      fi
    fi

    # 获取 IPv6 信息
    WARPGO_WAN6=$(curl -x socks5h://${SOCKS_HOST}:${SOCKS_PORT} -6 --retry 2 -ksm5 https://api6.ipify.org 2>/dev/null)
    if [ -n "$WARPGO_WAN6" ]; then
      local WARP_IP6_JSON=$(curl -x socks5h://${SOCKS_HOST}:${SOCKS_PORT} -6 --retry 2 -ksm3 --user-agent Mozilla https://ifconfig.co/json 2>/dev/null)
      if [ -n "$WARP_IP6_JSON" ]; then
        WARPGO_COUNTRY6=$(echo "$WARP_IP6_JSON" | jq -r '.country // empty' 2>/dev/null)
        WARPGO_ASNORG6=$(echo "$WARP_IP6_JSON" | jq -r '.asn_org // empty' 2>/dev/null)
      fi
    fi
  fi
}

# ============ 显示系统状态 ============
show_status() {
  clear
  echo "========================================================================"
  info "版本: $VERSION"
  echo "------------------------------------------------------------------------"
  info "系统信息:"
  info "\t 当前操作系统: $SYS"
  info "\t 内核: $(uname -r)"
  info "\t 处理器架构: $(uname -m)"
  info "\t 虚拟化: $VIRT"
  info "\t IPv4: $WAN4 $COUNTRY4 $ASNORG4"
  info "\t IPv6: $WAN6 $COUNTRY6 $ASNORG6"
  echo "------------------------------------------------------------------------"
  
  # 显示 warp-go 状态
  if [ "$WARPGO_STATUS" = "已开启" ]; then
    info "\t warp-go $WARPGO_STATUS\t 本地 Socks5: $WARPGO_SOCKS5"
    info "\t IPv4: $WARPGO_WAN4 $WARPGO_COUNTRY4 $WARPGO_ASNORG4"
    info "\t IPv6: $WARPGO_WAN6 $WARPGO_COUNTRY6 $WARPGO_ASNORG6"
  else
    info "\t warp-go $WARPGO_STATUS"
  fi
  echo "========================================================================"
}

# ============ 开启 warp-go Socks5 代理 ============
start_warpgo() {
  if [ ! -s "$WARP_CONF" ]; then
    error "warp-go 配置文件不存在: $WARP_CONF，请先安装 warp-go"
  fi

  if pgrep -x "warp-go" >/dev/null 2>&1; then
    warning "warp-go Socks5 代理已经在运行中"
    return
  fi

  # 启用 Socks5 配置（取消注释）
  if grep -q "^#.*Socks5" "$WARP_CONF"; then
    sed -i 's/^#\s*Socks5/Socks5/' "$WARP_CONF"
  elif ! grep -q "^Socks5" "$WARP_CONF"; then
    # 如果没有 Socks5 配置，添加默认配置
    sed -i '/\[Peer\]/i Socks5 = 127.0.0.1:40000' "$WARP_CONF"
  fi

  # 启动 warp-go
  if [ -x "$WARP_DIR/warp-go" ]; then
    nohup "$WARP_DIR/warp-go" --config="$WARP_CONF" >/dev/null 2>&1 &
    sleep 2
    
    if pgrep -x "warp-go" >/dev/null 2>&1; then
      info "warp-go Socks5 代理已成功开启"
    else
      error "warp-go Socks5 代理启动失败"
    fi
  else
    error "warp-go 程序不存在，请先安装 warp-go"
  fi
}

# ============ 关闭 warp-go Socks5 代理 ============
stop_warpgo() {
  if ! pgrep -x "warp-go" >/dev/null 2>&1; then
    warning "warp-go Socks5 代理未在运行"
    return
  fi

  # 停止 warp-go 进程
  pkill -15 warp-go >/dev/null 2>&1
  sleep 1

  if ! pgrep -x "warp-go" >/dev/null 2>&1; then
    info "warp-go Socks5 代理已成功关闭"
  else
    warning "warp-go 进程可能未完全停止，尝试强制关闭..."
    pkill -9 warp-go >/dev/null 2>&1
    sleep 1
    if ! pgrep -x "warp-go" >/dev/null 2>&1; then
      info "warp-go Socks5 代理已强制关闭"
    else
      error "无法停止 warp-go 进程"
    fi
  fi
}

# ============ 修改 warp-go Socks5 端口 ============
modify_port() {
  local NEW_PORT="$1"
  
  if [ ! -s "$WARP_CONF" ]; then
    error "warp-go 配置文件不存在: $WARP_CONF"
  fi

  # 如果没有提供端口，询问用户
  if [ -z "$NEW_PORT" ]; then
    reading "请输入新的 Socks5 端口 (默认 40000): " NEW_PORT
    NEW_PORT=${NEW_PORT:-40000}
  fi

  # 验证端口范围
  if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1024 ] || [ "$NEW_PORT" -gt 65535 ]; then
    error "无效的端口号，请输入 1024-65535 之间的数字"
  fi

  # 修改配置文件
  if grep -q "^Socks5" "$WARP_CONF"; then
    sed -i "s/^Socks5.*/Socks5 = 127.0.0.1:${NEW_PORT}/" "$WARP_CONF"
  elif grep -q "^#.*Socks5" "$WARP_CONF"; then
    sed -i "s/^#.*Socks5.*/Socks5 = 127.0.0.1:${NEW_PORT}/" "$WARP_CONF"
  else
    sed -i "/\[Peer\]/i Socks5 = 127.0.0.1:${NEW_PORT}" "$WARP_CONF"
  fi

  info "Socks5 端口已修改为: 127.0.0.1:${NEW_PORT}"

  # 如果 warp-go 正在运行，重启以应用新配置
  if pgrep -x "warp-go" >/dev/null 2>&1; then
    hint "正在重启 warp-go 以应用新配置..."
    stop_warpgo
    sleep 1
    start_warpgo
  else
    hint "配置已更新，使用 'bash $0 -o' 启动 warp-go"
  fi
}

# ============ 卸载 warp-go ============
uninstall_warpgo() {
  reading "确认卸载 warp-go? (y/N): " CONFIRM
  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    hint "取消卸载"
    return
  fi

  # 停止 warp-go
  pkill -9 warp-go >/dev/null 2>&1

  # 删除文件和目录
  rm -rf "$WARP_DIR"
  rm -f /usr/bin/warp-go /lib/systemd/system/warp-go.service

  info "warp-go 已成功卸载"
}

# ============ 显示菜单 ============
show_menu() {
  show_status
  echo ""
  hint "1) 开启 warp-go Socks5 代理"
  hint "3) 关闭 warp-go Socks5 代理"
  hint "5) 修改 warp-go Socks5 端口"
  hint "6) 卸载"
  hint "0) 退出"
  echo ""
  reading "请选择 [0-6]: " CHOICE

  case "$CHOICE" in
    1) start_warpgo; reading "\n按回车键继续..." DUMMY; show_menu ;;
    3) stop_warpgo; reading "\n按回车键继续..." DUMMY; show_menu ;;
    5) modify_port; reading "\n按回车键继续..." DUMMY; show_menu ;;
    6) uninstall_warpgo; exit 0 ;;
    0) exit 0 ;;
    *) warning "无效选择"; sleep 1; show_menu ;;
  esac
}

# ============ 显示帮助信息 ============
show_help() {
  echo "用法: bash $0 [选项] [参数]"
  echo ""
  echo "选项:"
  echo "  -o           开启 warp-go Socks5 代理"
  echo "  -c           关闭 warp-go Socks5 代理"
  echo "  -p [PORT]    修改 Socks5 端口"
  echo "  -u           卸载 warp-go"
  echo "  -h           显示此帮助信息"
  echo ""
  echo "示例:"
  echo "  bash $0           # 显示交互式菜单"
  echo "  bash $0 -o        # 开启代理"
  echo "  bash $0 -c        # 关闭代理"
  echo "  bash $0 -p 40001  # 修改端口为 40001"
  echo "  bash $0 -u        # 卸载"
}

# ============ 主程序 ============
main() {
  # 检查是否有命令行参数
  if [ $# -eq 0 ]; then
    # 无参数，显示菜单
    check_root
    check_operating_system
    check_arch
    check_dependencies
    check_virt
    ip4_info
    ip6_info
    check_warpgo_status
    show_menu
  else
    # 有参数，执行命令
    case "$1" in
      -o)
        check_root
        start_warpgo
        ;;
      -c)
        check_root
        stop_warpgo
        ;;
      -p)
        check_root
        modify_port "$2"
        ;;
      -u)
        check_root
        uninstall_warpgo
        ;;
      -h|--help)
        show_help
        ;;
      *)
        error "未知选项: $1\n使用 -h 查看帮助"
        ;;
    esac
  fi
}

# 运行主程序
main "$@"
