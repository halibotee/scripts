#!/usr/bin/env bash

# ax-warpsocket5.sh - WARP Socks5和全局代理管理脚本
# 版本: 1.0.0
# 功能: 管理WireProxy Socks5代理和WARP全局代理

VERSION='1.0.0'

# 环境变量设置
export DEBIAN_FRONTEND=noninteractive

# 颜色函数
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; }  # 红色
info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
reading() { read -rp "$(info "$1")" "$2"; }

# 清理函数
cleanup_resources() {
  rm -f /tmp/{ip,wireguard-go-*,best_mtu,statistics} 2>/dev/null
  exit 0
}

trap cleanup_resources EXIT INT TERM

# 检查root权限
check_root() {
  [ "$(id -u)" != 0 ] && error " 必须以root方式运行脚本，可以输入 sudo -i 后重新运行"
}

# 检测操作系统
check_operating_system() {
  if [ -s /etc/os-release ]; then
    SYS="$(grep -i pretty_name /etc/os-release | cut -d \" -f2)"
  elif [ -x "$(type -p hostnamectl)" ]; then
    SYS="$(hostnamectl | grep -i system | cut -d : -f2)"
  elif [ -x "$(type -p lsb_release)" ]; then
    SYS="$(lsb_release -sd)"
  elif [ -s /etc/lsb-release ]; then
    SYS="$(grep -i description /etc/lsb-release | cut -d \" -f2)"
  elif [ -s /etc/redhat-release ]; then
    SYS="$(grep . /etc/redhat-release)"
  elif [ -s /etc/issue ]; then
    SYS="$(grep . /etc/issue | cut -d '\' -f1 | sed '/^[ ]*$/d')"
  fi

  REGEX=("debian" "ubuntu" "centos|red hat|kernel|alma|rocky" "alpine" "arch linux|endeavouros" "fedora")
  RELEASE=("Debian" "Ubuntu" "CentOS" "Alpine" "Arch" "Fedora")

  for int in "${!REGEX[@]}"; do
    [[ "${SYS,,}" =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
  done

  # 针对各厂运的订制系统
  if [ -z "$SYSTEM" ]; then
    [ -x "$(type -p yum)" ] && int=2 && SYSTEM='CentOS' || error " 不支持的操作系统: $SYS"
  fi
}

# 判断虚拟化
check_virt() {
  if [ "$1" = 'Alpine' ]; then
    VIRT=$(virt-what | tr '\n' ' ')
  else
    [ "$(type -p systemd-detect-virt)" ] && VIRT=$(systemd-detect-virt)
    [[ -z "$VIRT" && -x "$(type -p hostnamectl)" ]] && VIRT=$(hostnamectl | awk '/Virtualization:/{print $NF}')
  fi
}

# 获取IP信息
ip_info() {
  local CHECK_46="$1"
  if [[ "$2" =~ ^[0-9]+$ ]]; then
    local INTERFACE_SOCK5="--proxy socks5h://127.0.0.1:$2"
  elif [[ "$2" =~ ^[[:alnum:]]+$ ]]; then
    local INTERFACE_SOCK5="--interface $2"
  fi

  [ "$CHECK_46" = '6' ] && CHOOSE_IP_API='https://api-ipv6.ip.sb/geoip' || CHOOSE_IP_API='https://ipinfo.io/ip'
  IP_TRACE=$(curl --retry 2 -ksm5 $INTERFACE_SOCK5 https://www.cloudflare.com/cdn-cgi/trace | awk -F '=' '/^warp=/{print $NF}')
  if [ -n "$IP_TRACE" ]; then
    local API_IP=$(curl --retry 2 -ksm5 $INTERFACE_SOCK5 --user-agent Mozilla $CHOOSE_IP_API | sed 's/.*"ip":"\([^"]\+\)".*/\1/')
    [[ -n "$API_IP" && ! "$API_IP" =~ error[[:space:]]+code:[[:space:]]+1015 ]] && local IP_JSON=$(curl --retry 2 -ksm5 https://ip.forvps.gq/${API_IP}) || unset IP_JSON
    IP_JSON=${IP_JSON:-"$(curl --retry 3 -ks${CHECK_46}m5 $INTERFACE_SOCK5 --user-agent Mozilla https://ifconfig.co/json)"}

    if [ -n "$IP_JSON" ]; then
      local WAN=$(sed -En 's/.*"(ip|query)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_JSON")
      local COUNTRY=$(sed -En 's/.*"country":[ ]*"([^"]+)".*/\1/p' <<< "$IP_JSON")
      local ASNORG=$(sed -En 's/.*"(isp|asn_org)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_JSON")
    fi
  fi

  echo -e "trace=$IP_TRACE@\nip=$WAN@\ncountry=$COUNTRY@\nasnorg=$ASNORG\n"
}

# 获取IP信息 - WireProxy
get_wireproxy_ip() {
  unset WIREPROXY_SOCKS5 WIREPROXY_PORT WIREPROXY_WAN4 WIREPROXY_COUNTRY4 WIREPROXY_ASNORG4
  WIREPROXY_SOCKS5=$(ss -nltp 2>/dev/null | awk '/"wireproxy"/{print $4}')
  if [ -n "$WIREPROXY_SOCKS5" ]; then
    WIREPROXY_PORT=$(cut -d: -f2 <<< "$WIREPROXY_SOCKS5")
    local IP_RESULT4=$(ip_info 4 "$WIREPROXY_PORT")
    WIREPROXY_TRACE4=$(expr "$IP_RESULT4" : '.*trace=\([^@]*\).*')
    WIREPROXY_WAN4=$(expr "$IP_RESULT4" : '.*ip=\([^@]*\).*')
    WIREPROXY_COUNTRY4=$(expr "$IP_RESULT4" : '.*country=\([^@]*\).*')
    WIREPROXY_ASNORG4=$(expr "$IP_RESULT4" : '.*asnorg=\([^@]*\).*')
    
    local IP_RESULT6=$(ip_info 6 "$WIREPROXY_PORT")
    WIREPROXY_TRACE6=$(expr "$IP_RESULT6" : '.*trace=\([^@]*\).*')
    WIREPROXY_WAN6=$(expr "$IP_RESULT6" : '.*ip=\([^@]*\).*')
    WIREPROXY_COUNTRY6=$(expr "$IP_RESULT6" : '.*country=\([^@]*\).*')
    WIREPROXY_ASNORG6=$(expr "$IP_RESULT6" : '.*asnorg=\([^@]*\).*')
  fi
}

# 获取IP信息 - Client
get_client_ip() {
  unset CLIENT_SOCKS5 CLIENT_PORT CLIENT_WAN4 CLIENT_COUNTRY4 CLIENT_ASNORG4
  CLIENT_SOCKS5=$(ss -nltp 2>/dev/null | awk '/"warp-svc"/{print $4}')
  if [ -n "$CLIENT_SOCKS5" ]; then
    CLIENT_PORT=$(cut -d: -f2 <<< "$CLIENT_SOCKS5")
    local IP_RESULT4=$(ip_info 4 "$CLIENT_PORT")
    CLIENT_TRACE4=$(expr "$IP_RESULT4" : '.*trace=\([^@]*\).*')
    CLIENT_WAN4=$(expr "$IP_RESULT4" : '.*ip=\([^@]*\).*')
    CLIENT_COUNTRY4=$(expr "$IP_RESULT4" : '.*country=\([^@]*\).*')
    CLIENT_ASNORG4=$(expr "$IP_RESULT4" : '.*asnorg=\([^@]*\).*')
    
    local IP_RESULT6=$(ip_info 6 "$CLIENT_PORT")
    CLIENT_TRACE6=$(expr "$IP_RESULT6" : '.*trace=\([^@]*\).*')
    CLIENT_WAN6=$(expr "$IP_RESULT6" : '.*ip=\([^@]*\).*')
    CLIENT_COUNTRY6=$(expr "$IP_RESULT6" : '.*country=\([^@]*\).*')
    CLIENT_ASNORG6=$(expr "$IP_RESULT6" : '.*asnorg=\([^@]*\).*')
  fi
}

# 获取本机IP信息
get_native_ip() {
  unset WAN4 COUNTRY4 ASNORG4 WAN6 COUNTRY6 ASNORG6
  
  local IP_RESULT4=$(curl --retry 2 -4 -ksm5 --user-agent Mozilla https://ifconfig.co/json 2>/dev/null)
  if [ -n "$IP_RESULT4" ]; then
    WAN4=$(sed -En 's/.*"(ip|query)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_RESULT4")
    COUNTRY4=$(sed -En 's/.*"country":[ ]*"([^"]+)".*/\1/p' <<< "$IP_RESULT4")
    ASNORG4=$(sed -En 's/.*"(isp|asn_org)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_RESULT4")
  fi
  
  local IP_RESULT6=$(curl --retry 2 -6 -ksm5 --user-agent Mozilla https://ifconfig.co/json 2>/dev/null)
  if [ -n "$IP_RESULT6" ]; then
    WAN6=$(sed -En 's/.*"(ip|query)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_RESULT6")
    COUNTRY6=$(sed -En 's/.*"country":[ ]*"([^"]+)".*/\1/p' <<< "$IP_RESULT6")
    ASNORG6=$(sed -En 's/.*"(isp|asn_org)":[ ]*"([^"]+)".*/\2/p' <<< "$IP_RESULT6")
  fi
}

# 检查WireProxy状态
check_wireproxy_status() {
  if [ -x "$(type -p wireproxy)" ]; then
    if ss -nltp 2>/dev/null | awk '{print $NF}' | awk -F \" '{print $2}' | grep -q wireproxy; then
      WIREPROXY_STATUS="已开启"
      get_wireproxy_ip
    else
      WIREPROXY_STATUS="已安装，状态为断开连接"
    fi
  else
    WIREPROXY_STATUS="未安装"
  fi
}

# 检查Client状态
check_client_status() {
  if [ -x "$(type -p warp-cli)" ]; then
    local CLIENT_CONNECTED=$(warp-cli --accept-tos status 2>/dev/null | awk '/Status update/{for (i=0; i<NF; i++) if ($i=="update:") {print $(i+1)}}')
    if [ "$CLIENT_CONNECTED" = 'Connected' ]; then
      local CLIENT_MODE=$(warp-cli --accept-tos settings 2>/dev/null | awk '/Mode:/{for (i=0; i<NF; i++) if ($i=="Mode:") {print $(i+1)}}')
      if [ "$CLIENT_MODE" = 'Warp' ]; then
        CLIENT_STATUS="已开启 (WARP全局模式)"
        get_client_ip
      else
        CLIENT_STATUS="已开启 (Proxy模式，非全局)"
      fi
    else
      CLIENT_STATUS="已安装，断开状态"
    fi
  else
    CLIENT_STATUS="未安装"
  fi
}

# 显示系统信息
show_info() {
  clear
  echo "---------------------------------------------------------"
  info "版本:$VERSION"
  info "系统信息:"
  info "\t 当前操作系统:$SYS"
  info "\t 内核:$(uname -r)"
  info "\t 处理器架构:$(uname -m)"
  info "\t 虚拟化:$VIRT "
  info "\t IPv4: $WAN4 $COUNTRY4  $ASNORG4 "
  info "\t IPv6: $WAN6 $COUNTRY6  $ASNORG6 "
  
  # 显示WireProxy状态
  if [ "$WIREPROXY_STATUS" = "已开启" ]; then
    info "\t WARP Free WireProxy $WIREPROXY_STATUS\t 本地 Socks5: $WIREPROXY_SOCKS5"
    info "\t IPv4: $WIREPROXY_WAN4 $WIREPROXY_COUNTRY4 $WIREPROXY_ASNORG4"
    info "\t IPv6: $WIREPROXY_WAN6 $WIREPROXY_COUNTRY6 $WIREPROXY_ASNORG6 "
  else
    info "\t WireProxy $WIREPROXY_STATUS "
  fi
  
  # 显示Client状态  
  if [[ "$CLIENT_STATUS" =~ "已开启" ]]; then
    info "\t Client $CLIENT_STATUS\t 本地 Socks5: $CLIENT_SOCKS5"
    info "\t IPv4: $CLIENT_WAN4 $CLIENT_COUNTRY4 $CLIENT_ASNORG4"
    info "\t IPv6: $CLIENT_WAN6 $CLIENT_COUNTRY6 $CLIENT_ASNORG6 "
  else
    info "\t Client $CLIENT_STATUS "
  fi
  
  echo "---------------------------------------------------------"
}

# 开启 WireProxy (Socks5代理)
enable_wireproxy() {
  if [ ! -x "$(type -p wireproxy)" ]; then
    error " WireProxy 未安装，请先使用 warp.sh 安装"
  fi
  
  info " 正在启动 WireProxy Socks5 代理..."
  
  if [ "$SYSTEM" = "Alpine" ]; then
    rc-service wireproxy start >/dev/null 2>&1
  else
    systemctl start wireproxy >/dev/null 2>&1
  fi
  
  sleep 2
  
  if ss -nltp 2>/dev/null | awk '{print $NF}' | awk -F \" '{print $2}' | grep -q wireproxy; then
    get_wireproxy_ip
    info " ✓ WireProxy Socks5 代理已成功启动"
    info " 本地 Socks5: $WIREPROXY_SOCKS5"
    info " IPv4: $WIREPROXY_WAN4 $WIREPROXY_COUNTRY4 $WIREPROXY_ASNORG4"
    info " IPv6: $WIREPROXY_WAN6 $WIREPROXY_COUNTRY6 $WIREPROXY_ASNORG6"
  else
    error " ✗ WireProxy 启动失败"
  fi
}

# 关闭 WireProxy (Socks5代理)
disable_wireproxy() {
  if [ ! -x "$(type -p wireproxy)" ]; then
    warning " WireProxy 未安装"
    return 1
  fi
  
  info " 正在关闭 WireProxy Socks5 代理..."
  
  if [ "$SYSTEM" = "Alpine" ]; then
    rc-service wireproxy stop >/dev/null 2>&1
  else
    systemctl stop wireproxy >/dev/null 2>&1
  fi
  
  sleep 1
  
  if ! ss -nltp 2>/dev/null | awk '{print $NF}' | awk -F \" '{print $2}' | grep -q wireproxy; then
    info " ✓ WireProxy Socks5 代理已关闭"
  else
    warning " ✗ WireProxy 关闭失败"
  fi
}

# 开启 Client 全局代理
enable_client_global() {
  if [ ! -x "$(type -p warp-cli)" ]; then
    error " WARP Client 未安装，请先使用 warp.sh 安装"
  fi
  
  info " 正在启动 WARP Client 全局代理..."
  
  # 确保模式为 Warp (全局模式)
  local CURRENT_MODE=$(warp-cli --accept-tos settings 2>/dev/null | awk '/Mode:/{for (i=0; i<NF; i++) if ($i=="Mode:") {print $(i+1)}}')
  if [ "$CURRENT_MODE" != "Warp" ]; then
    info " 设置为 WARP 全局模式..."
    warp-cli --accept-tos mode warp >/dev/null 2>&1
    sleep 1
  fi
  
  # 连接
  warp-cli --accept-tos connect >/dev/null 2>&1
  sleep 2
  
  local CLIENT_CONNECTED=$(warp-cli --accept-tos status 2>/dev/null | awk '/Status update/{for (i=0; i<NF; i++) if ($i=="update:") {print $(i+1)}}')
  if [ "$CLIENT_CONNECTED" = 'Connected' ]; then
    get_client_ip
    info " ✓ WARP Client 全局代理已成功启动"
    info " IPv4: $CLIENT_WAN4 $CLIENT_COUNTRY4 $CLIENT_ASNORG4"
    info " IPv6: $CLIENT_WAN6 $CLIENT_COUNTRY6 $CLIENT_ASNORG6"
  else
    error " ✗ WARP Client 连接失败"
  fi
}

# 关闭 Client 全局代理
disable_client_global() {
  if [ ! -x "$(type -p warp-cli)" ]; then
    warning " WARP Client 未安装"
    return 1
  fi
  
  info " 正在关闭 WARP Client 全局代理..."
  
  warp-cli --accept-tos disconnect >/dev/null 2>&1
  sleep 1
  
  local CLIENT_CONNECTED=$(warp-cli --accept-tos status 2>/dev/null | awk '/Status update/{for (i=0; i<NF; i++) if ($i=="update:") {print $(i+1)}}')
  if [ "$CLIENT_CONNECTED" != 'Connected' ]; then
    info " ✓ WARP Client 全局代理已关闭"
  else
    warning " ✗ WARP Client 关闭失败"
  fi
}

# 卸载功能
uninstall() {
  warning " 警告: 此操作将卸载 WireProxy 和 WARP Client"
  reading " 确认卸载请按 [y]，其他键取消: " CONFIRM
  
  if [[ "${CONFIRM,,}" != 'y' ]]; then
    info " 已取消卸载"
    return 0
  fi
  
  info " 开始卸载..."
  
  # 卸载 WireProxy
  if [ -x "$(type -p wireproxy)" ]; then
    info " 正在卸载 WireProxy..."
    if [ "$SYSTEM" = "Alpine" ]; then
      rc-update del wireproxy default >/dev/null 2>&1
      rc-service wireproxy stop >/dev/null 2>&1
      rm -f /etc/init.d/wireproxy
    else
      systemctl disable --now wireproxy >/dev/null 2>&1
    fi
    rm -rf /usr/bin/wireproxy /lib/systemd/system/wireproxy.service /etc/wireguard/proxy.conf
    info " ✓ WireProxy 卸载完成"
  fi
  
  # 卸载 WARP Client
  if [ -x "$(type -p warp-cli)" ]; then
    info " 正在卸载 WARP Client..."
    warp-cli --accept-tos disconnect >/dev/null 2>&1
    warp-cli --accept-tos delete >/dev/null 2>&1
    
    if [ "$SYSTEM" = "Debian" ] || [ "$SYSTEM" = "Ubuntu" ]; then
      apt-get purge -y cloudflare-warp >/dev/null 2>&1
      rm -f /etc/apt/sources.list.d/cloudflare-client.list
      rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    elif [ "$SYSTEM" = "CentOS" ] || [ "$SYSTEM" = "Fedora" ]; then
      yum remove -y cloudflare-warp >/dev/null 2>&1
    fi
    info " ✓ WARP Client 卸载完成"
  fi
  
  # 清理配置文件
  info " 清理配置文件..."
  rm -rf /etc/wireguard/warp-account.conf /etc/wireguard/info.log
  [[ -e /etc/wireguard && -z "$(ls -A /etc/wireguard/)" ]] && rmdir /etc/wireguard
  
  info " ✓ 卸载完成"
}

# 显示菜单
show_menu() {
  # 更新状态信息
  get_native_ip
  check_wireproxy_status
  check_client_status
  
  show_info
  
  hint " 1）开启 warp socket5代理"
  hint " 2）开启 warp全局代理"
  hint " 3）关闭 warp socket5代理"
  hint " 4）关闭 warp全局代理"
  hint " 5）卸载"
  hint " 0）退出"
  reading " 请选择: " CHOICE
  
  case "$CHOICE" in
    1)
      enable_wireproxy
      ;;
    2)
      enable_client_global
      ;;
    3)
      disable_wireproxy
      ;;
    4)
      disable_client_global
      ;;
    5)
      uninstall
      ;;
    0)
      info " 退出脚本"
      exit 0
      ;;
    *)
      warning " 请输入正确数字 [0-5]"
      sleep 1
      show_menu
      ;;
  esac
  
  echo ""
  reading " 按回车键继续..." DUMMY
  show_menu
}

# 主程序
main() {
  check_root
  check_operating_system
  check_virt "$SYSTEM"
  
  # 命令行参数处理
  case "$1" in
    -s)
      # 开启 warp socket5代理
      get_native_ip
      check_wireproxy_status
      enable_wireproxy
      ;;
    -w)
      # 开启 warp全局代理
      get_native_ip
      check_client_status
      enable_client_global
      ;;
    -cs)
      # 关闭 warp socket5代理
      disable_wireproxy
      ;;
    -cw)
      # 关闭 warp全局代理
      disable_client_global
      ;;
    -u)
      # 卸载
      uninstall
      ;;
    *)
      # 默认显示菜单
      show_menu
      ;;
  esac
}

# 运行主程序
main "$@"
