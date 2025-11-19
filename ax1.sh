#!/bin/bash
# ============================================================
#  AX.sh v2.4.1 (CN Fix)
#  架构：激进重构 | 语言：中文 | 修复：UDP2RAW 下载问题
# ============================================================

# --- 0. 全局配置与辅助函数 ---
SCRIPT_VERSION="2.4.1 CN"
DEBUG_LOG="/root/ax_debug.log"

# 核心目录路径
DIR_XRAY="/etc/xray";     DIR_HY2="/etc/hysteria2"
DIR_KCP="/etc/kcptun";    DIR_UDP="/etc/udp2raw"
DIR_CERT="/etc/ax-certs"

# 颜色定义
C_RED="\033[0;31m"; C_GREEN="\033[0;32m"; C_YELLOW="\033[0;33m"; C_CYAN="\033[0;36m"; C_RESET="\033[0m"
info() { echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[错误]${C_RESET} $*"; }
die()  { err "$*"; exit 1; }

# 调试模式
if [[ "$1" == "--debug" ]]; then
    exec 19>>"$DEBUG_LOG"; export BASH_XTRACEFD=19; set -x
    trap 'echo "[ERR] Line $LINENO: $BASH_COMMAND" >&19' ERR
fi

# --- 1. 依赖检查与系统核心 ---
check_deps() {
    local deps=(curl wget tar unzip jq openssl uuidgen socat)
    local missing=()
    for d in "${deps[@]}"; do command -v "$d" &>/dev/null || missing+=("$d"); done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "正在安装缺少的依赖组件: ${missing[*]}"
        if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y "${deps[@]}"
        elif command -v yum &>/dev/null; then yum install -y epel-release && yum install -y "${deps[@]}"
        elif command -v dnf &>/dev/null; then dnf install -y "${deps[@]}"
        else die "不支持的操作系统，请手动安装: ${deps[*]}"; fi
    fi
    mkdir -p "$DIR_XRAY" "$DIR_HY2" "$DIR_KCP" "$DIR_UDP" "$DIR_CERT"
}

get_ip() { curl -s4m3 ip.sb || curl -s4m3 ipinfo.io/ip; }
get_port() { 
    local p; while true; do p=$((RANDOM % 55535 + 10000)); 
    if ! ss -tuln | grep -q ":$p "; then echo "$p"; return; fi; done 
}
input() { read -p "$(echo -e "$1 [默认: $2]: ")" v; echo "${v:-$2}"; }
menu_sel() { 
    local prompt="$1"; shift; local opts=("$@")
    echo -e "\n${C_CYAN}$prompt${C_RESET}"
    for i in "${!opts[@]}"; do echo "  $((i+1)). ${opts[$i]}"; done
    read -p "请选择 [1-${#opts[@]}]: " c; 
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 1 ] && [ "$c" -le "${#opts[@]}" ] && echo "${opts[$((c-1))]}" || echo "${opts[0]}"
}

# --- 2. 通用安装器 (已修复 UDP2RAW 逻辑) ---
install_bin() {
    local repo=$1 pattern=$2 dest_dir=$3 bin_name=$4 type=$5 # type: zip/tar/bin
    [ -f "$dest_dir/$bin_name" ] && return 0
    info "正在安装 $bin_name (源: $repo)..."
    
    # 获取下载链接
    local url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | jq -r --arg p "$pattern" '.assets[]|select(.name|test($p))|.browser_download_url' | head -1)
    [ -z "$url" ] && die "未找到 $repo 的发布资源 (匹配规则: $pattern)"
    
    local tmp="/tmp/ax_dl_$(date +%s)"; curl -L -o "$tmp" "$url" || die "下载失败"
    
    case "$type" in
        zip) unzip -o "$tmp" -d "$dest_dir" ;;
        tar) tar -xzf "$tmp" -C "$dest_dir" ;;
        bin) mv "$tmp" "$dest_dir/$bin_name" ;;
    esac
    
    # --- 特殊后续处理 ---
    # 1. Xray: 复制 Geo 文件
    [ "$bin_name" == "xray" ] && cp -n "$dest_dir/geoip.dat" "$DIR_HY2/" 2>/dev/null
    
    # 2. UDP2RAW: 提取并重命名 amd64 二进制 (因为压缩包里包含多个架构)
    if [ "$bin_name" == "udp2raw" ]; then
        if [ -f "$dest_dir/udp2raw_amd64" ]; then
            mv "$dest_dir/udp2raw_amd64" "$dest_dir/udp2raw"
        fi
    fi
    
    chmod +x "$dest_dir/$bin_name"
    rm -f "$tmp"
}

update_all() {
    # Xray: 保持不变
    install_bin "XTLS/Xray-core" "linux-64.zip" "$DIR_XRAY" "xray" "zip"
    # Hysteria2: 保持不变
    install_bin "apernet/hysteria" "linux-amd64" "$DIR_HY2" "hysteria" "bin"
    # KCPTUN: 保持不变
    install_bin "xtaci/kcptun" "linux-amd64" "$DIR_KCP" "kcptun_server" "tar"
    
    # UDP2RAW: [修复] 匹配规则改为 "tar.gz"，不再匹配 "amd64"
    install_bin "wangyu-/udp2raw" "tar.gz" "$DIR_UDP" "udp2raw" "tar"
    
    # 生成通用的 Systemd 模板
    create_systemd "ax-xray" "$DIR_XRAY/xray -c $DIR_XRAY/xray_%i.json"
    create_systemd "ax-hysteria2" "$DIR_HY2/hysteria -c $DIR_HY2/hy2_%i.json server"
    create_systemd "ax-kcptun" "$DIR_KCP/kcptun_server -c $DIR_KCP/kcptun_%i.json"
    create_systemd "ax-udp2raw" "$DIR_UDP/udp2raw --conf-file $DIR_UDP/udp2raw_%i.conf"
    systemctl daemon-reload
}

create_systemd() {
    local name=$1 cmd=$2
    cat > "/etc/systemd/system/${name}@.service" <<EOF
[Unit]
Description=$name instance %i
After=network.target
[Service]
Type=simple
ExecStart=$cmd
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
[Install]
WantedBy=multi-user.target
EOF
}

# --- 3. 配置文件构建器 (纯 JQ 实现 + WARP 注入) ---

# 构建 Xray 配置
build_xray_conf() {
    local file=$1 type=$2 port=$3 uuid=$4 arg1=$5 arg2=$6 warp_state=$7
    
    local json='{log:{loglevel:"warning"},inbounds:[{port:($p|tonumber),listen:"0.0.0.0",tag:"in",sniffing:{enabled:true,destOverride:["http","tls","quic"]}}],outbounds:[{protocol:"freedom",tag:"direct"},{protocol:"blackhole",tag:"block"}],routing:{domainStrategy:"IPIfNonMatch",rules:[{type:"field",outboundTag:"block",domain:["geosite:category-ads-all"]}]}}'
    
    case "$type" in
        reality)
            json=$(echo "$json" | jq --arg id "$uuid" --arg sni "$arg1" --arg pk "$arg2" '.inbounds[0] += {protocol:"vless",settings:{clients:[{id:$id,flow:"xtls-rprx-vision"}],decryption:"none"},streamSettings:{network:"tcp",security:"reality",realitySettings:{show:false,fingerprint:"chrome",target:($sni+":443"),serverNames:[$sni],privateKey:$pk,shortIds:[(""+($id|split("-")[0]))]}}}') ;;
        mkcp)
            json=$(echo "$json" | jq --arg id "$uuid" --arg seed "$arg1" --arg hd "$arg2" '.inbounds[0] += {protocol:"vless",settings:{clients:[{id:$id}],decryption:"none"},streamSettings:{network:"kcp",kcpSettings:{seed:$seed,header:{type:$hd},mtu:1350,tti:20,uplinkCapacity:5,downlinkCapacity:20,congestion:false}}}') ;;
        ss)
            json=$(echo "$json" | jq --arg m "$arg1" --arg p "$arg2" '.inbounds[0] += {protocol:"shadowsocks",settings:{method:$m,password:$p,network:"tcp,udp"}}') ;;
    esac
    
    if [[ "$warp_state" == "y" ]]; then
        json=$(echo "$json" | jq '.outbounds += [{protocol:"socks",tag:"warp",settings:{servers:[{address:"127.0.0.1",port:40000}]}}] | .routing.rules = ([{type:"field",outboundTag:"warp",domain:["geosite:google","geosite:openai","suffix:openai.com"]}] + .routing.rules)')
    fi
    
    echo "$json" | jq --arg p "$port" '.' > "$file"
}

# 构建 Hysteria2 配置
build_hy2_conf() {
    local file=$1 port=$2 cert=$3 key=$4 pass=$5 warp_state=$6
    
    local json_args=(--arg p ":$port" --arg c "$cert" --arg k "$key" --arg pw "$pass")
    local base_tmpl='{listen: $p, tls: {cert: $c, key: $k}, auth: {type: "password", password: $pw}, masquerade: {type: "proxy", proxy: {url: "https://bing.com", rewriteHost: true}}, ignoreClientBandwidth: false}'
    
    if [[ "$warp_state" == "y" ]]; then
        base_tmpl+=' + {outbounds: [{name: "warp", type: "socks5", socks5: {addr: "127.0.0.1:40000"}}], acl: {inline: ["warp(geosite:google)", "warp(geosite:openai)", "direct(all)"]}}'
    fi

    jq -n "${json_args[@]}" "$base_tmpl" > "$file"
}

build_kcptun_conf() {
    local file=$1 port=$2 target=$3 key=$4
    jq -n --arg p ":$port" --arg t "$target" --arg k "$key" \
    '{listen: $p, target: $t, key: $k, crypt: "aes-128", mode: "fast3", mtu: 1350, sndwnd: 512, rcvwnd: 512, datashard: 10, parityshard: 3, dscp: 46, nocomp: true}' > "$file"
}

build_udp2raw_conf() {
    local file=$1 port=$2 target=$3 pass=$4
    echo "-s -l 0.0.0.0:$port -r $target -k $pass --raw-mode faketcp --cipher-mode aes128cbc --auth-mode hmac_sha1 -a" > "$file"
}

# --- 4. 实例生命周期管理 ---
create_instance() {
    local flavor=$1  # reality, mkcp, ss, hy2, kcptun, udp2raw, chain_hy2
    local id=$(get_next_id "$flavor")
    
    info "正在创建 $flavor 实例 (ID: $id)..."
    local port=$(input "请输入监听端口" "$(get_port)")
    local warp_state="n"
    
    if [[ "$flavor" =~ ^(reality|mkcp|ss|hy2|chain_hy2)$ ]]; then
        warp_state=$(input "是否启用 WARP 分流? (需先通过菜单安装 WARP 客户端) [y/N]" "n")
    fi

    local pass uuid cert key
    
    case "$flavor" in
        reality)
            local sni=$(input "请输入 SNI (域名)" "www.apple.com")
            local keys=$("$DIR_XRAY/xray" x25519)
            local pk=$(echo "$keys" | grep -i Private | awk '{print $3}'); local pub=$(echo "$keys" | grep -i Public | awk '{print $3}')
            uuid=$(uuidgen)
            build_xray_conf "$DIR_XRAY/xray_$id.json" "reality" "$port" "$uuid" "$sni" "$pk" "$warp_state"
            enable_svc "ax-xray" "$id"
            info "链接: vless://$uuid@$(get_ip):$port?type=tcp&security=reality&sni=$sni&pbk=$pub&fp=chrome#Reality_$id"
            ;;
        mkcp)
            uuid=$(uuidgen); local seed=$(input "Seed" "axsh")
            build_xray_conf "$DIR_XRAY/xray_$id.json" "mkcp" "$port" "$uuid" "$seed" "none" "$warp_state"
            enable_svc "ax-xray" "$id"
            ;;
        ss)
            local method="aes-256-gcm"; local pw=$(openssl rand -base64 16)
            build_xray_conf "$DIR_XRAY/xray_$id.json" "ss" "$port" "" "$method" "$pw" "$warp_state"
            enable_svc "ax-xray" "$id"
            info "链接: ss://$(echo -n "$method:$pw" | base64 | tr -d '\n')@$(get_ip):$port#SS_$id"
            ;;
        hy2)
            cert="$DIR_HY2/self_$id.crt"; key="$DIR_HY2/self_$id.key"
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$key" -out "$cert" -days 3650 -subj "/CN=bing.com" &>/dev/null
            pass=$(input "请输入密码" "myhy2pass")
            build_hy2_conf "$DIR_HY2/hy2_$id.json" "$port" "$cert" "$key" "$pass" "$warp_state"
            enable_svc "ax-hysteria2" "$id"
            info "链接: hysteria2://$pass@$(get_ip):$port?insecure=1&sni=bing.com#Hy2_$id"
            ;;
        chain_hy2)
            local iport=$(get_port); local pw=$(uuidgen); local raw_pw="raw_$(uuidgen)"
            cert="$DIR_HY2/self_c$id.crt"; key="$DIR_HY2/self_c$id.key"
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$key" -out "$cert" -days 3650 -subj "/CN=bing.com" &>/dev/null
            build_hy2_conf "$DIR_HY2/hy2_c$id.json" "$iport" "$cert" "$key" "$pw" "$warp_state"
            build_udp2raw_conf "$DIR_UDP/udp2raw_c$id.conf" "$port" "127.0.0.1:$iport" "$raw_pw"
            enable_svc "ax-hysteria2" "c$id"
            enable_svc "ax-udp2raw" "c$id"
            info "串联已创建. 公网端口: $port (UDP2RAW) -> 本地: $iport (Hy2)"
            ;;
    esac
}

get_next_id() {
    local type=$1; local i=1
    while [[ -f "$DIR_XRAY/xray_${i}.json" || -f "$DIR_HY2/hy2_${i}.json" || -f "$DIR_UDP/udp2raw_${i}.conf" ]]; do ((i++)); done
    echo "$i"
}

enable_svc() { systemctl enable --now "${1}@${2}.service"; }

# --- 5. 统一服务管理器 ---
manage_services() {
    while true; do
        clear; echo -e "=== ${C_CYAN}当前运行服务${C_RESET} ==="
        local list=()
        # 自动发现
        for f in "$DIR_XRAY"/*.json; do [[ -f "$f" ]] && list+=("Xray|ax-xray|$(basename $f .json | sed 's/xray_//')|$f"); done
        for f in "$DIR_HY2"/*.json; do [[ -f "$f" ]] && list+=("Hy2|ax-hysteria2|$(basename $f .json | sed 's/hy2_//')|$f"); done
        for f in "$DIR_UDP"/*.conf; do [[ -f "$f" ]] && list+=("UDP2RAW|ax-udp2raw|$(basename $f .conf | sed 's/udp2raw_//')|$f"); done
        for f in "$DIR_KCP"/*.json; do [[ -f "$f" ]] && list+=("KCPTUN|ax-kcptun|$(basename $f .json | sed 's/kcptun_//')|$f"); done
        
        if [ ${#list[@]} -eq 0 ]; then echo "暂无运行实例。"; else
            for i in "${!list[@]}"; do
                IFS='|' read -r name svc id path <<< "${list[$i]}"
                local status=$(systemctl is-active "${svc}@${id}" 2>/dev/null || echo "inactive")
                [[ "$status" == "active" ]] && color="$C_GREEN" || color="$C_RED"
                local warp_tag=""; grep -q "warp" "$path" && warp_tag="[WARP]"
                echo -e "$((i+1)). ${color}[$status]${C_RESET} $name #$id $warp_tag"
            done
        fi
        
        echo -e "\n[N] 新建实例 | [D] 删除 | [L] 日志 | [R] 重启 | [0] 退出"
        read -p "请选择操作: " act
        
        if [[ "$act" =~ ^[0-9]+$ ]] && [ "$act" -le ${#list[@]} ] && [ "$act" -gt 0 ]; then
            IFS='|' read -r name svc id path <<< "${list[$((act-1))]}"
            echo "配置文件: $path"; cat "$path"
            read -p "按回车继续..."
        elif [[ "$act" == "N" || "$act" == "n" ]]; then
            local type=$(menu_sel "请选择协议类型" "reality" "mkcp" "ss" "hy2" "chain_hy2" "udp2raw" "kcptun")
            create_instance "$type"
        elif [[ "$act" == "0" ]]; then return
        elif [[ "$act" =~ ^[DLR] ]]; then
             read -p "输入序号: " idx
             IFS='|' read -r name svc id path <<< "${list[$((idx-1))]}"
             case "${act^^}" in
                D) systemctl stop "${svc}@${id}"; systemctl disable "${svc}@${id}"; rm -f "$path"; info "已删除";;
                R) systemctl restart "${svc}@${id}"; info "已重启";;
                L) journalctl -u "${svc}@${id}" -f -n 50 ;;
             esac
             sleep 1
        fi
    done
}

# --- 6. 专用外部脚本调用器 ---
run_sys_opt() {
    info "正在下载并运行 VPS 优化脚本..."
    wget --no-check-certificate -O vps_optimizert.sh "https://raw.githubusercontent.com/halibotee/scripts/main/vps_optimizert.sh" && chmod +x vps_optimizert.sh && ./vps_optimizert.sh
    read -p "按回车键继续..." -n1 -s
}

run_warp_mgr() {
    info "正在下载并运行 WARP 管理脚本..."
    wget --no-check-certificate -O CFwarp.sh "https://raw.githubusercontent.com/halibotee/warp-yg/main/CFwarp.sh" && chmod +x CFwarp.sh && ./CFwarp.sh
    read -p "按回车键继续..." -n1 -s
}

# --- 7. 全局卸载逻辑 ---
uninstall_all() {
    echo -e "\n${C_RED}=== ⚠️  危险操作 ===${C_RESET}"
    read -p "确认要卸载所有组件并清除配置吗? (输入 y 确认): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

    info "正在停止所有相关服务..."
    systemctl stop "ax-xray@*" "ax-hysteria2@*" "ax-kcptun@*" "ax-udp2raw@*" 2>/dev/null
    systemctl disable "ax-xray@*" "ax-hysteria2@*" "ax-kcptun@*" "ax-udp2raw@*" 2>/dev/null

    info "正在清理文件与配置..."
    rm -rf "$DIR_XRAY" "$DIR_HY2" "$DIR_KCP" "$DIR_UDP" "$DIR_CERT"
    rm -f /etc/systemd/system/ax-xray@.service \
          /etc/systemd/system/ax-hysteria2@.service \
          /etc/systemd/system/ax-kcptun@.service \
          /etc/systemd/system/ax-udp2raw@.service

    systemctl daemon-reload
    systemctl reset-failed
    
    info "卸载完成。外部安装的脚本 (WARP/SysOpt) 可能会残留，请按需手动卸载。"
    
    read -p "是否连同本脚本一起删除? [y/N]: " del_script
    if [[ "$del_script" == "y" || "$del_script" == "Y" ]]; then
        rm -f "$0"
        echo "脚本已自毁，再见！"
        exit 0
    fi
}

# --- 8. 主入口 ---
check_deps
while true; do
    clear
    echo -e "${C_CYAN}AX.sh v$SCRIPT_VERSION${C_RESET} (全能版)"
    echo "1. 服务管理 (创建/删除/查看)"
    echo "2. 更新核心组件 (Xray/Hy2等)"
    echo "3. 系统优化 (Halibotee版)"
    echo "4. WARP 管理 (Halibotee/YG版)"
    echo "5. ACME 证书申请"
    echo "99. 卸载脚本与服务"
    echo "0. 退出脚本"
    read -p "请选择: " opt
    case $opt in
        1) update_all; manage_services ;; 
        2) update_all; info "核心组件已更新"; sleep 1 ;;
        3) run_sys_opt ;;
        4) run_warp_mgr ;;
        5) input "请输入域名" ""; # ACME 占位
           ;;
        99) uninstall_all ;;
        0) exit 0 ;;
    esac
done
