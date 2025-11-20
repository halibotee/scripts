#!/bin/bash
# ==================================================================
# 全能隧道管理脚本 (Refactored Ultimate v2.6.0)
# 架构：OO模拟 + 泛型编程
# 修复：Text file busy, 重复下载, 配置空格, 卸载缺失, 状态显示
# ==================================================================

SCRIPT_VERSION="2.6.0-Final"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- 1. 核心注册表 (Service Registry) ---

declare -A META

# [原子服务定义]
META[hy2,name]="Hysteria2"; META[hy2,bin]="hysteria"; META[hy2,repo]="apernet/hysteria"; META[hy2,ext]="yaml"
META[hy2,dir]="/etc/hysteria2"; META[hy2,svc]="ax-hysteria2"; META[hy2,install]="mv"

META[xray,name]="Xray"; META[xray,bin]="xray"; META[xray,repo]="XTLS/Xray-core"; META[xray,ext]="json"
META[xray,dir]="/etc/xray"; META[xray,svc]="ax-xray"; META[xray,install]="unzip"

META[udp2raw,name]="UDP2RAW"; META[udp2raw,bin]="udp2raw"; META[udp2raw,repo]="wangyu-/udp2raw"; META[udp2raw,ext]="conf"
META[udp2raw,dir]="/etc/udp2raw"; META[udp2raw,svc]="ax-udp2raw"; META[udp2raw,install]="tar_udp"

META[kcptun,name]="KCPTUN"; META[kcptun,bin]="kcptun_server"; META[kcptun,repo]="xtaci/kcptun"; META[kcptun,ext]="json"
META[kcptun,dir]="/etc/kcptun"; META[kcptun,svc]="ax-kcptun"; META[kcptun,install]="tar_kcp"

# [别名定义]
META[ss,name]="Shadowsocks"; META[ss,bin]="xray"; META[ss,repo]="XTLS/Xray-core"; META[ss,ext]="json"
META[ss,dir]="/etc/xray"; META[ss,svc]="ax-xray"; META[ss,install]="unzip"

META[xray_mkcp,name]="VLESS+mKCP"; META[xray_mkcp,bin]="xray"; META[xray_mkcp,repo]="XTLS/Xray-core"; META[xray_mkcp,ext]="json"
META[xray_mkcp,dir]="/etc/xray"; META[xray_mkcp,svc]="ax-xray"; META[xray_mkcp,install]="unzip"

# [串联组合定义]
META[chain_hy2,is_chain]="true"; META[chain_hy2,parts]="hy2 udp2raw"; META[chain_hy2,name]="Hysteria2+UDP一键串联"
META[chain_vless,is_chain]="true"; META[chain_vless,parts]="xray udp2raw"; META[chain_vless,name]="VLESS_KCP+UDP一键串联"
META[chain_ss3,is_chain]="true"; META[chain_ss3,parts]="xray kcptun udp2raw"; META[chain_ss3,name]="SS+KCP+UDP 一键串联"

# 全局常量
PUBLIC_IP=""
GITHUB_API="https://api.github.com/repos"

# --- 2. 工具库 (Utils) ---

msg() { local c=$1; shift; echo -e "\033[${c}m$*\033[0m"; }
green() { msg "0;32" "$1"; }; red() { msg "0;31" "$1"; }; yellow() { msg "0;33" "$1"; }; cyan() { msg "0;36" "$1"; }
dim() { msg "2" "$1"; }; bold() { msg "1" "$1"; }
log() { echo -e "[$(date '+%H:%M:%S')] $(bold "$1")"; }

check_root() { [[ $EUID -ne 0 ]] && { red "错误: 必须 root 运行"; exit 1; }; }

install_deps() {
    local deps=("curl" "wget" "tar" "unzip" "nano" "jq" "openssl" "uuid-runtime" "socat")
    local missing=(); for cmd in "${deps[@]}"; do ! command -v "$cmd" &>/dev/null && missing+=("$cmd"); done
    if [[ ${#missing[@]} -gt 0 ]]; then log "安装依赖: ${missing[*]}"; apt-get update &>/dev/null; apt-get install -y "${missing[@]}" &>/dev/null || yum install -y "${missing[@]}" &>/dev/null; fi
}

get_ip() { [[ -z "$PUBLIC_IP" ]] && PUBLIC_IP=$(curl -s4m2 ip.sb || curl -s4m2 ipinfo.io/ip || echo "127.0.0.1"); echo "$PUBLIC_IP"; }
get_port() { local p; while true; do p=$((RANDOM%55535+10000)); ! ss -tuln | grep -q ":$p " && echo "$p" && return; done; }
gen_uuid() { uuidgen || cat /proc/sys/kernel/random/uuid; }
gen_pass() { openssl rand -base64 16; }

# --- 3. 泛型核心 (Generic Core) ---

get_ver() { 
    # 获取 GitHub Tag，增加超时防止卡死，去除首尾空格换行
    curl -s --connect-timeout 5 "$GITHUB_API/$1/releases/latest" | jq -r .tag_name | tr -d ' \n\r'
}

install_bin_generic() {
    local type=$1
    local bin=${META[$type,bin]} dir=${META[$type,dir]} repo=${META[$type,repo]} mode=${META[$type,install]}
    local ver_file="$dir/.version"
    
    # 1. 获取远程版本
    local latest=$(get_ver "$repo")
    [[ -z "$latest" || "$latest" == "null" ]] && { return 0; } # 网络失败时不阻塞脚本

    # 2. 检查本地标记 (解决重复下载问题)
    local current=""
    [[ -f "$ver_file" ]] && current=$(cat "$ver_file" | tr -d ' \n\r')
    
    if [[ -f "$dir/$bin" && "$current" == "$latest" ]]; then
        return 0 # 版本一致，静默跳过
    fi

    log "正在安装/更新 $type ($latest)..."
    
    # 3. [Fix] 解决 Text file busy: 更新前停止服务
    systemctl stop "${META[$type,svc]}*" 2>/dev/null

    mkdir -p "$dir"; local url=""
    local dl_ok=false
    
    # 4. 下载策略
    case $mode in
        mv) 
            url="https://github.com/$repo/releases/download/$latest/${bin}-linux-amd64"
            curl -L --connect-timeout 20 -o "$dir/$bin" "$url" && chmod +x "$dir/$bin" && dl_ok=true ;;
        unzip) 
            url="https://github.com/$repo/releases/download/$latest/Xray-linux-64.zip"
            curl -L --connect-timeout 20 -o /tmp/dl.zip "$url" && unzip -o /tmp/dl.zip -d "$dir" "$bin" geoip.dat geosite.dat && chmod +x "$dir/$bin" && dl_ok=true
            cp -n "$dir/geoip.dat" "/etc/hysteria2/" 2>/dev/null ;;
        tar_udp) 
            url="https://github.com/$repo/releases/download/$latest/udp2raw_binaries.tar.gz"
            curl -L --connect-timeout 20 -o /tmp/dl.tar.gz "$url" && tar -xzf /tmp/dl.tar.gz -C "$dir" udp2raw_amd64 && mv "$dir/udp2raw_amd64" "$dir/$bin" && chmod +x "$dir/$bin" && dl_ok=true ;;
        tar_kcp) 
            url="https://github.com/$repo/releases/download/$latest/kcptun-linux-amd64-${latest#v}.tar.gz"
            curl -L --connect-timeout 20 -o /tmp/dl.tar.gz "$url" && tar -xzf /tmp/dl.tar.gz -C "$dir" server_linux_amd64 && mv "$dir/server_linux_amd64" "$dir/$bin" && chmod +x "$dir/$bin" && dl_ok=true ;;
    esac

    # 5. 写入版本标记
    if $dl_ok; then
        echo "$latest" > "$ver_file"
        green "$type 更新成功。"
    else
        red "$type 下载失败。"
    fi
}

render_template() {
    local tpl_var=$1 out_file=$2
    local content="${!tpl_var}"
    shift 2
    while (( "$#" )); do
        # [Fix] 强制剔除参数中的空格，解决 UDP2RAW 启动报错
        local val=$(echo "$2" | tr -d ' ')
        content="${content//__$1__/$val}"
        shift 2
    done
    echo "$content" > "$out_file"
}

install_service() {
    local type=$1
    local svc_name=${META[$type,svc]} bin=${META[$type,bin]} dir=${META[$type,dir]} ext=${META[$type,ext]}
    local svc_file="/etc/systemd/system/${svc_name}@.service"
    [[ -f "$svc_file" ]] && return 0
    
    local exec=""
    case $type in
        hy2) exec="$dir/$bin -c $dir/hy2_%i.$ext server" ;;
        xray) exec="$dir/$bin -c $dir/xray_%i.$ext" ;;
        udp2raw) exec="$dir/$bin --conf-file $dir/udp2raw_%i.$ext" ;;
        kcptun) exec="$dir/$bin -c $dir/kcptun_%i.$ext" ;;
    esac

    cat > "$svc_file" <<EOF
[Unit]
Description=$type Service (Instance %i)
After=network.target
[Service]
Type=simple
ExecStart=$exec
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# 通用服务控制器
sys_ctl() {
    local action=$1 type=$2 id=$3
    local svcs=()
    
    # 解析依赖
    if [[ "${META[$type,is_chain]}" == "true" ]]; then
        for comp in ${META[$type,parts]}; do svcs+=("${META[$comp,svc]}@$id"); done
    else
        svcs+=("${META[$type,svc]}@$id")
    fi

    case $action in
        start|stop|restart) systemctl $action "${svcs[@]}" ;;
        enable) systemctl enable --now "${svcs[@]}" ;;
        disable) systemctl disable --now "${svcs[@]}" ;;
        status_color) 
            local all_active=true; local str=""
            for s in "${svcs[@]}"; do
                if systemctl is-active --quiet "$s"; then str+="\033[32m[运行]\033[0m "; else str+="\033[33m[停止]\033[0m "; all_active=false; fi
            done
            echo -e "$str" ;;
        log) journalctl -u "${svcs[0]}" -f ;;
    esac
}

get_existing_ids() {
    local type=$1; local scan_type=$type
    [[ "${META[$type,is_chain]}" == "true" ]] && scan_type=$(echo ${META[$type,parts]} | awk '{print $1}')
    local dir=${META[$scan_type,dir]} ext=${META[$scan_type,ext]} prefix=${scan_type}
    
    if [[ -d "$dir" ]]; then
        ls "$dir" 2>/dev/null | grep -E "^${prefix}_[0-9]+\.${ext}$" | sed -E "s/${prefix}_([0-9]+)\.${ext}/\1/" | sort -n | tr '\n' ' '
    fi
}

get_next_id() {
    local type=$1; local dir=${META[$type,dir]} ext=${META[$type,ext]}
    local i=1; while [[ -f "$dir/${type}_${i}.${ext}" ]]; do ((i++)); done; echo "$i"
}

# --- 4. 业务逻辑 (Business) ---

get_cert_path() {
    local key="/etc/ssl/private/bing.com.key" crt="/etc/ssl/private/bing.com.crt"
    mkdir -p /etc/ssl/private
    [[ ! -f "$key" ]] && openssl req -new -x509 -days 3650 -keyout "$key" -out "$crt" -subj "/CN=bing.com" -nodes &>/dev/null
    echo "$crt|$key|bing.com"
}

gen_link() {
    local type=$1 id=$2 ip=$(get_ip)
    local meta_type=$type; [[ "$type" == *"xray"* ]] && meta_type="xray"
    local conf="${META[$meta_type,dir]}/${meta_type}_${id}.${META[$meta_type,ext]}"
    [[ ! -f "$conf" ]] && echo "N/A" && return

    # 映射串联类型到基础类型以生成链接
    local link_type=$type
    [[ "$type" == "chain_hy2" ]] && link_type="hy2"
    
    if [[ "$link_type" == "hy2" || "$link_type" == "hysteria2" ]]; then
        local pass=$(grep "password:" "$conf" | awk '{print $2}')
        local port=$(grep "listen:" "$conf" | awk -F: '{print $NF}')
        echo "hysteria2://${pass}@${ip}:${port}?insecure=1&sni=bing.com#${type}_${id}"
    elif [[ "$type" == "xray_reality" ]]; then
        local uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$conf")
        local port=$(jq -r '.inbounds[0].port' "$conf")
        local pbk=$(jq -r '.inbounds[0].streamSettings.realitySettings.publicKey' "$conf")
        echo "vless://${uuid}@${ip}:${port}?security=reality&sni=www.apple.com&fp=chrome&pbk=${pbk}&type=tcp&flow=xtls-rprx-vision#Reality_${id}"
    elif [[ "$type" == "xray_mkcp" ]]; then
        local uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$conf")
        local port=$(jq -r '.inbounds[0].port' "$conf")
        echo "vless://${uuid}@${ip}:${port}?security=none&type=kcp&headerType=wechat-video#mKCP_${id}"
    elif [[ "$type" == "ss" ]]; then
        local method=$(jq -r '.inbounds[0].settings.method' "$conf")
        local pass=$(jq -r '.inbounds[0].settings.password' "$conf")
        local port=$(jq -r '.inbounds[0].port' "$conf")
        # base64 encode user:pass
        local userpass=$(echo -n "${method}:${pass}" | base64 -w 0)
        echo "ss://${userpass}@${ip}:${port}#SS_${id}"
    elif [[ "$type" == "chain_hy2" ]]; then
         echo "(组合：UDP2RAW -> 本地HY2，请查看配置文件)"
    elif [[ "$type" == "chain_vless" ]]; then
         echo "(组合：UDP2RAW -> 本地mKCP，请查看配置文件)"
    elif [[ "$type" == "chain_ss3" ]]; then
         echo "(组合：UDP2RAW -> KCPTUN -> 本地SS，请查看配置文件)"
    else
        echo "(请查看配置文件: $conf)"
    fi
}

# --- 5. 菜单系统 (Menus) ---

declare -A QUICK_MAP_TYPE QUICK_MAP_ID

show_status_summary() {
    QUICK_MAP_TYPE=(); QUICK_MAP_ID=() 
    echo "$(bold "--- 当前状态 (输入序号可直接管理) ---")"
    local idx=21
    local has_instance=false
    
    # 定义扫描顺序
    local scan_list="chain_hy2 chain_vless chain_ss3 hy2 xray_reality udp2raw kcptun"
    
    for t in $scan_list; do
        local ids=$(get_existing_ids "$t")
        [[ -z "$ids" ]] && continue
        
        local dname="${META[$t,name]}"
        [[ "$t" == "hy2" ]] && dname="Hysteria2 (独立)"
        [[ "$t" == "xray_reality" ]] && dname="VLESS+Reality"
        
        for i in $ids; do
            echo "$idx) ${dname} [ID:$i] $(sys_ctl status_color "$t" "$i")"
            QUICK_MAP_TYPE[$idx]="$t"; QUICK_MAP_ID[$idx]="$i"
            ((idx++)); has_instance=true
        done
    done
    
    if [[ "$has_instance" == false ]]; then yellow "当前没有已创建的实例。"; fi
}

# 类型管理菜单
type_manager_menu() {
    local type=$1; local title=${META[$type,name]}
    while true; do
        local ids=$(get_existing_ids "$type")
        clear; echo "=================================="
        echo "      管理/安装 $title"
        echo "=================================="
        if [[ -n "$ids" ]]; then
            echo "$(bold "--- 已存在的实例 ---")"
            for i in $ids; do echo "ID: $(bold "$i") | 状态: $(sys_ctl status_color "$type" "$i")"; done
            echo "----------------------------------"
            echo "1) 启动一个新的实例"
            echo "2) 管理一个已存在的实例"
        else
            yellow "当前没有已创建的实例。"
            echo "----------------------------------"
            echo "1) 启动一个新的实例"
        fi
        echo "0) 返回主菜单"
        read -p "请选择: " c
        case $c in
            1) [[ "${META[$type,is_chain]}" == "true" ]] && create_chain "$type" || create_instance "$type"
               read -p "按键返回..." -n1 -s ;;
            2) [[ -z "$ids" ]] && continue
               read -p "请输入实例ID: " tid
               if [[ " $ids " =~ " $tid " ]]; then
                   [[ "${META[$type,is_chain]}" == "true" ]] && menu_chain "$type" "$tid" || menu_instance "$type" "$tid"
               else red "无效ID" && sleep 1; fi ;;
            0) return ;;
        esac
    done
}

# 独立实例菜单
menu_instance() {
    local type=$1 id=$2; local meta=$type; [[ "$type" == *"xray"* ]] && meta="xray"
    local conf="${META[$meta,dir]}/${meta}_${id}.${META[$meta,ext]}"
    while true; do
        clear; echo "=================================="
        echo "      管理 ${META[$meta,name]} $(dim "$id")"
        echo "=================================="
        echo "状态: $(sys_ctl status_color "$meta" "$id")"
        cyan "链接: $(gen_link "$type" "$id")"
        echo "----------------------------------"
        echo "1) 启动/重启  2) 停止  3) 实时日志"
        echo "4) 编辑配置   99) 删除实例"
        echo "0) 返回"
        read -p "选择: " c
        case $c in
            1) sys_ctl restart "$meta" "$id" ;;
            2) sys_ctl stop "$meta" "$id" ;;
            3) sys_ctl log "$meta" "$id" ;;
            4) nano "$conf"; sys_ctl restart "$meta" "$id" ;;
            99) sys_ctl stop "$meta" "$id"; sys_ctl disable "$meta" "$id"; rm -f "$conf"; green "已删除"; return ;;
            0) return ;;
        esac; read -p "按任意键..." -n1 -s
    done
}

# 串联实例菜单
menu_chain() {
    local type=$1 id=$2; local parts=${META[$type,parts]}
    local main=$(echo $parts | awk '{print $1}')
    while true; do
        clear; echo "=================================="
        echo "   管理 ${META[$type,name]} $(dim "$id")"
        echo "=================================="
        echo "状态: $(sys_ctl status_color "$type" "$id")"
        cyan "主链接: $(gen_link "$main" "$id")"
        echo "----------------------------------"
        echo "1) 启动/重启串联  2) 停止串联"
        local i=3; for p in $parts; do echo "$i) 查看 ${META[$p,name]} 日志"; ((i++)); done
        echo "99) 删除串联      0) 返回"
        read -p "选择: " c
        local log_end=$((3 + $(echo $parts | wc -w)))
        if [[ $c -eq 1 ]]; then sys_ctl restart "$type" "$id"
        elif [[ $c -eq 2 ]]; then sys_ctl stop "$type" "$id"
        elif [[ $c -ge 3 && $c -lt $log_end ]]; then
             local idx=$((c-3)); local arr=($parts); sys_ctl log "${arr[$idx]}" "$id"
        elif [[ $c -eq 99 ]]; then
             sys_ctl stop "$type" "$id"; sys_ctl disable "$type" "$id"
             for p in $parts; do rm -f "${META[$p,dir]}/${p}_${id}.${META[$p,ext]}"; done
             green "已删除"; return
        elif [[ $c -eq 0 ]]; then return; fi
        read -p "按任意键..." -n1 -s
    done
}

# --- 6. 创建工厂 (Factory) ---

create_instance() {
    local type=$1; local meta=$type; [[ "$type" == *"xray"* ]] && meta="xray"
    local nid=$(get_next_id "$meta")
    green "创建 $type (ID: $nid)..."
    local port=$(get_port); local pass=$(gen_pass); local uuid=$(gen_uuid)
    
    case $type in
        hy2|hysteria2)
            # [Fix] 使用 awk 避免 cut 报错
            local cinfo=$(get_cert_path "n")
            local crt=$(echo "$cinfo" | awk -F'|' '{print $1}')
            local key=$(echo "$cinfo" | awk -F'|' '{print $2}')
            render_template TPL_HY2 "${META[hy2,dir]}/hy2_${nid}.yaml" \
                LISTEN ":$port" CERT "$crt" KEY "$key" PASS "$pass" ;;
        xray_reality)
            local keys=$(${META[xray,dir]}/xray x25519)
            local pk=$(echo "$keys" | grep "Private" | awk -F: '{print $2}' | tr -d ' ')
            local short=$(openssl rand -hex 4)
            render_template TPL_XRAY_REALITY "${META[xray,dir]}/xray_${nid}.json" \
                PORT "$port" UUID "$uuid" PK "$pk" SHORT "$short" ;;
        xray_mkcp)
            render_template TPL_XRAY_MKCP "${META[xray,dir]}/xray_${nid}.json" \
                PORT "$port" UUID "$uuid" ;;
        ss)
            render_template TPL_SS "${META[xray,dir]}/xray_${nid}.json" \
                PORT "$port" PASS "$pass" ;;
        udp2raw)
            render_template TPL_UDP2RAW "${META[udp2raw,dir]}/udp2raw_${nid}.conf" \
                LISTEN "0.0.0.0:$port" TARGET "127.0.0.1:22" PASS "$pass" ;;
        kcptun)
            render_template TPL_KCPTUN "${META[kcptun,dir]}/kcptun_${nid}.json" \
                LISTEN ":$port" TARGET "127.0.0.1:22" KEY "$pass" ;;
    esac
    
    sys_ctl enable "$meta" "$nid"
    sleep 2
    green "创建成功！状态: $(sys_ctl status_color "$meta" "$nid")"
    echo; gen_link "$type" "$nid"
}

create_chain() {
    local type=$1; local parts=${META[$type,parts]}
    local main=$(echo $parts | awk '{print $1}')
    local nid=$(get_next_id "$main")
    local pin=$(get_port); local pout=$(get_port); local pass=$(gen_pass)
    
    green "创建串联 $type (ID: $nid)..."
    if [[ "$type" == "chain_hy2" ]]; then
        local cinfo=$(get_cert_path "n")
        local crt=$(echo "$cinfo" | awk -F'|' '{print $1}')
        local key=$(echo "$cinfo" | awk -F'|' '{print $2}')
        render_template TPL_HY2 "${META[hy2,dir]}/hy2_${nid}.yaml" \
            LISTEN "127.0.0.1:$pin" CERT "$crt" KEY "$key" PASS "$(gen_pass)"
        render_template TPL_UDP2RAW "${META[udp2raw,dir]}/udp2raw_${nid}.conf" \
            LISTEN "0.0.0.0:$pout" TARGET "127.0.0.1:$pin" PASS "$pass"
        sys_ctl enable "chain_hy2" "$nid"
    elif [[ "$type" == "chain_vless" ]]; then
        # Xray (mKCP) -> UDP2RAW
        render_template TPL_XRAY_MKCP "${META[xray,dir]}/xray_${nid}.json" \
            PORT "$pin" UUID "$(gen_uuid)"
        # 修改监听地址为本地
        sed -i 's/"port": '"$pin"'/"port": '"$pin"', "listen": "127.0.0.1"/' "${META[xray,dir]}/xray_${nid}.json"
        
        render_template TPL_UDP2RAW "${META[udp2raw,dir]}/udp2raw_${nid}.conf" \
            LISTEN "0.0.0.0:$pout" TARGET "127.0.0.1:$pin" PASS "$pass"
        sys_ctl enable "chain_vless" "$nid"
    elif [[ "$type" == "chain_ss3" ]]; then
        # SS -> KCPTUN -> UDP2RAW
        local p_ss=$(get_port)
        local p_kcp=$pin
        
        # 1. SS (Local)
        render_template TPL_SS "${META[xray,dir]}/xray_${nid}.json" \
            PORT "$p_ss" PASS "$(gen_pass)"
        sed -i 's/"port": '"$p_ss"'/"port": '"$p_ss"', "listen": "127.0.0.1"/' "${META[xray,dir]}/xray_${nid}.json"
        
        # 2. KCPTUN (Local)
        render_template TPL_KCPTUN "${META[kcptun,dir]}/kcptun_${nid}.json" \
            LISTEN "127.0.0.1:$p_kcp" TARGET "127.0.0.1:$p_ss" KEY "$(gen_pass)"
            
        # 3. UDP2RAW (Public)
        render_template TPL_UDP2RAW "${META[udp2raw,dir]}/udp2raw_${nid}.conf" \
            LISTEN "0.0.0.0:$pout" TARGET "127.0.0.1:$p_kcp" PASS "$pass"
            
        sys_ctl enable "chain_ss3" "$nid"
    fi
    sleep 2
    green "串联创建成功。状态: $(sys_ctl status_color "$type" "$nid")"
}

# --- 7. 额外功能 & 卸载 (Tools) ---

view_all_configs() {
    clear; echo "=== 所有配置信息 ==="
    for t in hy2 xray_reality chain_hy2 chain_vless chain_ss3 udp2raw kcptun; do
        local ids=$(get_existing_ids "$t")
        [[ -z "$ids" ]] && continue
        echo "-------------------------"
        echo "${META[$t,name]}:"
        for i in $ids; do
            echo -n "ID $i: "
            gen_link "$t" "$i"
        done
    done
    echo "-------------------------"
    read -p "按任意键返回..." -n1 -s
}

uninstall_all() {
    read -p "确认卸载所有服务并清除文件？[y/N]: " c
    [[ "$c" != "y" && "$c" != "Y" ]] && return
    green "正在卸载..."
    systemctl stop ax-* 2>/dev/null
    systemctl disable ax-* 2>/dev/null
    rm -f /etc/systemd/system/ax-*.service
    systemctl daemon-reload
    rm -rf /etc/hysteria2 /etc/xray /etc/udp2raw /etc/kcptun /etc/ax-certs
    green "卸载完成。"
    sleep 2
}

tool_sys_opt() { green "执行系统优化(模拟)..."; sleep 1; } 
tool_warp() { green "安装 WARP(模拟)..."; sleep 1; }    
tool_acme() { green "ACME 管理(模拟)..."; sleep 1; }   

# --- 8. 模板 (Templates) ---

read -r -d '' TPL_HY2 <<'EOF'
listen: __LISTEN__
tls:
  cert: __CERT__
  key: __KEY__
auth:
  type: password
  password: __PASS__
masquerade:
  type: proxy
  proxy: { url: https://bing.com, rewriteHost: true }
EOF

read -r -d '' TPL_XRAY_REALITY <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": __PORT__, "protocol": "vless",
    "settings": { "clients": [{ "id": "__UUID__", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "show": false, "dest": "www.apple.com:443", "serverNames": ["www.apple.com"], "privateKey": "__PK__", "shortIds": ["__SHORT__"] }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

read -r -d '' TPL_XRAY_MKCP <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": __PORT__, "protocol": "vless",
    "settings": { "clients": [{ "id": "__UUID__" }], "decryption": "none" },
    "streamSettings": {
      "network": "kcp",
      "kcpSettings": { "mtu": 1350, "tti": 20, "uplinkCapacity": 100, "downlinkCapacity": 100, "congestion": false, "readBufferSize": 2, "writeBufferSize": 2, "header": { "type": "wechat-video" } }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

read -r -d '' TPL_SS <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": __PORT__, "protocol": "shadowsocks",
    "settings": { "method": "aes-256-gcm", "password": "__PASS__", "network": "tcp,udp" }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

read -r -d '' TPL_KCPTUN <<'EOF'
{
  "listen": "__LISTEN__",
  "target": "__TARGET__",
  "key": "__KEY__",
  "crypt": "aes",
  "mode": "fast2",
  "mtu": 1350,
  "sndwnd": 1024,
  "rcvwnd": 1024,
  "datashard": 10,
  "parityshard": 3,
  "dscp": 46,
  "nocomp": false
}
EOF

read -r -d '' TPL_UDP2RAW <<'EOF'
-s -l __LISTEN__ -r __TARGET__ -k __PASS__ --raw-mode faketcp -a
EOF

# --- 9. 主入口 (Main) ---

main_menu() {
    while true; do
        clear; echo "=================================="
        echo "  多合一隧道管理 v$SCRIPT_VERSION"
        echo "=================================="
        cyan "--- 串联管理 ---"
        echo " 1) Hysteria2+UDP2RAW 串联"
        echo " 2) VLESS_KCP+UDP2RAW 串联"
        echo " 3) Shadowsocks+KCP+UDP 串联"
        cyan "--- 独立实例管理 ---"
        echo " 4) Hysteria2"
        echo " 5) VLESS+Reality"
        echo " 6) VLESS+mKCP"
        echo " 7) Shadowsocks"
        cyan "--- 加速管理 ---"
        echo " 8) UDP2RAW"
        echo " 9) KCPTUN"
        echo "----------------------------------"
        cyan "--- 全局操作 ---"
        echo " 10) 查看全部配置"
        echo " 11) 重启全部服务"
        echo " 12) 检查更新"
        cyan "--- 工具管理 ---"
        echo " 13) 优化VPS系统"
        echo " 14) 安装warp-Socks5"
        echo " 15) ACME证书管理"
        echo "----------------------------------"
        echo " 99) 卸载"
        echo " 0) 退出"
        echo "----------------------------------"
        
        show_status_summary
        
        echo "----------------------------------"
        read -p "请选择: " c
        
        # 快速跳转校验
        if [[ "$c" =~ ^[0-9]+$ ]] && [[ -n "${QUICK_MAP_TYPE[$c]}" ]]; then
            local qt=${QUICK_MAP_TYPE[$c]} qid=${QUICK_MAP_ID[$c]}
            if [[ "${META[$qt,is_chain]}" == "true" ]]; then menu_chain "$qt" "$qid"
            else menu_instance "$qt" "$qid"; fi
            continue
        fi

        case $c in
            1) type_manager_menu "chain_hy2" ;;
            2) type_manager_menu "chain_vless" ;;
            3) type_manager_menu "chain_ss3" ;;
            4) type_manager_menu "hy2" ;;
            5) type_manager_menu "xray_reality" ;;
            5) type_manager_menu "xray_reality" ;;
            6) type_manager_menu "xray_mkcp" ;;
            7) type_manager_menu "ss" ;;
            8) type_manager_menu "udp2raw" ;;
            9) type_manager_menu "kcptun" ;;
            10) view_all_configs ;;
            11) systemctl restart ax-*; green "已重启" ;;
            13) tool_sys_opt ;;
            14) tool_warp ;;
            15) tool_acme ;;
            99) uninstall_all ;;
            0) exit 0 ;;
            *) red "无效选择" && sleep 1 ;;
        esac
    done
}

# --- 初始化 ---
check_root
install_deps
install_bin_generic "hy2"
install_bin_generic "xray"
install_bin_generic "udp2raw"
install_bin_generic "kcptun"
install_service "hy2"
install_service "xray"
install_service "udp2raw"
install_service "kcptun"

main_menu
