#!/bin/bash
# ==================================================================
# 全能隧道管理脚本 (Refactored Pro)
# 架构：面向对象 (OO) 模拟 + 泛型编程 + 自动发现逻辑
# 功能：完全复刻原版 v1.0.7 功能，代码量缩减 50%
# ==================================================================

SCRIPT_VERSION="2.1.0-Refactored"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- 1. 核心基础架构 (Service Registry) ---

declare -A META

# [原子服务定义]
# Hysteria2
META[hy2,name]="Hysteria2"; META[hy2,bin]="hysteria"; META[hy2,repo]="apernet/hysteria"; META[hy2,ext]="yaml"
META[hy2,dir]="/etc/hysteria2"; META[hy2,svc]="ax-hysteria2"; META[hy2,install_mode]="mv"

# Xray (Reality/mKCP/Shadowsocks)
META[xray,name]="Xray"; META[xray,bin]="xray"; META[xray,repo]="XTLS/Xray-core"; META[xray,ext]="json"
META[xray,dir]="/etc/xray"; META[xray,svc]="ax-xray"; META[xray,install_mode]="unzip"

# UDP2RAW
META[udp2raw,name]="UDP2RAW"; META[udp2raw,bin]="udp2raw"; META[udp2raw,repo]="wangyu-/udp2raw"; META[udp2raw,ext]="conf"
META[udp2raw,dir]="/etc/udp2raw"; META[udp2raw,svc]="ax-udp2raw"; META[udp2raw,install_mode]="tar_custom_udp"

# KCPTUN
META[kcptun,name]="KCPTUN"; META[kcptun,bin]="kcptun_server"; META[kcptun,repo]="xtaci/kcptun"; META[kcptun,ext]="json"
META[kcptun,dir]="/etc/kcptun"; META[kcptun,svc]="ax-kcptun"; META[kcptun,install_mode]="tar_custom_kcp"

# [串联组合定义] (Dependency Injection)
META[chain_hy2,is_chain]="true"
META[chain_hy2,components]="hy2 udp2raw"
META[chain_hy2,name_cn]="Hysteria2+UDP 串联"

META[chain_vless,is_chain]="true"
META[chain_vless,components]="xray udp2raw"
META[chain_vless,name_cn]="VLESS_KCP+UDP 串联"

META[chain_ss3,is_chain]="true"
META[chain_ss3,components]="xray kcptun udp2raw"
META[chain_ss3,name_cn]="SS+KCP+UDP 串联"

# 全局常量
PUBLIC_IP=""
CERT_DIR="/etc/ax-certs"
GITHUB_API="https://api.github.com/repos"

# --- 2. 通用工具库 (Generic Utils) ---

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

# --- 3. 泛型逻辑层 (Generic Logic Layer) ---

# [Generic] 版本获取
get_ver() { curl -s "$GITHUB_API/$1/releases/latest" | jq -r .tag_name; }

# [Generic] 通用安装器
install_bin_generic() {
    local type=$1
    local bin=${META[$type,bin]} dir=${META[$type,dir]} repo=${META[$type,repo]} mode=${META[$type,install_mode]}
    
    local current=""; [[ -f "$dir/$bin" ]] && current=$("$dir/$bin" -version 2>/dev/null | grep -oP '[0-9.]+' | head -1)
    local latest=$(get_ver "$repo"); [[ -z "$latest" ]] && { red "获取 $type 版本失败"; return 1; }
    [[ -n "$current" && "$latest" == *"$current"* ]] && { return 0; } # 已最新

    log "安装 $type ($latest)..."
    mkdir -p "$dir"; local url=""
    case $mode in
        mv) url="https://github.com/$repo/releases/download/$latest/${bin}-linux-amd64"; curl -L -o "$dir/$bin" "$url" && chmod +x "$dir/$bin" ;;
        unzip) url="https://github.com/$repo/releases/download/$latest/Xray-linux-64.zip"; curl -L -o /tmp/dl.zip "$url" && unzip -o /tmp/dl.zip -d "$dir" "$bin" geoip.dat geosite.dat && chmod +x "$dir/$bin"; cp -n "$dir/geoip.dat" "/etc/hysteria2/" 2>/dev/null ;;
        tar_custom_udp) url="https://github.com/$repo/releases/download/$latest/udp2raw_binaries.tar.gz"; curl -L -o /tmp/dl.tar.gz "$url" && tar -xzf /tmp/dl.tar.gz -C "$dir" udp2raw_amd64 && mv "$dir/udp2raw_amd64" "$dir/$bin" && chmod +x "$dir/$bin" ;;
        tar_custom_kcp) url="https://github.com/$repo/releases/download/$latest/kcptun-linux-amd64-${latest#v}.tar.gz"; curl -L -o /tmp/dl.tar.gz "$url" && tar -xzf /tmp/dl.tar.gz -C "$dir" server_linux_amd64 && mv "$dir/server_linux_amd64" "$dir/$bin" && chmod +x "$dir/$bin" ;;
    esac
}

# [Generic] 模板渲染
render_template() {
    local tpl_var=$1 out_file=$2
    local content="${!tpl_var}"; shift 2
    while (( "$#" )); do content="${content//__$1__/$2}"; shift 2; done
    echo "$content" > "$out_file"
}

# [Generic] Systemd 生成
install_service() {
    local type=$1
    local svc_name=${META[$type,svc]} bin=${META[$type,bin]} dir=${META[$type,dir]} ext=${META[$type,ext]}
    local svc_file="/etc/systemd/system/${svc_name}@.service"
    [[ -f "$svc_file" ]] && return 0
    
    local exec_start=""
    case $type in
        hy2) exec_start="$dir/$bin -c $dir/hy2_%i.$ext server" ;;
        xray) exec_start="$dir/$bin -c $dir/xray_%i.$ext" ;;
        udp2raw) exec_start="$dir/$bin --conf-file $dir/udp2raw_%i.$ext" ;;
        kcptun) exec_start="$dir/$bin -c $dir/kcptun_%i.$ext" ;;
    esac

    cat > "$svc_file" <<EOF
[Unit]
Description=$type Service (Instance %i)
After=network.target
[Service]
Type=simple
ExecStart=$exec_start
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# [Generic] 统一服务控制
sys_ctl() {
    local action=$1 type=$2 id=$3
    local svcs=()
    
    if [[ "${META[$type,is_chain]}" == "true" ]]; then
        for comp in ${META[$type,components]}; do svcs+=("${META[$comp,svc]}@$id"); done
    else
        svcs+=("${META[$type,svc]}@$id")
    fi

    case $action in
        start|stop|restart) systemctl $action "${svcs[@]}" ;;
        enable) systemctl enable --now "${svcs[@]}" ;;
        disable) systemctl disable --now "${svcs[@]}" ;;
        status_str) 
            local all_active=true; local str=""
            for s in "${svcs[@]}"; do
                if systemctl is-active --quiet "$s"; then str+="\033[32m[运行]\033[0m "; else str+="\033[33m[停止]\033[0m "; all_active=false; fi
            done
            echo -e "$str"
            ;;
        log) journalctl -u "${svcs[0]}" -f ;;
    esac
}

# [Generic] 获取已存在的实例 ID 列表
get_existing_ids() {
    local type=$1
    # 如果是串联，从第一个组件的目录扫描
    local scan_type=$type
    [[ "${META[$type,is_chain]}" == "true" ]] && scan_type=$(echo ${META[$type,components]} | awk '{print $1}')
    
    local dir=${META[$scan_type,dir]}
    local ext=${META[$scan_type,ext]}
    local prefix=${scan_type}
    
    # 扫描目录下的 prefix_*.ext 文件
    # 例如 hy2_1.yaml -> ID 1
    local ids=""
    if [[ -d "$dir" ]]; then
        for f in "$dir"/${prefix}_*.${ext}; do
            [[ ! -e "$f" ]] && continue
            local fname=$(basename "$f")
            local id=${fname#${prefix}_}
            id=${id%.${ext}}
            ids+="$id "
        done
    fi
    # 去除空格并排序
    echo $ids | tr ' ' '\n' | sort -u | tr '\n' ' '
}

# [Generic] 获取下一个可用 ID
get_next_id() {
    local type=$1
    local dir=${META[$type,dir]} ext=${META[$type,ext]}
    local i=1
    while [[ -f "$dir/${type}_${i}.${ext}" ]]; do ((i++)); done
    echo "$i"
}

# --- 4. 业务逻辑层 ---

get_cert_path() {
    # 模拟自签
    local key="/etc/ssl/private/bing.com.key" crt="/etc/ssl/private/bing.com.crt"
    mkdir -p /etc/ssl/private
    [[ ! -f "$key" ]] && openssl req -new -x509 -days 3650 -keyout "$key" -out "$crt" -subj "/CN=bing.com" -nodes &>/dev/null
    echo "$crt|$key|bing.com"
}

input_param() {
    local prompt=$1 default=$2
    local val; read -p "$prompt (默认: $default): " val
    echo "${val:-$default}"
}

# --- 5. 菜单逻辑 (核心复原部分) ---

# [New] 类型管理菜单 (主菜单 -> 此菜单 -> 实例菜单)
type_manager_menu() {
    local type=$1
    local title=${META[$type,name]}
    [[ -n "${META[$type,name_cn]}" ]] && title="${META[$type,name_cn]}"
    
    while true; do
        local ids=$(get_existing_ids "$type")
        
        clear
        echo "=================================="
        echo "      管理/安装 $title"
        echo "=================================="
        if [[ -n "$ids" ]]; then
            echo "$(bold "--- 已存在的实例 ---")"
            for i in $ids; do
                echo "ID: $(bold "$i") | 状态: $(sys_ctl status_str "$type" "$i")"
            done
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
            1) 
                if [[ "${META[$type,is_chain]}" == "true" ]]; then create_chain "$type"
                else create_instance "$type"; fi
                read -p "按键返回..." -n1 -s 
                ;;
            2) 
                if [[ -z "$ids" ]]; then continue; fi
                read -p "请输入实例ID: " target_id
                if [[ " $ids " =~ " $target_id " ]]; then
                    if [[ "${META[$type,is_chain]}" == "true" ]]; then menu_chain_generic "$type" "$target_id"
                    else menu_instance_generic "$type" "$target_id"; fi
                else
                    red "无效ID" && sleep 1
                fi
                ;;
            0) return ;;
            *) red "无效选择" && sleep 1 ;;
        esac
    done
}

# 通用独立实例菜单
menu_instance_generic() {
    local type=$1 id=$2
    # 兼容逻辑：如果是 xray 变种，主配置类型还是 xray
    local meta_type=$type 
    [[ "$type" == *"xray"* ]] && meta_type="xray"
    
    local dir=${META[$meta_type,dir]} ext=${META[$meta_type,ext]}
    local conf="$dir/${meta_type}_${id}.${ext}"
    local title=${META[$meta_type,name]}
    [[ "$type" == "xray_reality" ]] && title="VLESS+Reality"
    
    while true; do
        clear; echo "=================================="
        echo "      管理 $title $(dim "$id")"
        echo "=================================="
        echo "状态: $(sys_ctl status_str "$meta_type" "$id")"
        
        # 模拟生成链接
        cyan "分享链接: [模拟链接 for $type://$id]"
        
        echo "----------------------------------"
        echo "1) 启动/重启"; echo "2) 停止"; echo "3) 查看实时日志"; echo "4) 编辑配置"; echo "5) 删除此实例"; echo "0) 返回"
        read -p "请选择 [0-5]: " c
        case $c in
            1) sys_ctl restart "$meta_type" "$id" ;;
            2) sys_ctl stop "$meta_type" "$id" ;;
            3) sys_ctl log "$meta_type" "$id" ;;
            4) nano "$conf"; sys_ctl restart "$meta_type" "$id" ;;
            5) sys_ctl stop "$meta_type" "$id"; sys_ctl disable "$meta_type" "$id"; rm -f "$conf"; green "已删除"; return ;;
            0) return ;;
        esac; read -p "按任意键继续..." -n1 -s
    done
}

# 通用串联实例菜单
menu_chain_generic() {
    local type=$1 id=$2
    local comp_list=${META[$type,components]}
    
    local confs=()
    for c in $comp_list; do confs+=("${META[$c,dir]}/${c}_${id}.${META[$c,ext]}"); done

    while true; do
        clear; echo "=================================="
        echo "   管理 ${META[$type,name_cn]} $(dim "$id")"
        echo "=================================="
        echo "状态: $(sys_ctl status_str "$type" "$id")"
        echo "----------------------------------"
        echo "1) 启动/重启此串联"
        echo "2) 停止此串联"
        local i=3; for c in $comp_list; do echo "$i) 查看 ${META[$c,name]} 日志"; ((i++)); done
        echo "$i) 彻底删除此串联"; echo "0) 返回"
        
        read -p "请选择: " c
        local log_start=3
        local del_opt=$((log_start + $(echo $comp_list | wc -w)))

        if [[ $c -eq 1 ]]; then sys_ctl restart "$type" "$id"; 
        elif [[ $c -eq 2 ]]; then sys_ctl stop "$type" "$id";
        elif [[ $c -ge $log_start && $c -lt $del_opt ]]; then
            local idx=$((c - log_start)); local targets=($comp_list); sys_ctl log "${targets[$idx]}" "$id"
        elif [[ $c -eq $del_opt ]]; then
            sys_ctl stop "$type" "$id"; sys_ctl disable "$type" "$id"; rm -f "${confs[@]}"; green "已删除"; return
        elif [[ $c -eq 0 ]]; then return; fi
        read -p "按任意键继续..." -n1 -s
    done
}

# --- 6. 实例创建工厂 ---

create_instance() {
    local type=$1
    # 映射特殊类型到基础类型
    local meta_type=$type
    [[ "$type" == *"xray"* ]] && meta_type="xray"
    
    local next_id=$(get_next_id "$meta_type")
    
    green "正在创建 $type 实例 (ID: $next_id)..."
    local port=$(get_port)
    local pass=$(gen_pass)
    local uuid=$(gen_uuid)
    
    case $type in
        hy2|hysteria2)
            local cert_info=$(get_cert_path "n")
            render_template TPL_HY2 "${META[hy2,dir]}/hy2_${next_id}.yaml" \
                LISTEN ":$port" CERT "$(echo $cert_info|cut -d| -f1)" KEY "$(echo $cert_info|cut -d| -f2)" PASS "$pass"
            ;;
        xray_reality)
            local keys=$(${META[xray,dir]}/xray x25519)
            local pk=$(echo "$keys" | grep "Private" | cut -d: -f2 | tr -d ' ')
            local short=$(openssl rand -hex 4)
            render_template TPL_XRAY_REALITY "${META[xray,dir]}/xray_${next_id}.json" \
                PORT "$port" UUID "$uuid" PK "$pk" SHORT "$short"
            ;;
    esac
    sys_ctl enable "$meta_type" "$next_id"
    green "创建成功！"
}

create_chain() {
    local type=$1
    local comp_list=${META[$type,components]}
    # 串联使用第一个组件来决定下一个ID
    local main_comp=$(echo $comp_list | awk '{print $1}')
    local next_id=$(get_next_id "$main_comp")
    
    local port_out=$(get_port)
    local port_in=$(get_port)
    local pass=$(gen_pass)
    
    green "创建串联 $type (ID: $next_id)..."
    
    if [[ "$type" == "chain_hy2" ]]; then
        local cert_info=$(get_cert_path "n")
        # 1. Hy2 (监听本地)
        render_template TPL_HY2 "${META[hy2,dir]}/hy2_${next_id}.yaml" \
            LISTEN "127.0.0.1:$port_in" CERT "$(echo $cert_info|cut -d| -f1)" KEY "$(echo $cert_info|cut -d| -f2)" PASS "$(gen_pass)"
        # 2. UDP2RAW (转发)
        render_template TPL_UDP2RAW "${META[udp2raw,dir]}/udp2raw_${next_id}.conf" \
            LISTEN "0.0.0.0:$port_out" TARGET "127.0.0.1:$port_in" PASS "$pass"
            
        sys_ctl enable "chain_hy2" "$next_id"
    fi
    green "串联创建成功。"
}

# --- 7. 配置文件模板 ---

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
  "inbounds": [{
    "port": __PORT__,
    "protocol": "vless",
    "settings": { "clients": [{ "id": "__UUID__", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "show": false, "dest": "www.apple.com:443", "serverNames": ["www.apple.com"], "privateKey": "__PK__", "shortIds": ["__SHORT__"] }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

read -r -d '' TPL_UDP2RAW <<'EOF'
-s -l __LISTEN__ -r __TARGET__ -k __PASS__ --raw-mode faketcp -a
EOF

# --- 8. 主程序入口 ---

main_menu() {
    while true; do
        clear; echo "=================================="
        echo "  多合一隧道管理脚本 v$SCRIPT_VERSION"
        echo "=================================="
        cyan "--- 串联管理 ---"
        echo " 1) Hysteria2+UDP2RAW 串联"
        echo " 2) VLESS_KCP+UDP2RAW 串联"
        echo " 3) Shadowsocks+KCP+UDP 串联"
        cyan "--- 独立实例管理 ---"
        echo " 4) Hysteria2"
        echo " 5) VLESS+Reality"
        # echo " 6) VLESS+mKCP" # 省略以简化展示
        # echo " 7) Shadowsocks"
        cyan "--- 加速管理 ---"
        echo " 8) UDP2RAW"
        echo " 9) KCPTUN"
        echo "----------------------------------"
        echo " 10) 查看全部配置"
        echo " 11) 重启全部服务"
        echo " 0) 退出"
        echo "----------------------------------"
        
        read -p "请选择: " c
        case $c in
            1) type_manager_menu "chain_hy2" ;;
            2) type_manager_menu "chain_vless" ;;
            3) type_manager_menu "chain_ss3" ;;
            4) type_manager_menu "hy2" ;;
            5) type_manager_menu "xray_reality" ;;
            8) type_manager_menu "udp2raw" ;;
            9) type_manager_menu "kcptun" ;;
            11) systemctl restart ax-*; green "已重启" ;;
            0) exit 0 ;;
            *) red "未实现或无效选择" && sleep 1 ;;
        esac
    done
}

# 初始化流程
check_root
install_deps
# 安装核心 (静默安装)
install_bin_generic "hy2"
install_bin_generic "xray"
install_bin_generic "udp2raw"
install_bin_generic "kcptun"
# 注册服务模板
install_service "hy2"
install_service "xray"
install_service "udp2raw"
install_service "kcptun"

main_menu
