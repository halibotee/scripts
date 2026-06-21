#!/bin/sh

# fancyss script for asuswrt/merlin based router with software center
source /koolshare/scripts/base.sh
NEW_PATH=$(echo $PATH|tr ':' '\n'|sed '/opt/d;/mmc/d'|awk '!a[$0]++'|tr '\n' ':'|sed '$ s/:$//')
export PATH=${NEW_PATH}
LC_ALL=C
LANG=C
LOCK_FILE=/var/lock/online_update.lock
LOG_FILE=/tmp/upload/ss_log.txt
DIR="/tmp/fancyss_subs"
LOCAL_NODES_SPL="$DIR/ss_nodes_spl.txt"
LOCAL_NODES_BAK="$DIR/ss_nodes_bak.txt"
NODES_SEQ=$(dbus list ssconf_basic_name_ | sed -n 's/^.*_\([0-9]\+\)=.*/\1/p' | sort -n)
NODE_INDEX=$(echo ${NODES_SEQ} | sed 's/.*[[:space:]]//')
SUB_MODE=$(dbus get ssr_subscribe_mode)
HY2_UP_SPEED=$(dbus get ss_basic_hy2_up_speed)
HY2_DL_SPEED=$(dbus get ss_basic_hy2_dl_speed)
HY2_TFO_SWITCH=$(dbus get ss_basic_hy2_tfo_switch)
CURR_NODE=$(dbus get ssconf_basic_node)
KEY_WORDS_1=$(dbus get ss_basic_exclude | sed 's/,$//g' | sed 's/,/|/g')
KEY_WORDS_2=$(dbus get ss_basic_include | sed 's/,$//g' | sed 's/,/|/g')
alias urldecode='sed "s@+@ @g;s@%@\\\\x@g" | xargs -0 printf "%b"'

# 20230701, some vairiable should be unset
unset usb2jffs_time_hour
unset usb2jffs_week
unset usb2jffs_title
unset usb2jffs_day
unset usb2jffs_rsync
unset usb2jffs_sync
unset usb2jffs_inter_day
unset usb2jffs_inter_pre
unset usb2jffs_version
unset usb2jffs_mount_path
unset usb2jffs_inter_hour
unset usb2jffs_time_min
unset usb2jffs_inter_min
unset usb2jffs_backupfile_name
unset usb2jffs_backup_file
unset usb2jffs_mtd_jffs
unset usb2jffs_warn_2
unset ACTION
unset DEVICENAME
unset DEVNAME
unset DEVPATH
unset DEVTYPE
unset INTERFACE
unset PRODUCT
unset USBPORT
unset SUBSYSTEM
unset SEQNUM
unset MAJOR
unset MINOR
unset PERP_SVPID
unset SHLVL
unset TERM
unset PERP_BASE
unset HOME
unset PWD

# 一个节点里可能有的所有信息，记录用
# ssconf_basic_name_
# ssconf_basic_server_
# ssconf_basic_mode_
# ssconf_basic_method_
# ssconf_basic_password_
# ssconf_basic_port_
# ssconf_basic_ss_obfs_
# ssconf_basic_ss_obfs_host_
# ssconf_basic_ss_v2ray_
# ssconf_basic_ss_v2ray_opts_
# ssconf_basic_rss_obfs_
# ssconf_basic_rss_obfs_param_
# ssconf_basic_rss_protocol_
# ssconf_basic_rss_protocol_param_
# ssconf_basic_koolgame_udp_
# ssconf_basic_use_kcp_
# ssconf_basic_use_lb_
# ssconf_basic_lbmode_
# ssconf_basic_weight_
# ssconf_basic_group_
# ssconf_basic_v2ray_use_json_
# ssconf_basic_v2ray_uuid_
# ssconf_basic_v2ray_alterid_
# ssconf_basic_v2ray_security_
# ssconf_basic_v2ray_network_
# ssconf_basic_v2ray_headtype_tcp_
# ssconf_basic_v2ray_headtype_kcp_
# ssconf_basic_v2ray_kcp_seed
# ssconf_basic_v2ray_headtype_quic_
# ssconf_basic_v2ray_grpc_mode_
# ssconf_basic_v2ray_network_path_
# ssconf_basic_v2ray_network_host_
# ssconf_basic_v2ray_network_security_
# ssconf_basic_v2ray_network_security_ai_
# ssconf_basic_v2ray_network_security_alpn_h2_
# ssconf_basic_v2ray_network_security_alpn_http_
# ssconf_basic_v2ray_network_security_sni_
# ssconf_basic_v2ray_mux_enable_
# ssconf_basic_v2ray_mux_concurrency_
# ssconf_basic_v2ray_json_
# ssconf_basic_xray_use_json_
# ssconf_basic_xray_uuid_
# ssconf_basic_xray_alterid_
# ssconf_basic_xray_prot_
# ssconf_basic_xray_encryption_
# ssconf_basic_xray_flow_
# ssconf_basic_xray_network_
# ssconf_basic_xray_headtype_tcp_
# ssconf_basic_xray_headtype_kcp_
# ssconf_basic_xray_kcp_seed
# ssconf_basic_xray_headtype_quic_
# ssconf_basic_xray_grpc_mode_
# ssconf_basic_xray_network_path_
# ssconf_basic_xray_network_host_
# ssconf_basic_xray_network_security_
# ssconf_basic_xray_network_security_ai_
# ssconf_basic_xray_network_security_alpn_h2_
# ssconf_basic_xray_network_security_alpn_http_
# ssconf_basic_xray_network_security_sni_
# ssconf_basic_xray_fingerprint_
# ssconf_basic_xray_show_
# ssconf_basic_xray_publickey_
# ssconf_basic_xray_shortid_
# ssconf_basic_xray_spiderx_
# ssconf_basic_xray_json_
# ssconf_basic_trojan_ai_
# ssconf_basic_trojan_uuid_
# ssconf_basic_trojan_sni_
# ssconf_basic_trojan_tfo_
# ssconf_basic_naive_prot_
# ssconf_basic_naive_server_
# ssconf_basic_naive_port_
# ssconf_basic_naive_user_
# ssconf_basic_naive_pass_
# ssconf_basic_tuic_json_
# ssconf_basic_hy2_server_
# ssconf_basic_hy2_port_
# ssconf_basic_hy2_pass_
# ssconf_basic_hy2_obfs_
# ssconf_basic_hy2_obfs_pass_
# ssconf_basic_hy2_up_
# ssconf_basic_hy2_dl_
# ssconf_basic_hy2_sni_
# ssconf_basic_hy2_tfo_
# ssconf_basic_type_

# 方案
# 设计：通过操作文件实现节点的订阅
# 1.	skipdb2json：订阅前将节点信息导出到文件，通过sed等操作将其转换为一个节点一行的压缩json格式的节点文件：fancyss_nodes_old_spl.txt，如果有有200个节点就是200行json
# 2.	nodes2files：根据节点中的link_hash信息，将节点文件拆分为多个，usr.txt (用户节点)， local_1_xxxx.txt (机场xxxx)， local_2_yyyy.txt (机场xxxx)
# 3.	nodes_stats：用拆分文件统计节点信息
# 4.	remove_null：订阅钱检测下是否有机场不再订阅（用户删除了这个机场的url）
# 5.	下载订阅
# 6.	解析订阅
# 7.	解析节点
# 8.		过滤节点
# 9.		点写入更新文件
# 10. 	对比更新文件和本地节点文件
# 11. 	写入/不写入节点
# 12.	

# 7. 最后改写key的顺序，写入dbus
# 8. 如果节点数量变少了，那么还需要掐尾去尾巴
# 优点：删除节点，节点排序很方便！

set_lock(){
	exec 233>"${LOCK_FILE}"
	flock -n 233 || {
		local PID1=$$
		local PID2=$(ps|grep -w "ss_online_update.sh"|grep -vw "grep"|grep -vw ${PID1})
		if [ -n "${PID2}" ];then
			echo_date "订阅脚本已经在运行，请稍候再试！"
			exit 1			
		else
			rm -rf ${LOCK_FILE}
		fi
	}
}

unset_lock(){
	flock -u 233
	rm -rf "${LOCK_FILE}"
}

count_start(){
	# opkg install coreutils-date
	_start=$(/opt/bin/date +%s.%6N)
	_start0=${_start}
	counter=0
	echo_date ------------------
	echo_date - 0.000000
}

count_time(){
	# opkg install coreutils-date
	_end=$(/opt/bin/date +%s.%6N)
	runtime=$(awk "BEGIN { x = ${_end}; y = ${_start}; print (x - y) }")
	let counter+=1
	echo_date + $counter $runtime
	_start=${_end}
}

count_total(){
	# opkg install coreutils-date
	_end=$(/opt/bin/date +%s.%6N)
	runtime=$(awk "BEGIN { x = ${_end}; y = ${_start0}; print (x - y) }")
	let counter+=1
	echo_date - $runtime
	echo_date ------------------
}

run(){
	env -i PATH=${PATH} "$@"
}

json_init(){
	#true >/tmp/node_data.txt
	NODE_DATA="{"
}

json_add_string(){
	if [ -n "$2" ];then
		NODE_DATA="${NODE_DATA}\"$1\":\"$2\","
	fi
}

json_write_object(){
	echo $NODE_DATA | sed '$ s/,$/}/g' >>$1
}

__valid_ip() {
	# 验证是否为ipv4或者ipv6地址，是则正确返回，不是返回空值
	local format_4=$(echo "$1" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}$")
	if [ -n "${format_4}" ]; then
		echo "${format_4}"
		return 0
	else
		echo ""
		return 1
	fi
}

dec64(){
	# echo -n "${link}" | sed 's/$/====/' | grep -o "...." | sed '${/====/d}' | tr -d '\n' | base64 -d
	echo -n "${1}===" | sed 's/-/+/g;s/_/\//g' | base64 -d 2>/dev/null
	return $?
}

# NEW Function to parse accelerator params
# Input: "tool://param1 val1 param2 val2 ..."
# Output: Sets global variables like kcp_listen_port, kcp_target_ip, kcp_param_final, etc.
parse_accelerator_params(){
    local link_part=$1
    local tool_type=$(echo "$link_part" | cut -d':' -f1)
    local params_str=$(echo "$link_part" | sed "s#^${tool_type}://##")

    # Reset global vars for safety
    kcp_listen_ip="" kcp_listen_port="" kcp_target_ip="" kcp_target_port="" kcp_param_final=""
    udp_listen_ip="" udp_listen_port="" udp_remote_ip="" udp_remote_port="" udp_key="" udp_param_final=""

    local temp_params=""
    local skip_next=0

    # Crude parameter parsing - handles space-separated args
    set -- $params_str # Split params_str by spaces into positional parameters $1, $2, ...
    while [ $# -gt 0 ]; do
        local arg="$1"
        local val="$2" # Potential value

        if [ "$skip_next" -eq 1 ]; then
            skip_next=0
            shift # Skip the value we already processed
            continue
        fi

        case "$tool_type" in
            KCPTUN)
                case "$arg" in
                    --listen)
                        kcp_listen_ip=$(echo "$val" | cut -d':' -f1)
                        kcp_listen_port=$(echo "$val" | cut -d':' -f2)
                        skip_next=1
                        ;;
                    --target)
                        kcp_target_ip=$(echo "$val" | cut -d':' -f1)
                        kcp_target_port=$(echo "$val" | cut -d':' -f2)
                        skip_next=1
                        ;;
                    *)
                        # Append other args to temp_params
                        temp_params="${temp_params} ${arg}"
                        if [ "$(echo "$arg" | cut -c1-2)" == "--" ] && [ "$#" -gt 1 ] && [ "$(echo "$val" | cut -c1)" != "-" ]; then
                             # Argument likely takes a value
                             temp_params="${temp_params} ${val}"
                             skip_next=1
                        fi
                        ;;
                esac
                ;;
            UDP2RAW)
                case "$arg" in
                    -l)
                        udp_listen_ip=$(echo "$val" | cut -d':' -f1)
                        udp_listen_port=$(echo "$val" | cut -d':' -f2)
                        skip_next=1
                        ;;
                    -r)
                        udp_remote_ip=$(echo "$val" | cut -d':' -f1)
                        udp_remote_port=$(echo "$val" | cut -d':' -f2)
                        skip_next=1
                        ;;
                    -k)
                        udp_key="$val" # Store key separately
                        skip_next=1
                        ;;
                    -c)
                        # Skip -c flag
                        ;;
                    *)
                        # Append other args to temp_params
                        temp_params="${temp_params} ${arg}"
                         if [ "$(echo "$arg" | cut -c1)" == "-" ] && [ "$(echo "$arg" | wc -c)" -eq 2 ] && [ "$#" -gt 1 ] && [ "$(echo "$val" | cut -c1)" != "-" ]; then
                             # Short argument likely takes a value
                             temp_params="${temp_params} ${val}"
                             skip_next=1
                         elif [ "$(echo "$arg" | cut -c1-2)" == "--" ] && [ "$#" -gt 1 ] && [ "$(echo "$val" | cut -c1)" != "-" ]; then
                             # Long argument likely takes a value
                             temp_params="${temp_params} ${val}"
                             skip_next=1
                         fi
                        ;;
                esac
                ;;
        esac
        shift # Move to next argument
    done

    # Trim leading/trailing whitespace
    if [ "$tool_type" == "KCPTUN" ]; then
        kcp_param_final=$(echo "$temp_params" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    elif [ "$tool_type" == "UDP2RAW" ]; then
        udp_param_final=$(echo "$temp_params" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi
}

# NEW Function to handle chained nodes
add_chained_node(){
    local base_part=$1
    local kcp_part=$2
    local udp_part=$3
    local action=$4 # Should be 2 for offline add

    local base_node_type_str=$(echo ${base_part} | sed -n 's/^\([a-zA-Z0-9_]\{1,\}\):\/\/.*/\1/p')
    local base_node_info=$(echo ${base_part} | sed -n 's/.\{1,\}:\/\/\(.*\)$/\1/p')

    local remarks="" accel_mode="0" final_name="" final_suffix=""
    local base_server="" base_port="" base_type=""
    local kcp_rserver="" kcp_rport="" kcp_param=""
    local udp2raw_rserver="" udp2raw_rport="" udp2raw_param="" udp2raw_key="" # Added key storage

    local kcp_present=0 udp_present=0

    # Determine base type
    case ${base_node_type_str} in
        ss) base_type="0" ;;
        hysteria2) base_type="8" ;;
        vless) base_type="4" ;; # Assuming VLESS maps to Xray type
        vmess) base_type="4" ;; # Assuming VMESS (in vless link structure) maps to Xray type
        *)
            echo_date "🔴链式节点：不支持的基础协议 ${base_node_type_str}，跳过！"
            return 1
            ;;
    esac

    # Parse KCPTUN if present
    if [ -n "$kcp_part" ]; then
        parse_accelerator_params "$kcp_part"
        # Check if essential KCP params were found
        if [ -n "$kcp_listen_port" ] && [ -n "$kcp_target_ip" ] && [ -n "$kcp_target_port" ]; then
            kcp_present=1
            kcp_param="$kcp_param_final" # Store the processed params
        else
            echo_date "⚠️链式节点：KCPTUN 部分参数解析不完整（缺少 listen/target），跳过 KCP 配置。"
        fi
    fi

    # Parse UDP2RAW if present
    if [ -n "$udp_part" ]; then
        parse_accelerator_params "$udp_part"
        # Check if essential UDP2RAW params were found
        if [ -n "$udp_listen_port" ] && [ -n "$udp_remote_ip" ] && [ -n "$udp_remote_port" ] && [ -n "$udp_key" ]; then
             udp_present=1
             udp2raw_param="$udp_param_final" # Store the processed params
             udp2raw_key="$udp_key" # Store key
        else
             echo_date "⚠️链式节点：UDP2RAW 部分参数解析不完整（缺少 l/r/k），跳过 UDP2RAW 配置。"
        fi
    fi

    # Determine accel_mode and configure server/ports
    if [ "$kcp_present" -eq 1 ] && [ "$udp_present" -eq 1 ]; then
        accel_mode="2"
        base_server="127.0.0.1"
        base_port="$kcp_listen_port"
        kcp_rserver="127.0.0.1"
        kcp_rport="$udp_listen_port"
        udp2raw_rserver="$udp_remote_ip"
        udp2raw_rport="$udp_remote_port"
        final_suffix="+KCPTUN+UDP2RAW"
    elif [ "$kcp_present" -eq 1 ]; then
        accel_mode="1"
        base_server="127.0.0.1"
        base_port="$kcp_listen_port"
        kcp_rserver="$kcp_target_ip"
        kcp_rport="$kcp_target_port"
        final_suffix="+KCPTUN"
    elif [ "$udp_present" -eq 1 ]; then
        accel_mode="3"
        base_server="127.0.0.1"
        base_port="$udp_listen_port"
        udp2raw_rserver="$udp_remote_ip"
        udp2raw_rport="$udp_remote_port"
        final_suffix="+UDP2RAW"
    else
        # If the link had " && " but neither KCP nor UDP2RAW could be parsed correctly
         echo_date "🔴链式节点：链接格式错误，虽包含 '&&' 但缺少有效的加速器部分或参数不全。"
         return 1
    fi

    # Now, parse the base protocol details, extracting name first
    echo "${base_node_info}" | grep -Eqo "#"
	if [ "$?" != "0" ];then
        # Fallback name if no # found - use the final remote server
        local final_remote_server=""
        [ -n "$udp2raw_rserver" ] && final_remote_server="$udp2raw_rserver" || final_remote_server="$kcp_rserver"
		remarks=${final_remote_server:-"ChainedNode"}
	else
		# (Fix) Use custom decode to preserve '+' in remarks (don't use urldecode alias which replaces + with space)
		remarks=$(echo "${base_node_info}" | awk -F"#" '{print $NF}' | sed 's/%/\\x/g' | xargs -0 printf "%b")
	fi
    
    # (Fix) Check if suffix already exists in remarks to avoid duplication
    # urldecode might have converted + to space, so check both
    local suffix_check="${final_suffix}"
    local suffix_check_space=$(echo "$final_suffix" | sed 's/+/ /g')
    
    if echo "$remarks" | grep -qF "$suffix_check"; then
        final_name="${remarks}"
    elif echo "$remarks" | grep -qF "$suffix_check_space"; then
        final_name="${remarks}"
    else
        final_name="${remarks}${final_suffix}"
    fi

    # Filter based on ORIGINAL remarks (before adding suffix) and final remote server
    local final_remote_server_filter=""
    [ -n "$udp2raw_rserver" ] && final_remote_server_filter="$udp2raw_rserver" || final_remote_server_filter="$kcp_rserver"
    filter_nodes "${base_node_type_str}(Chained)" "${remarks}" "${final_remote_server_filter}"
	if [ "$?" != "0" ];then
		return 1
	fi

    echo_date "🟠链式节点：${final_name}"

    json_init
    json_add_string name "$final_name"
    json_add_string type "$base_type"
    json_add_string mode "${SUB_MODE:-2}" # Default mode 2 if not from subscription
    json_add_string group "" # No group for offline links usually

    # Add base protocol specifics
    case ${base_type} in
        0) # SS
            local info_first=$(echo "${base_node_info}" | sed 's/[@:/?#]/\n/g' | sed -n '1p')
            local encrypt_method="" password=""
            # Try decoding the first part
            local decrypt_info=$(dec64 "${info_first}")
            if [ "$?" == "0" ];then
                # Check if server info is also encoded
                local server_in_first=$(echo "${decrypt_info}" | sed -n 's/.\+@\(.\+:[0-9]\+\).*/\1/p')
                if [ -n "${server_in_first}" ]; then # method:password@server:port are base64
                     encrypt_method=$(echo "${decrypt_info}" | awk -F':' '{print $1}')
                     password=$(echo "${decrypt_info}" | sed 's/@/|/g;s/:/|/g;s/?/|/g;s/#/|/g' | awk -F'|' '{print $2}')
                else # method:password are base64
                    encrypt_method=$(echo "${decrypt_info}" | awk -F':' '{print $1}')
                    password=$(echo "${decrypt_info}" | sed 's/@/|/g;s/:/|/g;s/?/|/g;s/#/|/g' | awk -F'|' '{print $2}')
                fi
            else # method:password@server:port/?...#
                encrypt_method=${info_first}
                password=$(echo "${base_node_info}" | sed 's/[@:/?#]/\n/g' | sed -n '2p')
            fi

            if [ -z "$encrypt_method" ] || [ -z "$password" ]; then
                echo_date "🔴链式SS节点：基础协议部分解析密码或加密方式失败。"
                return 1
            fi

            password=$(echo ${password} | base64_encode | sed 's/[[:space:]]//g')
            json_add_string server "$base_server"
            json_add_string port "$base_port"
            json_add_string method "$encrypt_method"
            json_add_string password "$password"
            # Assume no obfs/plugin for chained nodes for simplicity now
            json_add_string ss_obfs "0"
            json_add_string ss_obfs_host ""
            ;;
        8) # Hy2
            local hy2_pass=$(echo "${base_node_info}" | sed 's/[@:/?#]/\n/g' | sed -n '1p')
            local hy2_sni=$(echo "${base_node_info}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "sni=" | cut -d'=' -f2)
            local hy2_obfs_str=$(echo "${base_node_info}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "obfs=" | grep -v "obfs-password" | cut -d'=' -f2)
            local hy2_obfs="0" && [ "${hy2_obfs_str}" == "salamander" ] && hy2_obfs="1"
            local hy2_obfs_pass=$(echo "${base_node_info}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "obfs-password=" | cut -d'=' -f2)
            local hy2_ai=$(echo "${base_node_info}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "insecure=" | cut -d'=' -f2)
            local hy2_tfo_str=$(echo "${base_node_info}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "tfo=" | cut -d'=' -f2)
            local hy2_tfo="1" && [ "${hy2_tfo_str}" == "0" ] && hy2_tfo="0" # Default 1 if not 0

            local hy2_up="${HY2_UP_SPEED:-20}"
            local hy2_dl="${HY2_DL_SPEED:-100}"

            if [ -z "$hy2_pass" ]; then
                 echo_date "🔴链式Hy2节点：基础协议部分解析密码失败。"
                 return 1
            fi

            json_add_string hy2_server "$base_server"
            json_add_string hy2_port "$base_port"
            json_add_string hy2_pass "$hy2_pass"
            json_add_string hy2_sni "$hy2_sni"
            json_add_string hy2_obfs "$hy2_obfs"
            json_add_string hy2_obfs_pass "$hy2_obfs_pass"
            json_add_string hy2_ai "$hy2_ai"
            # Apply global override from settings if configured
            if [ "${HY2_TFO_SWITCH}" == "1" ]; then hy2_tfo="1"; fi
            if [ "${HY2_TFO_SWITCH}" == "0" ]; then hy2_tfo="0"; fi
            json_add_string hy2_tfo "$hy2_tfo"
            json_add_string hy2_up "$hy2_up"
            json_add_string hy2_dl "$hy2_dl"
            ;;
        4) # VLESS / VMESS (using vless structure)
             local x_uuid=$(echo "${base_node_info}" | awk -F"@" '{print $1}')
             local params_part=$(echo "${base_node_info}" | awk -F"?" '{print $2}' | awk -F"#" '{print $1}')
             # Helper function to extract param value
             _get_param(){ echo "$params_part" | sed 's/&/\n/g' | grep "^$1=" | cut -d'=' -f2 | head -n1; }

             local x_encryption=$(_get_param "encryption") && x_encryption=${x_encryption:-none}
             local x_type=$(_get_param "type") && x_type=${x_type:-tcp}
             local x_security=$(_get_param "security") && x_security=${x_security:-none}
             local x_sni=$(_get_param "sni")
             local x_flow=$(_get_param "flow")
             local x_fp=$(_get_param "fp")
             local x_pbk=$(_get_param "pbk")
             local x_sid=$(_get_param "sid")
             local x_spx=$(_get_param "spx")
             # Transport params
             local x_host=$(_get_param "host")
             local x_path=$(echo "$(_get_param 'path')" | urldecode)
             local x_headerType=$(_get_param "headerType")
             local x_kcp_seed=$(_get_param "seed")
             local x_grpc_mode=$(_get_param "mode") # Assuming grpc mode param is 'mode'
             local x_serviceName=$(echo "$(_get_param 'serviceName')" | urldecode)
             
             # (Fix) Extract congestion parameter
             local x_congestion=$(_get_param "congestion")
             # Default to true (1) if missing or explicitly true
             if [ "$x_congestion" == "true" ] || [ -z "$x_congestion" ]; then
                 x_congestion="1"
             else
                 x_congestion="0"
             fi

             local x_headtype_tcp="" x_headtype_kcp="" x_headtype_quic="" x_alpn_h2="" x_alpn_http=""

            case ${x_type} in
                tcp) x_headtype_tcp=${x_headerType:-none} ;;
                kcp) x_headtype_kcp=${x_headerType:-none} ;;
                ws|h2) x_host="${x_host}" ;; # Host used directly
                quic) x_headtype_quic=${x_headerType:-none} ;;
                grpc)
                    x_grpc_mode=${x_grpc_mode:-gun}
                    [ -n "$x_serviceName" ] && x_path="$x_serviceName"
                    x_host=""
                    ;;
            esac

            if [ "${x_security}" = "tls" ] || [ "${x_security}" = "xtls" ] || [ "${x_security}" = "reality" ]; then
                local x_alpn=$(echo "$(_get_param 'alpn')" | urldecode)
                [ -n "$(echo "$x_alpn" | grep 'h2')" ] && x_alpn_h2="1"
                [ -n "$(echo "$x_alpn" | grep 'http/1.1')" ] && x_alpn_http="1"
            fi

            if [ -z "$x_uuid" ]; then
                echo_date "🔴链式VLESS节点：基础协议部分解析UUID失败。"
                return 1
            fi

            json_add_string server "$base_server"
            json_add_string port "$base_port"
            json_add_string xray_uuid "$x_uuid"
            json_add_string xray_prot "vless" # Hardcode to vless
            json_add_string xray_encryption "$x_encryption"
            json_add_string xray_network "$x_type"
            json_add_string xray_network_security "$x_security"
            json_add_string xray_flow "$x_flow"
            json_add_string xray_network_host "$x_host"
            json_add_string xray_network_path "$x_path"
            json_add_string xray_headtype_tcp "$x_headtype_tcp"
            json_add_string xray_headtype_kcp "$x_headtype_kcp"
            json_add_string xray_kcp_seed "$x_kcp_seed"
            json_add_string xray_kcp_congestion "$x_congestion" # (Fix) Add congestion
            json_add_string xray_headtype_quic "$x_headtype_quic"
            json_add_string xray_grpc_mode "$x_grpc_mode"
            json_add_string xray_network_security_sni "$x_sni"
            json_add_string xray_network_security_alpn_h2 "$x_alpn_h2"
            json_add_string xray_network_security_alpn_http "$x_alpn_http"
            json_add_string xray_fingerprint "$x_fp"
            json_add_string xray_publickey "$x_pbk"
            json_add_string xray_shortid "$x_sid"
            json_add_string xray_spiderx "$x_spx"
            json_add_string xray_show "0" # Default show to 0
            json_add_string xray_use_json "0" # Assume not using json
            ;;
    esac

    # Add accelerator details
    json_add_string accel_mode "$accel_mode"
    if [ "$kcp_present" -eq 1 ]; then
        json_add_string kcp_rserver "$kcp_rserver"
        json_add_string kcp_rport "$kcp_rport"
        json_add_string kcp_param "$kcp_param"
    fi
     if [ "$udp_present" -eq 1 ]; then
        json_add_string udp2raw_rserver "$udp2raw_rserver"
        json_add_string udp2raw_rport "$udp2raw_rport"
        # Append -k <key> to udp2raw_param if key exists and not already in param
        local udp_param_to_write="$udp2raw_param"
        if [ -n "$udp2raw_key" ] && ! echo " $udp2raw_param " | grep -q -- " -k "; then
             udp_param_to_write="${udp2raw_param} -k ${udp2raw_key}"
             # Trim potential leading/trailing space again
             udp_param_to_write=$(echo "$udp_param_to_write" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        fi
        json_add_string udp2raw_param "$udp_param_to_write"
    fi

    # Write the combined JSON object
    if [ "${action}" == "1" ];then
        # This part is for online subscription, currently called with action=2
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}


decode_urllink(){
	# legacy
	read link
	local flag=$1
	local len=${#link}
	local mod4=$(($len%4))
	local var="===="
	#[ "${mod4}" -gt "0" ] && local link=${link}${var:${mod4}}
	local link=${link}${var:${mod4}}
	local decode_info=$(echo -n "${link}" | sed 's/-/+/g;s/_/\//g' | base64 -d 2>/dev/null)
	# 如果解析出乱码，返回空值，避免skipd中写入乱码value导致错误！
	echo -n "${decode_info}" | isutf8 -q
	if [ "$?" != "0" ];then
		echo ""
		return 1
	fi
	# 如果解析出多行结果，返回空值，避免skipd中写入多行value导致错误！
	if [ -z "${flag}" ];then
		local is_multi=$(echo "${decode_info}" | wc -l)
		if [ "${is_multi}" -gt "1" ];then
			echo ""
			return 2
		fi
	fi
	# 返回解析结果
	echo -n "${decode_info}"
	return 0
}

json2skipd(){
	local file_name=$1
	cat > $DIR/${file_name}.sh <<-EOF
		#!/bin/sh
		source /koolshare/scripts/base.sh
		#------------------------
	EOF
	NODE_INDEX=$(dbus list ssconf_basic_name_ | sed -n 's/^.*_\([0-9]\+\)=.*/\1/p' | sort -rn | sed -n '1p')
	[ -z "${NODE_INDEX}" ] && NODE_INDEX="0"
	local count=$(($NODE_INDEX + 1))
	while read nodes; do
		echo ${nodes} | sed 's/\",\"/\"\n\"/g;s/^{//;s/}$//' | sed 's/^\"/dbus set ssconf_basic_/g' | sed "s/\":/_${count}=/g" >>$DIR/${file_name}.sh
		let count+=1
	done < $DIR/${file_name}.txt
	#echo dbus save ssconf >>$DIR/${file_name}.sh
	chmod +x $DIR/${file_name}.sh
	sh $DIR/${file_name}.sh
	echo_date "🆗节点信息写入成功！"
	sync
}

skipdb2json(){
	if [ "${SEQ_NU}" == "0" ];then
		return
	fi
	echo_date "➡️开始整理本地节点到文件，请稍等..."
	# 将所有节点数据储存到文件，顺便清理掉空值的key
	dbus list ssconf_basic_ | grep -E "_[0-9]+=" | sed '/^ssconf_basic_.\+_[0-9]\+=$/d' | sed 's/^ssconf_basic_//' >${DIR}/ssconf_keyval.txt
	NODES_SEQ=$(cat ${DIR}/ssconf_keyval.txt | sed -n 's/name_\([0-9]\+\)=.*/\1/p'| sort -n)
	for nu in ${NODES_SEQ}
	do
		# cat ssconf_keyval.txt |grep _2=|sed "s/_2=/\":\"/"|sed 's/^/"/;s/$/\"/;s/$/,/g;1 s/^/{/;$ s/,$/}/'| tr -d '\n' |sed 's/$/\n/'
		cat ${DIR}/ssconf_keyval.txt | grep "_${nu}=" | sed "s/_${nu}=/\":\"/" | sed 's/^/"/;s/$/\"/;s/$/,/g;1 s/^/{/;$ s/,$/}/' | tr -d '\n' | sed 's/$/\n/' >>${LOCAL_NODES_SPL}
	done
	if [ -f "${LOCAL_NODES_SPL}" ];then
		echo_date "📁所有本地节点成功整理到文件：${LOCAL_NODES_SPL}"
		cp -rf ${LOCAL_NODES_SPL} ${LOCAL_NODES_BAK}
	else
		echo_date "⚠️节点文件处理失败！请重启路由器后重试！"
		exit 1
	fi
}

nodes2files(){
	if [ "${SEQ_NU}" == "0" ];then
		return
	fi
	rm -rf $DIR/local_*.txt
	local SP_NAME
	local SP_NUBS
	local SP_COUN=0
	local SP_STAT=$(cat ${LOCAL_NODES_SPL}|run jq -rc '.group'|awk -F "_" '{print $NF}'|uniq -c|sed 's/^[[:space:]]\+//g' | sed 's/[[:space:]]/|/g')
	for SP_LINE in ${SP_STAT}
	do
		SP_NAME=$(echo ${SP_LINE} | awk -F"|" '{print $2}')
		SP_NUBS=$(echo ${SP_LINE} | awk -F"|" '{print $1}')
		if [ "${SP_NAME}" == "null" -o -z "${SP_NAME}" ];then
			# echo_date "📂拆分：local_0_user.txt，共计${SP_NUBS}个节点！"
			sed -n "1,${SP_NUBS}p" ${LOCAL_NODES_SPL} >>$DIR/local_0_user.txt
		else
			local EXIST_FILE=$(ls -l $DIR/local_*_${SP_NAME}.txt 2>/dev/null)
			if [ -n "${EXIST_FILE}" ];then
				local EXIST_NU=$(echo $EXIST_FILE|head -n1|awk -F "/" '{print $NF}'|awk -F "_" '{print $2}')
				# echo_date "📂拆分：local_${EXIST_NU}_${SP_NAME}.txt，共计${SP_NUBS}个节点！"
				sed -n "1,${SP_NUBS}p" ${LOCAL_NODES_SPL} >>$DIR/local_${EXIST_NU}_${SP_NAME}.txt
			else
				let SP_COUN+=1
				# echo_date "📂拆分：local_${SP_COUN}_${SP_NAME}.txt，共计${SP_NUBS}个节点！"
				sed -n "1,${SP_NUBS}p" ${LOCAL_NODES_SPL} >>$DIR/local_${SP_COUN}_${SP_NAME}.txt
			fi
		fi
		sed -i "1,${SP_NUBS}d" ${LOCAL_NODES_SPL}
	done

	if [ "$(ls -l ${LOCAL_NODES_SPL} |awk '{print $5}')" != "0" ];then
		echo_date "⚠节点文件处理失败！请重启路由器后重试！"
		exit 1
	fi
}

nodes_stats(){
	echo_date "-----------------------------------"
	local GROP
	local NUBS
	local TTNODE=$(cat ${LOCAL_NODES_BAK} 2>/dev/null| wc -l)
	local NFILES=$(find $DIR -name "local_*.txt" | sort -n)
	if [ -n "${NFILES}" ];then
		echo_date "📢当前节点统计信息：共有节点${TTNODE}个，其中："
		for file in ${NFILES}
		do
			GROP=$(cat $file | run jq -c '.group' | sed 's/""/null/;s/^"//;s/"$//;s/_\w\+$//' | sort -u | sed 's/$/ + /g' | sed ':a;N;$!ba;s#\n##g' | sed 's/ + $//g')
			NUBS=$(cat $file | wc -l)
			if [ "${GROP}" == "null" ];then
				GROP_NAME="😛【用户自添加】节点"
			else
				GROP_NAME="🚀【${GROP}】机场节点"
			fi
			echo_date ${GROP_NAME}: ${NUBS}个
		done
	else
		echo_date "📢当前尚无任何节点...继续！"
	fi
	echo_date "-----------------------------------"
}

remove_null(){
	if [ "${SEQ_NU}" == "0" ];then
		# 没有节点，不进行检查
		return
	fi
	if [ "$(dbus list ssconf_|grep _group|wc -l)" == "0" ];then
		# 没有订阅节点，不进行检查
		return
	fi
	local online_sub_urls=$(dbus get ss_online_links | base64 -d | sed '/^$/d' | sed '/^#/d'| sed 's/^[[:space:]]//g' | sed 's/[[:space:]]&//g' | grep -E "^http" | sed 's/[[:space:]]/%20/g')
	for online_sub_url in ${online_sub_urls}
	do
		local sublink_hash=$(echo ${online_sub_url} | sed 's/%20/ /g' | md5sum | awk '{print $1}')
		echo ${sublink_hash:0:4} >> $DIR/sublink_hash.txt
	done

	local local_hashs=$(find $DIR -name "local_*.txt" | sort -n | xargs cat | run jq -r '.group' | awk -F "_" '{print $NF}' | grep -v "null" | sort -u)
	for local_hash in $local_hashs
	do
		local match_hash=$(cat $DIR/sublink_hash.txt | grep -Eo "${local_hash}")
		if [ -z "${match_hash}" ];then
			# remove node
			local _local_group=$(cat $DIR/local_*_${local_hash}.txt | run jq -rc '.group' | sed 's/_.*$//' | sort -u | sed 's/$/ + /g' | sed ':a;N;$!ba;s#\n##g' | sed 's/ + $//g')
			echo_date "⚠️检测到【${_local_group}】机场已经不再订阅！尝试删除该订阅的节点！"
			rm -rf $DIR/local_*_${local_hash}.txt
		fi
	done
}

clear_nodes(){
	# 写入节点钱需要清空所有ssconf配置
	if [ "${SEQ_NU}" == "0" ];then
		return
	fi
	echo_date "⌛节点写入前准备..."
	dbus list ssconf_basic_|awk -F "=" '{print "dbus remove "$1}' >$DIR/ss_nodes_remove.sh
	chmod +x $DIR/ss_nodes_remove.sh
	sh $DIR/ss_nodes_remove.sh
	sync
	[ -n "${CURR_NODE}" ] && dbus set ssconf_basic_node=$CURR_NODE
	echo_date "🆗准备完成！"
}

get_type_name() {
	case "$1" in
		0)
			echo "ss"
		;;
		1)
			echo "ssr"
		;;
		3)
			echo "V2ray"
		;;
		4)
			echo "xray"
		;;
		5)
			echo "trojan"
		;;
		6)
			echo "NaïveProxy"
		;;
		7)
			echo "tuic"
		;;
		8)
			echo "hysteria2"
		;;
	esac
}

# 清除已有的所有旧配置的节点
remove_all_node(){
	echo_date "删除所有节点信息！"
	confs=$(dbus list ssconf_basic_ | cut -d "=" -f1 | awk '{print $NF}')
	for conf in ${confs}
	do
		#echo_date "移除配置：${conf}"
		dbus remove ${conf}
	done
	# remove group name
	for conf1 in $(dbus list ss_online_group|awk -F"=" '{print $1}')
	do
		dbus remove ${conf1}
	done

	# remove group hash
	for conf2 in $(dbus list ss_online_hash|awk -F"=" '{print $1}')
	do
		dbus remove ${conf2}
	done
	echo_date "删除成功！"
}

# 删除所有订阅节点
remove_sub_node(){
	echo_date "删除所有订阅节点信息...自添加的节点不受影响！"
	#remove_node_info
	remove_nus=$(dbus list ssconf_basic_group_ | sed -n 's/ssconf_basic_group_\([0-9]\+\)=.\+$/\1/p' | sort -n)
	if [ -z "${remove_nus}" ]; then
		echo_date "节点列表内不存在任何订阅来源节点，退出！"
		return 1
	fi

	for remove_nu in ${remove_nus}
	do
		echo_date "移除第$remove_nu节点：【$(dbus get ssconf_basic_name_${remove_nu})】"
		dbus list ssconf_basic_|grep "_${remove_nu}="|sed -n 's/\(ssconf_basic_\w\+\)=.*/\1/p' |  while read key
		do
			dbus remove $key
		done
	done

	echo_date "所有订阅节点信息已经成功删除！"
}

check_nodes(){
	if [ "${SEQ_NU}" == "0" ];then
		return
	fi
	mkdir -p ${DIR}
	local BACKUP_FILE=${DIR}/ss_conf.sh
	echo_date "➡️开始节点数据检查..."
	local ADJUST=0
	local MAX_NU=${NODE_INDEX}
	dbus list ssconf_basic_ | grep -E "_[0-9]+=" >${DIR}/ssconf_keyval_origin.txt
	local KEY_NU=$(cat ${DIR}/ssconf_keyval_origin.txt | wc -l)
	local VAL_NU=$(cat ${DIR}/ssconf_keyval_origin.txt | cut -d "=" -f2 | sed '/^$/d' | wc -l)
	echo_date "ℹ️最大节点序号：${MAX_NU}"
	echo_date "ℹ️共有节点数量：${SEQ_NU}"

	# 如果[节点数量 ${SEQ_NU}]不等于[最大节点序号 ${MAX_NU}]，说明节点排序是不正确的。
	if [ ${SEQ_NU} -ne ${MAX_NU} ]; then
		local ADJUST=1
		echo_date "⚠️节点顺序不正确，需要调整！"
	fi

	# 如果key的数量不等于value的数量，说明有些key储存了空值，需要清理一下。
	if [ ${KEY_NU} -ne ${VAL_NU} ]; then
		echo_date "KEY_NU $KEY_NU"
		echo_date "VAL_NU $VAL_NU"
		local ADJUST=1
		echo_date "⚠️节点配置有残余值，需要清理！"
	fi

	if [ ${ADJUST} == "1" ]; then
		# 提取干净的节点配置，并重新排序，现在web界面里添加/删除节点后会自动排序，所以以下基本不会运行到
		echo_date "💾备份所有节点信息并重新排序..."
		echo_date "⌛如果节点数量过多，此处可能需要等待较长时间，请耐心等待..."
		rm -rf ${BACKUP_FILE}
		cat > ${BACKUP_FILE} <<-EOF
			#!/bin/sh
			source /koolshare/scripts/base.sh
			#------------------------
			# remove all nodes first
			confs=\$(dbus list ssconf_basic_ | cut -d "=" -f 1)
			for conf in \$confs
			do
			    dbus remove \$conf
			done
			usleep 300000
			#------------------------
			# rewrite all node in order
		EOF

		# node to json file
		sed -i '/^ssconf_basic_.\+_[0-9]\+=$/d' ${DIR}/ssconf_keyval_origin.txt
		local count="1"
		for nu in ${NODES_SEQ}
		do
			cat ${DIR}/ssconf_keyval_origin.txt | grep "_${nu}=" | sed "s/_${nu}=/_${count}=\"/g;s/^/dbus set /;s/$/\"/" >>${BACKUP_FILE}
			let count+=1
		done
		echo_date "⌛备份完毕，开始调整..."
		# 2 应用提取的干净的节点配置
		chmod +x ${BACKUP_FILE}
		sh ${BACKUP_FILE}
		echo_date "ℹ️节点调整完毕！"
		
		# 重新获取节点序列
		NODES_SEQ=$(dbus list ssconf_basic_name_ | sed -n 's/^.*_\([0-9]\+\)=.*/\1/p' | sort -n)
		NODE_INDEX=$(echo ${NODES_SEQ} | sed 's/.*[[:space:]]//')
	else
		echo_date "🆗节点顺序正确，节点配置信息OK！"
	fi
}

filter_nodes(){
	# ------------------------------- 关键词匹配逻辑 -------------------------------
	# 用[排除]和[包括]关键词去匹配，剔除掉用户不需要的节点，剩下的需要的节点：UPDATE_FLAG=0，
	# UPDATE_FLAG=0,需要的节点；1.判断本地是否有此节点，2.如果有就添加，没有就判断是否需要更新
	# UPDATE_FLAG=2,不需要的节点；1. 判断本地是否有此节点，2.如果有就删除，没有就不管
	if [ -z "${KEY_WORDS_1}" -a -z "${KEY_WORDS_2}" ];then
		return 0
	fi
	local _type=$1
	local remarks=$2
	local server=$3
	[ -n "${KEY_WORDS_1}" ] && local KEY_MATCH_1=$(echo ${remarks} ${server} | grep -Eo "${KEY_WORDS_1}")
	[ -n "${KEY_WORDS_2}" ] && local KEY_MATCH_2=$(echo ${remarks} ${server} | grep -Eo "${KEY_WORDS_2}")
	if [ -n "${KEY_WORDS_1}" -a -z "${KEY_WORDS_2}" ]; then
		# 排除节点：yes，包括节点：no
		if [ -n "${KEY_MATCH_1}" ]; then
			echo_date "⚪${_type}节点：【${remarks}】，不添加，因为匹配了[排除]关键词"
			let exclude+=1 
			return 1
		else
			return 0
		fi
	elif [ -z "${KEY_WORDS_1}" -a -n "${KEY_WORDS_2}" ]; then
		# 排除节点：no，包括节点：yes
		if [ -z "${KEY_MATCH_2}" ]; then
			echo_date "⚪${_type}节点：【${remarks}】，不添加，因为不匹配[包括]关键词"
			let exclude+=1 
			return 1
		else
			return 0
		fi
	elif [ -n "${KEY_WORDS_1}" -a -n "${KEY_WORDS_2}" ]; then
		# 排除节点：yes，包括节点：yes
		if [ -n "${KEY_MATCH_1}" -a -z "${KEY_MATCH_2}" ]; then
			echo_date "⚪${_type}节点：【${remarks}】，不添加，因为匹配了[排除+包括]关键词"
			let exclude+=1 
			return 1
		elif [ -n "${KEY_MATCH_1}" -a -n "${KEY_MATCH_2}" ]; then
			echo_date "⚪${_type}节点：【${remarks}】，不添加，因为匹配了[排除]关键词"
			let exclude+=1 
			return 1
		elif  [ -z "${KEY_MATCH_1}" -a -z "${KEY_MATCH_2}" ]; then
			echo_date "⚪${_type}节点：【${remarks}】，不添加，因为不匹配[包括]关键词"
			let exclude+=1 
			return 1
		else
			return 0
		fi
	else
		return 0
	fi
}

add_ss_node(){
	local urllink="$1"
	local action="$2"
	unset info_first string_nu decrypt_info server_raw encrypt_method password remarks server server_port 
	unset plugin_support obfs_para plugin_prog ss_obfs ss_obfs_host ss_v2ray ss_v2_opts group
	# 目前发现4种类型的节点：
	# 1. ss://YWVzLTEyOC1nY206RkFOQ1lTU19QQVNT@fancyss.net:111/?group=ZmFuY3lzX3Rlc3Q=#FANCYSS%20SS%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B91%0A
	# 2. ss://2022-blake3-aes-256-gcm:czh9CYElDUxw9Y94bzTPjx2Q8URybABYROeiFwZ3o4U=@11.22.33.44:222#FANCYSS%20SS%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B92%0A
	# 3. ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206TWtjeGJsTkJXbUpKemRvY25ERUpOSk5BUw==@11.22.33.44:333#FANCYSS%20SS%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B93%0A
	# 4. ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpGQU5DWVNTX1BBU1NAdGVzdC5mYW5jeXNzLmNvbTo0NDQ=#FANCYSS%20SS%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B94%0A

	info_first=$(echo "${urllink}" | sed 's/[@:/?#]/\n/g' | sed -n '1p')
	dec64 "${info_first}" >/dev/null 2>&1
	if [ "$?" == "0" ];then
		# first string is base64
		string_nu=$(echo "${urllink}" | sed 's/[@:/?#]/\n/g' | wc -l)
		if [ "${string_nu}" -eq "2" ];then
			# method:password@server:port are base64
			decrypt_info=$(dec64 "${info_first}")
			server_raw=$(echo "${decrypt_info}" | sed -n 's/.\+@\(.\+:[0-9]\+\).*/\1/p')
			if [ -n "${server_raw}" ];then
				server=$(echo "${server_raw}" | awk -F':' '{print $1}')
				server_port=$(echo "${server_raw}" | awk -F':' '{print $2}')
			fi
			encrypt_method=$(echo "${decrypt_info}" | awk -F':' '{print $1}')
			password=$(echo "${decrypt_info}" | sed 's/@/|/g;s/:/|/g;s/?/|/g;s/#/|/g' | awk -F'|' '{print $2}')
		elif [ "${string_nu}" -gt "2" ];then
			# method:passwor are base64
			decrypt_info=$(dec64 "${info_first}")
			server_raw=$(echo "${urllink}" | sed -n 's/.\+@\(.\+:[0-9]\+\).*/\1/p')
			if [ -n "${server_raw}" ];then
				server=$(echo "${server_raw}" | awk -F':' '{print $1}')
				server_port=$(echo "${server_raw}" | awk -F':' '{print $2}')
			fi
			encrypt_method=$(echo "${decrypt_info}" | awk -F':' '{print $1}')
			password=$(echo "${decrypt_info}" | sed 's/@/|/g;s/:/|/g;s/?/|/g;s/#/|/g' | awk -F'|' '{print $2}')
		fi
	else
		# first string not base64
		# method:password@server:port/?group=group#remark
		encrypt_method=${info_first}
		server_raw=$(echo "${urllink}" | sed -n 's/.\+@\(.\+:[0-9]\+\).*/\1/p')
		if [ -n "${server_raw}" ];then
			server=$(echo "${server_raw}" | awk -F':' '{print $1}')
			server_port=$(echo "${server_raw}" | awk -F':' '{print $2}')
		fi
		password=$(echo "${urllink}" | sed 's/[@:/?#]/\n/g' | sed -n '2p')
	fi

	#remarks=$(echo "${urllink}" | sed -n 's/.*#\(.*\).*$/\1/p' | sed 's/@.*$//g' | urldecode | sed 's/^[[:space:]]//g')
	remarks=$(echo "${urllink}" | sed -n 's/.*#\(.*\).*$/\1/p' | urldecode | sed 's/^[[:space:]]//g')
	echo "${remarks}" | isutf8 -q
	if [ "$?" != "0" ];then
		echo_date "当前节点名中存在特殊字符，节点添加后可能出现乱码！"
		remarks=""
	fi
	
	if [ "${action}" == "1" ];then
		group=$(echo "${urllink}" | sed -n 's/.\+group=\(.\+\)#.\+/\1/p')
		if [ -n "${group}" ];then
			group=$(dec64 $group)
		else
			group=${DOMAIN_NAME}
		fi
	fi

	password=$(echo ${password} | base64_encode | sed 's/[[:space:]]//g')
	plugin_support=$(echo "${urllink}"|grep -Eo "plugin=")
	if [ -n "${plugin_support}" ];then
		obfs_para=$(echo "${urllink}" | sed -n 's/.\+plugin=\(\)/\1/p'|sed 's/@/|/g;s/:/|/g;s/?/|/g;s/#/|/g' | awk -F'|' '{print $1}'| urldecode)
		plugin_prog=$(echo "${obfs_para}" | awk -F';' '{print $1}')
		if [ "${plugin_prog}" == "obfs-local" -o "${plugin_prog}" == "simple-obfs" ];then
			ss_obfs=$(echo "${obfs_para}" | awk -F';' '{print $2}'| awk -F'=' '{print $2}')
			ss_obfs_host=$(echo "${obfs_para}" | awk -F';' '{print $3}'| awk -F'=' '{print $2}')
			ss_v2ray="0"
			ss_v2_opts=""
		elif [ "${plugin_prog}" == "v2ray-plugin" ];then
			ss_obfs="0"
			ss_obfs_host=""
			ss_v2ray="1"
			ss_v2_opts=$(echo "${obfs_para}" | sed 's/v2ray-plugin;//g')
		fi
	else
		ss_obfs="0"
		ss_obfs_host=""
		ss_v2ray="0"
		ss_v2_opts=""
	fi

	# echo ------------------------
	# echo info_first: ${info_first}
	# echo decrypt_info: ${decrypt_info}
	# echo remarks: ${remarks}
	# echo server: ${server}
	# echo server_port: ${server_port}
	# echo encrypt_method: ${encrypt_method}
	# echo password: ${password}
	# echo plugin_prog: ${plugin_prog}
	# echo ss_obfs: ${ss_obfs}
	# echo ss_obfs_host: ${ss_obfs_host}
	# echo ss_v2ray: ${ss_v2ray}
	# echo ss_v2_opts: ${ss_v2_opts}
	# echo ------------------------

	if [ -z "${server}" -o -z "${remarks}" -o -z "${server_port}" -o -z "${password}" -o -z "${encrypt_method}" ]; then
		echo_date "🔴SS节点：检测到一个错误节点，跳过！"
		return 1
	fi

	# 过滤节点
	if [ "${action}" == "1" ]; then
		filter_nodes "SS" "${remarks}" "${server}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi
	
	echo_date "🟢SS节点：${remarks}"
	
	json_init
	
	json_add_string accel_mode "0"
	json_add_string hy2_server ""
	json_add_string naive_server ""
	
	json_add_string group "${group}_${SUB_LINK_HASH:0:4}"
	json_add_string method "${encrypt_method}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${remarks}"
	json_add_string password "${password}"
	json_add_string port "${server_port}"
	json_add_string server "${server}"
	json_add_string ss_obfs "${ss_obfs}"
	json_add_string ss_obfs_host "${ss_obfs_host}"
	json_add_string ss_v2ray "${ss_v2ray}"
	json_add_string ss_v2ray_opts "${v2_plugin_opts}"
	json_add_string type "0"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

add_ssr_node(){
	local urllink="$1"
	local action="$2"
	unset decrypt_info server server_port protocol encrypt_method obfs password obfsparam_temp obfsparam protoparam_temp protoparam remarks_temp remarks group_temp group

	local decrypt_info=$(dec64 ${urllink})

	# mysql.accessconnect.cc:699:auth_aes128_md5:rc4-md5:tls1.2_ticket_auth:ZGkxNVBW/?obfsparam=MWRjZjMxOTg2NjEud3d3Lmdvdi5oaw&protoparam=MTk4NjYxOjMydUk5RQ&remarks=TGFyZ2Ug5Y-w54GjMDQgLSBJRVBMIHwg5YCN546HOjEuNQ&group=5rW36LGa5rm-
	# server:port:protocol:method:obfs:password/?obfsparam=xxx&protoparam=xxx&remarks=xxx&group=xxx
	server=$(echo "${decrypt_info}" | awk -F':' '{print $1}' | sed 's/[[:space:]]//g')
	server_port=$(echo "${decrypt_info}" | awk -F':' '{print $2}')
	encrypt_method=$(echo "${decrypt_info}" |awk -F':' '{print $4}')
	password=$(echo "${decrypt_info}" | awk -F':' '{print $6}' | awk -F'/' '{print $1}')
	
	protocol=$(echo "${decrypt_info}" | awk -F':' '{print $3}')
	protoparam_temp=$(echo "${decrypt_info}" | awk -F':' '{print $6}' | grep -Eo "protoparam.+" | sed 's/protoparam=//g' | awk -F'&' '{print $1}')
	if [ -n "${protoparam_temp}" ];then
		protoparam=$(dec64 ${protoparam_temp} | sed 's/_compatible//g' | sed 's/[[:space:]]//g')
	else
		protoparam=""
	fi
	
	obfs=$(echo "${decrypt_info}" | awk -F':' '{print $5}' | sed 's/_compatible//g')
	ssr_subscribe_obfspara=$(dbus get ssr_subscribe_obfspara)
	obfsparam_temp=$(echo "${decrypt_info}" | awk -F':' '{print $6}' | grep -Eo "obfsparam.+" | sed 's/obfsparam=//g' | awk -F'&' '{print $1}')
	if [ -n "${obfsparam_temp}" ];then
		obfsparam=$(dec64 ${obfsparam_temp})
	else
		obfsparam=""
	fi
	remarks_temp=$(echo "${decrypt_info}" | awk -F':' '{print $6}' | grep -Eo "remarks.+" | sed 's/remarks=//g' | awk -F'&' '{print $1}')
	# 在线订阅必须要remarks信息
	if [ "${action}" == "1" ]; then
		if [ -n "${remarks_temp}" ];then
			remarks=$(dec64 ${remarks_temp})
		else
			remarks=""
		fi
	elif [ "${action}" == "2" ]; then
		if [ -n "${remarks_temp}" ];then
			remarks=$(dec64 ${remarks_temp})
		else
			remarks="${server}"
		fi
	fi
	group_temp=$(echo "${decrypt_info}" | awk -F':' '{print $6}' | grep -Eo "group.+" | sed 's/group=//g' | awk -F'&' '{print $1}')
	if [ "${action}" == "1" ]; then
		# 在线订阅，group从订阅链接里拿
		if [ -n "${group_temp}" ];then
			ssr_group=$(dec64 $group_temp)
		else
			ssr_group=${DOMAIN_NAME}
		fi
		ssr_group_hash="${ssr_group}_${SUB_LINK_HASH:0:4}"
	elif [ "${action}" == "2" ]; then
		# 离线离线添加节点，group不需要
		ssr_group=""
		ssr_group_hash=""
	fi
	
	# for debug, please keep it here~
	# echo ------------
	# echo group: $group
	# echo remarks: $remarks
	# echo server: $server
	# echo server_port: $server_port
	# echo password: $password
	# echo encrypt_method: $encrypt_method
	# echo protocol: $protocol
	# echo protoparam: $protoparam
	# echo obfs: $obfs
	# echo obfsparam: $obfsparam
	# echo ------------

	if [ -z "${server}" -o -z "${remarks}" -o -z "${server_port}" -o -z "${password}" -o -z "${protocol}" -o -z "${obfs}" -o -z "${encrypt_method}" ]; then
		echo_date "🔴SSR节点：检测到一个错误节点，跳过！"
		return 1
	fi

	# 过滤节点
	if [ "${action}" == "1" ]; then
		filter_nodes "SSR" "${remarks}" "${server}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi

	echo_date "🔵SSR节点：$remarks"
	
	json_init
	json_add_string group "${ssr_group_hash}"
	json_add_string method "${encrypt_method}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${remarks}"
	json_add_string password "${password}"
	json_add_string port "${server_port}"
	json_add_string rss_obfs "${obfs}"
	json_add_string rss_obfs_param "${obfsparam}"
	json_add_string rss_protocol "${protocol}"
	json_add_string rss_protocol_param "${protoparam}"
	json_add_string server "${server}"
	json_add_string type "1"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

json_query(){
	echo "${2}" | sed 's/^{//;s/}$//;s/,"/,\n"/g;s/":"/":/g' | sed 's/,$//g;s/"$//g' | sed -n "s/^\"${1}\":\(.\+\)\$/\1/p"
}

add_vmess_node(){
	local urllink="$1"
	local action="$2"
	unset decrypt_info v_remark_tmp v_ps v_add v_port v_id v_aid v_scy v_net v_type
	unset v_headerType_tmp v_headtype_tcp v_headtype_kcp v_headtype_quic v_grpc_mode v_tls v_kcp_seed
	unset v_ai_tmp v_ai v_alpn v_alpn_h2_tmp v_alpn_http_tmp v_alpn_h2 v_alpn_http v_sni v_v v_host v_path v_group v_group_hash
	decrypt_info=$(dec64 ${urllink} | run jq -c '.')
	# node name, could be ps/remark in sub json，必须项
	
	v_ps=$(json_query ps "${decrypt_info}")
	[ -z "${v_ps}" ] && v_ps=$(json_query remark "${decrypt_info}")

	# node server addr，必须项
	v_add=$(json_query add "${decrypt_info}")

	# node server port，必须项
	v_port=$(json_query port "${decrypt_info}")

	# node uuid，必须项
	v_id=$(json_query id "${decrypt_info}")

	# alterid，必须项，如果为空则填0
	v_aid=$(json_query aid "${decrypt_info}")
	[ -z "${v2ray_aid}" ] && v2ray_aid="0"

	# 加密方式 (security)，v2ray必须字段，订阅中机场很多不提供该值，设为auto就好了
	v_scy=$(json_query scy "${decrypt_info}")
	[ -z "${v_scy}" ] && v_scy="auto"
	
	# 传输协议: tcp kcp ws h2 quic grpc
	v_net=$(json_query net "${decrypt_info}")
	[ -z "${v_net}" ] && v_net="tcp"
	
	# 伪装类型，在tcp kcp quic中使用，grpc mode借用此字段，ws和h2中不使用
	v_type=$(json_query type "${decrypt_info}")
	[ -z "${v_type}" ] && v_type=$(json_query headerType "${decrypt_info}")

	case ${v_net} in
	tcp)
		# tcp协议设置【tcp伪装类型 (type)】
		v_headtype_tcp=${v_type}
		v_headtype_kcp=""
		v_headtype_quic=""
		v_grpc_mode=""
		[ -z "${v_headtype_tcp}" ] && v_headtype_tcp="none"
		;;
	kcp)
		# kcp协议设置【kcp伪装类型 (type)】
		v_headtype_tcp=""
		v_headtype_kcp=${v_type}
		v_headtype_quic=""
		v_grpc_mode=""
		[ -z "${v_headtype_kcp}" ] && v_headtype_kcp="none"
		;;
	ws|h2)
		# ws/h2协议设置【伪装域名 (host))】
		v_headtype_tcp=""
		v_headtype_kcp=""
		v_headtype_quic=""
		v_grpc_mode=""
		;;
	quic)
		# quic协议设置【quic伪装类型 (type)】
		v_headtype_tcp=""
		v_headtype_kcp=""
		v_headtype_quic=${v_type}
		v_grpc_mode=""
		[ -z "${v_headtype_quic}" ] && v_headtype_quic="none"
		;;
	grpc)
		# grpc协议设置【grpc模式】
		v_headtype_tcp=""
		v_headtype_kcp=""
		v_headtype_quic=""
		v_grpc_mode=${v_type}
		[ -z "${v_grpc_mode}" ] && v_grpc_mode="multi"
		;;
	esac

	# 底层传输安全：none, tls
	v_tls=$(json_query tls "${decrypt_info}")
	if [ "${v_tls}" == "tls" ];then

		# 跳过证书验证 (AllowInsecure)，此处在底层传输安全（network_security）为tls时使用
		v_ai_tmp=$(json_query verify_cert "${decrypt_info}")
		if [ "${v_ai_tmp}" == "true" ];then
			v_ai=""
		else
			v_ai="1"
		fi

		# alpn: h2; http/1.1; h2,http/1.1，此处在底层传输安全（network_security）为tls时使用
		v_alpn=$(json_query alpn "${decrypt_info}")
		v_alpn_h2_tmp=$(echo "${v_alpn}" | grep "h2")
		v_alpn_http_tmp=$(echo "${v_alpn}" | grep "http/1.1")
		if [ -n "${v_alpn_h2_tmp}" ];then
			v_alpn_h2="1"
		else
			v_alpn_h2=""
		fi
		if [ -n "${v_alpn_http_tmp}" ];then
			v_alpn_http="1"
		else
			v_alpn_http=""
		fi

		# SNI, 如果空则用host替代，如果host空则空，此处在底层传输安全（network_security）为tls时使用
		v_sni=$(json_query sni "${decrypt_info}")
	else
		v_tls="none"
		v_ai=""
		v_alpn_h2=""
		v_alpn_http=""
		v_sni=""
	fi

	# sub version, 1 or 2
	v_v=$(json_query v "${decrypt_info}")

	# v2ray host & path
	v_host=$(json_query host "${decrypt_info}")
	v_path=$(json_query path "${decrypt_info}")

	# host is not needed in kcp and grpc
	if [ "${v_net}" == "kcp" -o "${v_net}" == "grpc" ];then
		v_host=""
	fi

	if [ "${v_net}" == "kcp" ];then
		v_kcp_seed=${v_path}
	fi
	
	# 根据订阅版本不同，来设置host path
	if [ "${v_v}" != "2" -a "${v_net}" == "ws" -a -n "${v_host}" ]; then
		format_ws=$(echo ${v_host} | grep -E ";")
		if [ -n "${format_ws}" ]; then
			v_host=$(echo ${v_host} | cut -d ";" -f1)
			v_path=$(echo ${v_host} | cut -d ";" -f2)
		else
			v_host=""
			v_path=${v_host}
		fi
	fi

	if [ "${action}" == "1" ];then
		v_group=${DOMAIN_NAME}
		v_group_hash="${v_group}_${SUB_LINK_HASH:0:4}"
	fi
	
	# for debug
	# echo ------------------
	# echo vmess_v: ${v_v}
	# echo vmess_ps: ${v_ps}
	# echo vmess_add: ${v_add}
	# echo vmess_port: ${v_port}
	# echo vmess_id: ${v_id}
	# echo vmess_net: ${v_net}
	# echo vmess_type: ${v_type}
	# echo vmess_scy: ${v_scy}
	# echo vmess_host: ${v_host}
	# echo vmess_path: ${v_path}
	# echo vmess_tls: ${v_tls}
	# echo ------------------
	
	if [ -z "${v_ps}" -o -z "${v_add}" -o -z "${v_port}" -o -z "${v_id}" ];then
		# 丢弃无效节点
		echo_date "🔴vmess节点：检测到一个错误节点，跳过！"
		return 1
	fi

	# 过滤节点
	if [ "${action}" == "1" ]; then
		filter_nodes "vmess" "${v_ps}" "${v_add}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi

	echo_date "🟠vmess节点：${v_ps}"

	json_init
	json_add_string group "${v_group_hash}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${v_ps}"
	json_add_string port "${v_port}"
	json_add_string server "${v_add}"
	json_add_string type "3"
	json_add_string v2ray_alterid "${v_aid}"
	json_add_string v2ray_grpc_mode "${v_grpc_mode}"
	json_add_string v2ray_headtype_kcp "${v_headtype_kcp}"
	json_add_string v2ray_headtype_quic "${v_headtype_quic}"
	json_add_string v2ray_headtype_tcp "${v_headtype_tcp}"
	json_add_string v2ray_kcp_seed "${v_kcp_seed}"
	json_add_string v2ray_kcp_congestion "0"
	json_add_string v2ray_mux_enable "0"
	json_add_string v2ray_network "${v_net}"
	json_add_string v2ray_network_host "${v_host}"
	json_add_string v2ray_network_path "${v_path}"
	json_add_string v2ray_network_security "${v_tls}"
	json_add_string v2ray_network_security_ai "${v_ai}"
	json_add_string v2ray_network_security_alpn_h2 "${v_alpn_h2}"
	json_add_string v2ray_network_security_alpn_http "${v_alpn_http}"
	json_add_string v2ray_network_security_sni "${v_sni}"
	json_add_string v2ray_security "${v_scy}"
	json_add_string v2ray_use_json "0"
	json_add_string v2ray_uuid "${v_id}"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

add_vless_node(){
	local decode_link="$1"
	local action="$2"
	local strtype="$3"
	unset x_server_raw x_server x_server_port x_remarks x_uuid x_host x_path x_encryption x_type
	unset x_headerType x_headtype_tcp x_headtype_kcp x_headtype_quic x_grpc_modex_security_tmp x_security
	unset x_alpn x_alpn_h2_tmp x_alpn_http_tmp x_alpn_h2 x_alpn_http x_sni x_flow x_group x_group_hash x_kcp_seed
	unset x_fp x_pbk x_sid x_spx

	x_server_raw=$(echo "${decode_link}" | sed -n 's/.\+@\(.\+:[0-9]\+\).*/\1/p')
	x_server=$(echo "${x_server_raw}" | awk -F':' '{print $1}')
	x_server_port=$(echo "${x_server_raw}" | awk -F':' '{print $2}')

	echo "${decode_link}"|grep -Eqo "#"
	if [ "$?" != "0" ];then
		x_remarks=${x_server}
	else
		x_remarks=$(echo "${decode_link}" | awk -F"#" '{print $NF}' | urldecode)
	fi
	
	x_uuid=$(echo "${decode_link}" | awk -F"@" '{print $1}')
	if [ "${strtype}" == "vmess" ];then
		x_aid=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "alterId" | awk -F"=" '{print $2}')
	fi
	x_host=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "host" | awk -F"=" '{print $2}')
	x_path=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "path" | awk -F"=" '{print $2}' | urldecode)
	x_encryption=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "encryption" | awk -F"=" '{print $2}')
	if [ -z "${x_encryption}" ];then
		x_encryption="none"
	fi
	x_type=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "type" | grep -v "header" | awk -F"=" '{print $2}')
	if [ -z "${x_type}" ];then
		x_type="tcp"
	fi
	x_headerType=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "headerType" | awk -F"=" '{print $2}')
	x_mode=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "mode" | awk -F"=" '{print $2}')
	x_security=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "security" | awk -F"=" '{print $2}')
	x_serviceName=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "serviceName" | awk -F"=" '{print $2}' | urldecode)
	x_sni=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "sni" | awk -F"=" '{print $2}')
	
	x_flow=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "flow" | awk -F"=" '{print $2}')
	x_kcp_seed=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "seed" | awk -F"=" '{print $2}')
	x_fp=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "fp=" | awk -F"=" '{print $2}')
	
	
	x_pbk=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "pbk=" | awk -F"=" '{print $2}')
	x_sid=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "sid=" | awk -F"=" '{print $2}')
	x_spx=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "spx=" | awk -F"=" '{print $2}')
	case ${x_type} in
	tcp)
		x_headtype_tcp=${x_headerType}
		x_headtype_kcp=""
		x_headtype_quic=""
		x_grpc_mode=""
		if [ -z "${x_headtype_tcp}" ];then
			x_headtype_tcp="none"
		fi
		;;
	kcp)
		x_headtype_tcp=""
		x_headtype_kcp=${x_headerType}
		x_headtype_quic=""
		x_grpc_mode=""
		if [ -z "${x_headtype_kcp}" ];then
			x_headtype_kcp="none"
		fi
		;;
	ws)
		x_headtype_tcp=""
		x_headtype_kcp=""
		x_headtype_quic=""
		x_grpc_mode=""
		;;
	h2)
		x_headtype_tcp=""
		x_headtype_kcp=""
		x_headtype_quic=""
		x_grpc_mode=""
		if [ -z "${x_host}" ];then
			x_host="${x_server}"
		fi
		;;
	quic)
		x_headtype_tcp=""
		x_headtype_kcp=""
		x_headtype_quic=${x_headerType}
		x_grpc_mode=""
		if [ -z "${x_headtype_quic}" ];then
			x_headtype_quic="none"
		fi
		;;
	grpc)
		x_headtype_tcp=""
		x_headtype_kcp=""
		x_headtype_quic=""
		x_grpc_mode=${x_mode}
		if [ -n "${x_grpc_mode}" ];then
			x_grpc_mode="${x_grpc_mode}"
		else
			x_grpc_mode="gun"
		fi
		if [ -n "${x_serviceName}" ];then
			x_path="${x_serviceName}"
		fi
		;;
	esac

	if [ "${x_type}" == "kcp" -o "${x_type}" == "grpc" ];then 
		x_host=""
	fi


	if [ "${x_security}" == "tls" -o "${x_security}" == "xtls" ];then
		x_alpn=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "alpn" | awk -F"=" '{print $2}' | urldecode)
		x_alpn_h2_tmp=$(echo "${x_alpn}" | grep "h2")
		x_alpn_http_tmp=$(echo "${x_alpn}" | grep "http/1.1")
		if [ -n "${x_alpn_h2_tmp}" ];then
			x_alpn_h2="1"
		else
			x_alpn_h2=""
		fi
		if [ -n "${x_alpn_http_tmp}" ];then
			x_alpn_http="1"
		else
			x_alpn_http=""
		fi
	elif [ "${x_security}" == "reality" ];then
		if [ -z "${x_fp}" ];then
			x_fp="chrome"
		fi
		if [ "${x_type}" != "tcp" ];then
			x_flow=""
		fi
	fi
	
	if [ "${action}" == "1" ];then
		x_group=${DOMAIN_NAME}
		x_group_hash="${x_group}_${SUB_LINK_HASH:0:4}"
	elif [ "${action}" == "2" ]; then
		# 离线离线添加节点，group不需要
		x_group=""
		x_group_hash=""
	fi
	
	# # for debug, please keep it here
	# echo ------------
	# echo group: ${x_group_hash}
	# echo remarks: ${x_remarks}
	# echo x_server_raw: ${x_server_raw}
	# echo server: ${x_server}
	# echo server_port: ${x_server_port}
	# echo uuid: ${x_uuid}
	# echo encryption: ${x_encryption}
	# echo type: ${x_type}
	# echo security: ${x_security}
	# echo host: ${x_host}
	# echo sni: ${x_sni}
	# echo fingerprint: ${x_fp}
	# echo flow: ${x_flow}
	# echo publicKey: ${x_pbk}
	# echo shortId: ${x_sid}
	# echo spiderX: ${x_spx}
	# echo path: ${x_path}
	# echo headerType: ${x_headerType}
	# echo x_headtype_tcp: ${x_headtype_tcp}
	# echo x_headtype_kcp: ${x_headtype_kcp}
	# echo x_headtype_quic: ${x_headtype_quic}
	# echo x_grpc_mode: ${x_grpc_mode}
	# echo alpn: ${x_alpn}
	# echo ------------
	
	if [ -z "${x_server}" -o -z "${x_remarks}" -o -z "${x_server_port}" -o -z "${x_uuid}" ]; then
		# 丢弃无效节点
		if [ "${strtype}" == "vmess" ];then
			echo_date "🟠vmess节点：检测到一个错误节点，跳过！"
		else
			echo_date "🔴vless节点：检测到一个错误节点，跳过！"
		fi
		return 1
	fi

	# 过滤节点
	if [ "${action}" == "1" ]; then
		filter_nodes "vless" "${x_remarks}" "${x_server}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi

	if [ "${strtype}" == "vmess" ];then
		echo_date "🟠vmess节点：${x_remarks}"
	else
		echo_date "🟣vless节点：${x_remarks}"
	fi
	
	json_init
	# (关键修正) 明确写入初始值，防止UI显示混乱
	json_add_string accel_mode "0"
	json_add_string hy2_server ""
	json_add_string naive_server ""
	json_add_string group "${x_group_hash}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${x_remarks}"
	json_add_string port "${x_server_port}"
	json_add_string server "${x_server}"
	json_add_string type "4"
	json_add_string xray_alterid "${x_aid}"
	json_add_string xray_encryption "${x_encryption}"
	json_add_string xray_fingerprint "${x_fp}"
	json_add_string xray_flow "${x_flow}"
	json_add_string xray_grpc_mode "${x_grpc_mode}"
	json_add_string xray_headtype_kcp "${x_headtype_kcp}"
	json_add_string xray_headtype_quic "${x_headtype_quic}"
	json_add_string xray_headtype_tcp "${x_headtype_tcp}"
	json_add_string xray_kcp_seed "${x_kcp_seed}"
	json_add_string xray_kcp_congestion "1"
	json_add_string xray_network "${x_type}"
	json_add_string xray_network_host "${x_host}"
	json_add_string xray_network_path "${x_path}"
	json_add_string xray_network_security "${x_security}"
	#json_add_string xray_network_security_ai
	json_add_string xray_network_security_alpn_h2 "${x_alpn_h2}"
	json_add_string xray_network_security_alpn_http "${x_alpn_http}"
	json_add_string xray_network_security_sni "${x_sni}"
	json_add_string xray_prot "${strtype}"
	json_add_string xray_publickey "${x_pbk}"
	json_add_string xray_shortid "${x_sid}"
	json_add_string xray_show "0"
	json_add_string xray_spiderx "${x_spx}"
	#json_add_string xray_use_json
	json_add_string xray_uuid "${x_uuid}"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

add_trojan_node(){
	local decode_link="$1"
	local action="$2"
	unset t_server t_server_port t_remarks t_uuid t_ai t_tfo t_sni_tmp t_peer_tmp t_sni t_group t_group_hash
	
	t_server=$(echo "${decode_link}" | sed 's/@/ /g;s/:/ /g;s/?/ /g;s/#/ /g' | awk '{print $2}')
	t_server_port=$(echo "${decode_link}" | sed 's/@/ /g;s/:/ /g;s/?/ /g;s/#/ /g' | awk '{print $3}')

	echo "${decode_link}" | grep -Eqo "#"
	if [ "$?" != "0" ];then
		t_remarks=${t_server}
	else
		t_remarks=$(echo "${decode_link}" | awk -F"#" '{print $NF}' | urldecode)
	fi

	t_uuid=$(echo "${decode_link}" | awk -F"@" '{print $1}')
	t_ai=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "allowInsecure" | awk -F"=" '{print $2}')
	t_tfo=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "tfo" | awk -F"=" '{print $2}')
	t_sni_tmp=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "sni" | awk -F"=" '{print $2}')
	t_peer_tmp=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "peer" | awk -F"=" '{print $2}')
	if [ -n "${t_sni_tmp}" ];then
		t_sni=${t_sni_tmp}
	else
		if [ -n "${t_peer_tmp}" ];then
			t_sni=${t_peer_tmp}
		fi
	fi

	if [ "${action}" == "1" ];then
		t_group=${DOMAIN_NAME}
		t_group_hash="${t_group}_${SUB_LINK_HASH:0:4}"
	elif [ "${action}" == "2" ]; then
		# 离线离线添加节点，group不需要
		t_group=""
		t_group_hash=""
	fi
	
	# for debug, please keep it here
	# echo ------------
	# echo group: ${t_group}
	# echo remarks: ${t_remarks}
	# echo server: ${t_server}
	# echo port: ${t_server_port}
	# echo password: ${t_uuid}
	# echo allowInsecure: ${t_ai}
	# echo SNI: ${t_sni}
	# echo TFO: ${t_tfo}
	# echo ------------	

	if [ -z "${t_server}" -o -z "${t_remarks}" -o -z "${t_server_port}" -o -z "${t_uuid}" ]; then
		# 丢弃无效节点
		echo_date "🔴trojan节点：检测到一个错误节点，跳过！"
		return 1
	fi

	# 过滤节点
	if [ "${action}" == "1" ]; then
		filter_nodes "trojan" "${t_remarks}" "${t_server}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi

	echo_date "🟡trojan节点：${t_remarks}"
	
	json_init
	json_add_string group "${t_group_hash}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${t_remarks}"
	json_add_string port "${t_server_port}"
	json_add_string server "${t_server}"
	json_add_string trojan_ai "${t_ai}"
	json_add_string trojan_sni "${t_sni}"
	json_add_string trojan_tfo "${t_tfo}"
	json_add_string trojan_uuid "${t_uuid}"
	json_add_string type "5"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

# (修改) 重写函数，明确设置 accel_mode 和 server 字段的初始值
add_hy2_node(){
	local decode_link="$1"
	local action="$2"
	unset hy2_server hy2_server_port hy2_remarks hy2_uuid hy2_ai hy2_tfo hy2_sni_tmp hy2_peer_tmp hy2_sni hy2_group hy2_group_hash

	if [ -z "${HY2_UP_SPEED}" ];then
		echo_date "⚠️未在【更新管理】页面设置Hysteria2的默认上行速度，将使用 20 Mbps 作为默认值。"
		HY2_UP_SPEED="20"
	fi

	if [ -z "${HY2_DL_SPEED}" ];then
		echo_date "⚠️未在【更新管理】页面设置Hysteria2的默认下行速度，将使用 100 Mbps 作为默认值。"
		HY2_DL_SPEED="100"
	fi

	hy2_server=$(echo "${decode_link}" | sed 's/[@:/?#]/\n/g' | sed -n '2p')
	hy2_pass=$(echo "${decode_link}" | sed 's/[@:/?#]/\n/g' | sed -n '1p')
	hy2_port=$(echo "${decode_link}" | sed 's/[@:/?#]/\n/g' | sed -n '3p')

	echo "${decode_link}" | grep -Eqo "#"
	if [ "$?" != "0" ];then
		hy2_remarks=${hy2_server}
	else
		hy2_remarks=$(echo "${decode_link}" | awk -F"#" '{print $NF}' | urldecode)
	fi

	hy2_sni=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "sni" | awk -F"=" '{print $2}')
	hy2_obfs=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "obfs" | grep -v "obfs-password" | awk -F"=" '{print $2}')
	if [ -z "${hy2_obfs}" ];then
		hy2_obfs="0"
	fi
	if [ "${hy2_obfs}" == "salamander" ];then
		hy2_obfs="1"
	fi
	hy2_obfs_pass=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "obfs-password" | awk -F"=" '{print $2}')
	hy2_ai=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "insecure" | awk -F"=" '{print $2}')
	hy2_tfo=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "tfo" | awk -F"=" '{print $2}')
	if [ -z "${hy2_tfo}" ];then
		hy2_tfo="1"
	fi
	hy2_mport=$(echo "${decode_link}" | awk -F"?" '{print $2}'|sed 's/&/\n/g;s/#/\n/g' | grep "mport" | awk -F"=" '{print $2}')
	if [ -n "${hy2_mport}" ];then
		hy2_port=${hy2_mport}
	fi

	if [ "${action}" == "1" ];then
		hy2_group=${DOMAIN_NAME}
		hy2_group_hash="${hy2_group}_${SUB_LINK_HASH:0:4}"
	elif [ "${action}" == "2" ]; then
		hy2_group=""
		hy2_group_hash=""
	fi
	
	if [ -z "${hy2_server}" -o -z "${hy2_remarks}" -o -z "${hy2_port}" -o -z "${hy2_pass}" ]; then
		echo_date "🔴hysteria2节点：检测到一个错误节点，跳过！"
		return 1
	fi

	if [ "${action}" == "1" ]; then
		filter_nodes "hysteria2" "${hy2_remarks}" "${hy2_server}"
		if [ "$?" != "0" ];then
			return 1
		fi
	fi

	echo_date "🟤hysteria2节点：${hy2_remarks}"
	
	json_init
	
	# (关键修正) 明确写入初始值，防止UI显示混乱
	json_add_string server ""
	json_add_string accel_mode "0"

	json_add_string group "${hy2_group_hash}"
	json_add_string mode "${SUB_MODE}"
	json_add_string name "${hy2_remarks}"
	json_add_string hy2_server "${hy2_server}"
	json_add_string hy2_port "${hy2_port}"
	json_add_string hy2_pass "${hy2_pass}"
	json_add_string hy2_ai "${hy2_ai}"
	json_add_string hy2_sni "${hy2_sni}"
	json_add_string hy2_obfs "${hy2_obfs}"
	json_add_string hy2_obfs_pass "${hy2_obfs_pass}"
	json_add_string hy2_up "${HY2_UP_SPEED}"
	json_add_string hy2_dl "${HY2_DL_SPEED}"
	if [ "${HY2_TFO_SWITCH}" == "2" ];then
		json_add_string hy2_tfo "${hy2_tfo}"
	elif [ "${HY2_TFO_SWITCH}" == "1" ];then
		json_add_string hy2_tfo "1"
	elif [ "${HY2_TFO_SWITCH}" == "0" ];then
		json_add_string hy2_tfo "0"
	else
		json_add_string hy2_tfo "${hy2_tfo}"
	fi
	json_add_string type "8"

	if [ "${action}" == "1" ];then
		json_write_object ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt
	elif [ "${action}" == "2" ]; then
		json_write_object ${DIR}/offline_node_new.txt
	fi
}

get_fancyss_running_status(){
	local STATUS_1=$(dbus get ss_basic_enable 2>/dev/null)
	local STATUS_2=$(iptables --t nat -S|grep SHADOWSOCKS|grep -w "3333" 2>/dev/null)
	local STATUS_3=$(netstat -nlp 2>/dev/null|grep -w "3333"|grep -E "ss-redir|sslocal|v2ray|koolgame|xray|ipt2socks")
	local STATUS_4=$(netstat -nlp 2>/dev/null|grep -w "7913")
	# 当插件状态为开启，iptables状态正常，透明端口进程正常，DNS端口正常，DNS配置文件正常
	if [ "${STATUS_1}" == "1" -a -n "${STATUS_2}" -a -n "${STATUS_3}" -a -n "${STATUS_4}" -a -f "/jffs/configs/dnsmasq.d/wblist.conf" ];then
		echo 1
	fi
}

get_domain_name(){
	echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | awk -F ":" '{print $1}'
}

dnsmasq_rule(){
	# better way todo: resolve first and add ip to ipset:router mannuly
	local ACTION="$1"
	local DOMAIN="$2"
	local DNSF_PORT=7913
	local DOMAIN_FILE=/jffs/configs/dnsmasq.d/ss_domain.conf
	if [ "${ACTION}" == "add" ];then
		if [ ! -f ${DOMAIN_FILE} -o "$(grep -c ${DOMAIN} ${DOMAIN_FILE} 2>/dev/null)" != "2" ];then
			echo_date "✅添加域名：${DOMAIN} 到本机走代理名单..."
			rm -rf ${DOMAIN_FILE}
			echo "server=/${DOMAIN}/127.0.0.1#$DNSF_PORT" >>${DOMAIN_FILE}
			echo "ipset=/${DOMAIN}/router" >>${DOMAIN_FILE}
			sync
			service restart_dnsmasq >/dev/null 2>&1
		fi
	elif [ "${ACTION}" == "remove" ];then
		if [ -f ${DOMAIN_FILE} ];then
			rm -rf ${DOMAIN_FILE}
			sync
			service restart_dnsmasq >/dev/null 2>&1
		fi
	fi
}

go_proxy(){
	# 4. subscribe go through proxy or not
	if [ "$(dbus get ss_basic_online_links_goss)" == "1" ]; then
		if [ "$(get_fancyss_running_status)" == "1" ];then
			echo_date "✈️使用当前$(get_type_name $(dbus get ssconf_basic_type_${CURR_NODE}))节点：[$(dbus get ssconf_basic_name_${CURR_NODE})]提供的网络下载..."
			dnsmasq_rule add "${DOMAIN_NAME}"
		else
			echo_date "⚠️当前$(get_type_name $(dbus get ssconf_basic_type_${CURR_NODE}))节点工作异常，改用常规网络下载..."
			dnsmasq_rule remove
		fi
	else
		echo_date "⬇️使用常规网络下载..."
		dnsmasq_rule remove
	fi
}

download_by_curl(){
	if [ "$(dbus get ss_basic_online_links_goss)" == "1" ]; then
		SOCKS5_OPEN=$(netstat -nlp 2>/dev/null|grep -w "23456"|grep -Eo "ss-local|sslocal|v2ray|xray|naive|tuic")
		if [ -n "${SOCKS5_OPEN}" ];then
			local EXT_ARG="-x socks5h://127.0.0.1:23456"
			echo_date "✈️使用当前$(get_type_name $(dbus get ssconf_basic_type_${CURR_NODE}))节点：[$(dbus get ssconf_basic_name_${CURR_NODE})]提供的网络下载..."
		else
			local EXT_ARG=""
			echo_date "⚠️当前$(get_type_name $(dbus get ssconf_basic_type_${CURR_NODE}))节点工作异常，改用常规网络下载..."
		fi
	else
		echo_date "⬇️使用常规网络下载..."
		dnsmasq_rule remove
	fi

	local url_encode=$(echo "$1" | sed 's/[[:space:]]/%20/g')
	
	echo_date "1️⃣使用curl下载订阅，第一次尝试下载..."
	run curl-fancyss -4sSk ${EXT_ARG} --connect-timeout 6 "${url_encode}" 2>/dev/null >${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi
	
	echo_date "2️⃣使用curl下载订阅失败，第二次尝试下载..."
	run curl-fancyss -4sSk ${EXT_ARG} --connect-timeout 10 "${url_encode}" 2>/dev/null >${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi

	echo_date "3️⃣使用curl下载订阅失败，第三次尝试下载..."
	run curl-fancyss -4sSk ${EXT_ARG} --connect-timeout 12 "${url_encode}" 2>/dev/null >${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi	

	return 1
}

download_by_wget(){
	# if go proxy or not
	go_proxy
	
	if [ -n $(echo $1 | grep -E "^https") ]; then
		local EXT_OPT="--no-check-certificate"
	else
		local EXT_OPT=""
	fi
	
	local url_encode=$(echo "$1" | sed 's/[[:space:]]/%20/g')
	
	echo_date "1️⃣使用wget下载订阅，第一次尝试下载..."
	wget -4 -t 1 -T 10 --dns-timeout=5 -q ${EXT_OPT} "${url_encode}" -O ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi

	echo_date "2️⃣使用wget下载订阅，第二次尝试下载..."
	wget -4 -t 1 -T 15 --dns-timeout=10 -q ${EXT_OPT} "${url_encode}" -O ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi	
	
	echo_date "3️⃣使用wget下载订阅，第三次尝试下载..."
	wget -4 -t 1 -T 20 --dns-timeout=15 -q ${EXT_OPT} "${url_encode}" -O ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" == "0" ]; then
		return 0
	fi

	return 1
}

download_by_aria2(){
	go_proxy
	echo_date "⬇️使用aria2c下载订阅..."
	rm -rf ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
	/koolshare/aria2/aria2c --check-certificate=false --quiet=true -d $DIR -o ssr_subscribe_file.txt $1
	if [ "$?" == "0" ]; then
		return 0
	fi

	return 1
}

get_online_rule_now(){
	# 0. variable define
	local SUB_LINK="$1"

	# 1. get domain name of node subscribe link
	local DOMAIN_NAME="$(get_domain_name ${SUB_LINK})"
	if [ -z "${DOMAIN_NAME}" ];then
		echo_date "⚠️该订阅链接不包含任何节点信息！请检查你的服务商是否更换了订阅链接！"
		subscribe_failed
		return 1
	fi

	# 2. detect duplitcate sub
	local SUB_LINK_HASH=$(echo "${SUB_LINK}" | md5sum | awk '{print $1}')
	if [ -f "/$DIR/sublink_md5.txt" ];then
		local IS_ADD=$(cat /$DIR/sublink_md5.txt | grep -Eo ${SUB_LINK_HASH})
		if [ -n "${IS_ADD}" ];then
			echo_date "⚠️检测到重复的订阅链接！不订阅该链接！请检查你的订阅地址栏填写情况！"
			return 1
		fi
	fi
	echo ${SUB_LINK_HASH} >>/$DIR/sublink_md5.txt

	# 3. try to delete some file left by last sublink subscribe
	rm -rf /tmp/ssr_subscribe_file* >/dev/null 2>&1
	
	# 7. download sublink
	echo_date "📁准备下载订阅链接到本地临时文件，请稍等..."
	download_by_curl "${SUB_LINK}"
	if [ "$?" == "0" ]; then
		echo_date "🆗下载成功，继续检测下载内容..."

		#可能有跳转
		local jump=$(grep -Eo "Redirecting|301" ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt)
		if [ -n "$jump" ]; then
			echo_date "⤴️订阅链接可能有跳转，尝试更换wget进行下载..."
			rm ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
			download_by_wget "${SUB_LINK}"
		fi

		#下载为空...
		if [ "$(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | wc -c)" == "0" ]; then
			echo_date "🈳下载内容为空，尝试更换wget进行下载..."
			rm ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
			download_by_wget "${SUB_LINK}"
		fi

		# 404
		local wrong1=$(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | grep -E "404")
		if [ -n "${wrong1}" ]; then
			echo_date "⚠️解析错误！原因：该订阅链接无法访问，错误代码：404！"
			return 1
		fi
		
		# 产品信息错误
		local wrong=$(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | grep -E "\{")
		if [ -n "${wrong}" ]; then
			echo_date "⚠️解析错误！原因：该订阅链接获取的内容并非正确的base64编码内容！"
			echo_date "⚠️请检查你是否使用了错误的订阅链接，如clash专用订阅链接！"
			echo_date "⚠️请尝试将用浏览器打开订阅链接，看内容是否正常！"
			return 1
		fi

		# 非base64编码
		dec64 $(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt) >/dev/null 2>&1
		if [ "$?" != "0" ]; then
			echo_date "⚠️解析错误！原因：该订阅链接获取的内容并非正确的base64编码内容！"
			echo_date "⚠️请尝试将用浏览器打开订阅链接，看内容是否正常！"
			return 1
		fi
	else
		echo_date "⚠️使用curl下载订阅失败，尝试更换wget进行下载..."
		rm ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt
		download_by_wget "${SUB_LINK}"

		#返回错误
		if [ "$?" != "0" ]; then
			if [ -x "/koolshare/aria2/aria2c" ];then
				download_by_aria2 "${SUB_LINK}"
				if [ "$?" != "0" ]; then
					echo_date "⬇️使用aria2c下载订阅失败！请检查你的网络！"
					return 1
				fi
			else
				echo_date "⚠️更换wget下载订阅失败！"
				return 1
			fi
		fi

		#下载为空...
		if [ "$(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | wc -c)" == "0" ]; then
			echo_date "⚠️下载内容为空！️该订阅链接不包含任何节点信息"
			echo_date "⚠️请检查你的服务商是否更换了订阅链接！"
			return 1
		fi
		
		# 产品信息错误
		local wrong2=$(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | grep -E "\{")
		if [ -n "${wrong2}" ]; then
			echo_date "⚠️解析错误！原因：该订阅链接获取的内容并非正确的base64编码内容！"
			echo_date "⚠️请检查你是否使用了错误的订阅链接，如clash专用订阅链接！"
			echo_date "⚠️请尝试将用浏览器打开订阅链接，看内容是否正常！"
			return 1
		fi

		# 非base64编码
		dec64 $(cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt) >/dev/null 2>&1
		if [ "$?" != "0" ]; then
			echo_date "⚠️解析错误！原因：该订阅链接获取的内容并非正确的base64编码内容！"
			echo_date "⚠️请尝试将用浏览器打开订阅链接，看内容是否正常！"
			return 1
		fi
	fi
	
	echo_date "🆗下载内容检测完成！"
	echo_date "🔍开始解析节点信息..."

	# 8. 解析订阅原始文本
	# xargs --show-limits </dev/null to get arg_max, GT-AX6000 is 131072, which means 128kb
	# 如果订阅原始文本超过128kb，会导致echo，printf命令无法完整输出，所以直接对文件操作即可
	cat ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt | tr -d '\n' | sed 's/-/+/g;s/_/\//g' | sed 's/$/===/' | base64 -d > ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt
	if [ "$?" != "0" ]; then
		echo_date "⚠️解析错误！原因：解析后检测到乱码！请检查你的订阅地址！"
	fi

	# 9. 一些机场使用的换行符是dos格式（\r\n\)，在路由Linux下会出问题！转换成unix格式
	if [ -n "$(which dos2unix)" ];then
		dos2unix -u ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt
	else
		tr -d '\r' < ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | sponge ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt
	fi
	echo "" >> ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt
	local NODE_NU_RAW=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -c "://")
	echo_date "🆗初步解析成功！共获得${NODE_NU_RAW}个节点！"

	# 11. 检测 ss ssr vmess
	NODE_FORMAT1=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^ss://")
	NODE_FORMAT2=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^ssr://")
	NODE_FORMAT3=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^vmess://")
	NODE_FORMAT4=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^vless://")
	NODE_FORMAT5=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^trojan://")
	NODE_FORMAT6=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -E "^hysteria2://")
	if [ -z "${NODE_FORMAT1}" -a -z "${NODE_FORMAT2}" -a -z "${NODE_FORMAT3}" -a -z "${NODE_FORMAT4}" -a -z "${NODE_FORMAT5}" -a -z "${NODE_FORMAT6}" ];then
		echo_date "⚠️订阅中不包含任何ss/ssr/vmess/vless/trojan/hysteria2节点，退出！"
		return 1
	fi
	
	local NODE_NU_SS=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^ss://") || "0"
	local NODE_NU_SR=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^ssr://") || "0"
	local NODE_NU_VM=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^vmess://") || "0"
	local NODE_NU_VL=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^vless://") || "0"
	local NODE_NU_TJ=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^trojan://") || "0"
	local NODE_NU_H2=$(cat ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt | grep -Ec "^hysteria2://") || "0"
	local NODE_NU_TT=$((${NODE_NU_SS} + ${NODE_NU_SR} + ${NODE_NU_VM} + ${NODE_NU_VL} + ${NODE_NU_TJ} + ${NODE_NU_H2}))
	if [ "${NODE_NU_TT}" -lt "${NODE_NU_RAW}" ];then
		echo_date "ℹ️${NODE_NU_RAW}个节点中，一共检测到${NODE_NU_TT}个支持节点！"
	fi
	echo_date "ℹ️具体情况如下："
	[ "${NODE_NU_SS}" -gt "0" ] && echo_date "🟢ss节点：${NODE_NU_SS}个"
	[ "${NODE_NU_SR}" -gt "0" ] && echo_date "🔵ssr节点：${NODE_NU_SR}个"
	[ "${NODE_NU_VM}" -gt "0" ] && echo_date "🟠vmess节点：${NODE_NU_VM}个"
	[ "${NODE_NU_VL}" -gt "0" ] && echo_date "🟣vless节点：${NODE_NU_VL}个"
	[ "${NODE_NU_TJ}" -gt "0" ] && echo_date "🟡trojan节点：${NODE_NU_TJ}个"
	[ "${NODE_NU_H2}" -gt "0" ] && echo_date "🟤hysteria2节点：${NODE_NU_H2}个"
	echo_date "-------------------------------------------------------------------"

	# 12. 开始解析并写入节点
	while read node; do
		local node_type=$(echo ${node} | sed -n 's/^\(\w\+\):\/\/.*/\1/p')
		local node_info=$(echo ${node} | sed -n 's/.\+:\/\/\(.*\)$/\1/p')
		case ${node_type} in
		ss)
			add_ss_node "${node_info}" 1
			;;
		ssr)
			add_ssr_node "${node_info}" 1
			;;
		vmess)
			local _match=$(echo "${node_info}" | grep -E "@|\?|type")
			if [ -n "${_match}" ];then
				#明文的vmess链接
				add_vless_node "${node_info}" 1 vmess
			else
				#base64的vmess链接
				add_vmess_node "${node_info}" 1
			fi
			;;
		vless)
			add_vless_node "${node_info}" 1 vless
			;;
		trojan)
			add_trojan_node "${node_info}" 1
			;;
		hysteria2)
			add_hy2_node "${node_info}" 1
			;;
		*)
			if [ -n "${node_type}" ];then
				echo_date "⛔不支持${node_type}格式的节点，跳过！"
			fi
			# if [ -n "${node_info}" ];then
			# 	local _match=$(echo "${node_info}"|grep -E "//")
			# 	if [ -z "${_match}" ];then
			# 		echo_date "ℹ️$node"
			# 	else
			# 		echo "${node_info}"
			# 	fi
			# fi
			continue
			;;
		esac
	done < ${DIR}/sub_file_decode_${SUB_LINK_HASH:0:4}.txt
	echo_date "-------------------------------------------------------------------"
	if [ -f "${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt" ];then
		echo_date "ℹ️在线节点解析完毕，开始将订阅节点和和本地节点进行对比！"
	else
		echo_date "ℹ️在线节点解析失败！跳过此订阅！"
	fi

	# 14. print INFO
	local ONLINE_GROUP=$(cat ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt | run jq -rc '.group' | sed 's/_[^_]\+$//' | sort -u | sed 's/$/ + /g' | sed ':a;N;$!ba;s#\n##g' | sed 's/ + $//g')
	if [ -z "${ONLINE_GROUP}" ]; then
		# 如果机场没有定义group，则用其订阅域名写入即可
		ONLINE_GROUP=${DOMAIN_NAME}
	fi
	local md5_new=$(md5sum ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt | awk '{print $1}')
	echo_date "🌎订阅节点信息："
	echo_date "🔷当前订阅来源【${ONLINE_GROUP}】，共有节点${NODE_NU_TT}个。"
	if [ "${exclude}" != "0" ];then
		echo_date "🔷其中：因关键词匹配排除节点${exclude}个，最终获得有效节点$((${NODE_NU_TT} - ${exclude}))个"
	fi
	echo_date "🔷订阅节点校验：${md5_new}"
	echo_date "💾本地节点信息："
	local ISLOCALFILE=$(find ${DIR} -name "local_*_${SUB_LINK_HASH:0:4}.txt")
	if [ -n "${ISLOCALFILE}" ];then
		local md5_loc=$(md5sum ${ISLOCALFILE} | awk '{print $1}')
		local LOCAL_GROUP=$(cat $ISLOCALFILE | run jq -rc '.group' | sort -u | sed 's/_[^_]\+$//' | sed 's/$/ + /g' | sed ':a;N;$!ba;s#\n##g' | sed 's/ + $//g')
		local LOCAL_NODES=$(cat $ISLOCALFILE | wc -l)
		echo_date "🔶当前订阅来源【${LOCAL_GROUP}】，在本地已有节点${LOCAL_NODES}个。"
		echo_date "🔶本地节点校验：${md5_loc}"
		if [ "${md5_loc}" == "${md5_new}" ];then
			echo_date "🆚对比结果：本地节点已经是最新，跳过！"
		else
			echo_date "🆚对比结果：检测到节点发生变更，生成节点更新文件！"
		fi
		# 将订阅后的文件，覆盖为本地的相同link hash的文件
		rm -rf ${ISLOCALFILE}
		cp -rf ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt ${DIR}/local_${sub_count}_${SUB_LINK_HASH:0:4}.txt
		return 0
	else
		echo_date "🔶当前订阅链来源【${ONLINE_GROUP}】在本地尚无节点！"
		echo_date "🆚对比结果：检测到新的订阅节点，生成节点添加文件！"
		# 将订阅后的文件，覆盖为本地的相同link hash的文件
		cp -rf ${DIR}/online_${sub_count}_${SUB_LINK_HASH:0:4}.txt ${DIR}/local_${sub_count}_${SUB_LINK_HASH:0:4}.txt
		return 0
	fi
}

exit_sub(){
	echo_date "==================================================================="
	exit 1
}

start_online_update(){
	echo_date "==================================================================="
	echo_date "                服务器订阅程序(Shell by stones & sadog)"
	echo_date "==================================================================="

	# run some test before anything start
	# echo_date "⚙️test: 脚本环境变量：$(env | wc -l)个"
	
	# 0. var define
	NODES_SEQ=$(dbus list ssconf_basic_name_ | grep -E "_[0-9]+=" | sed -n 's/^.*_\([0-9]\+\)=.*/\1/p' | sort -n)
	SEQ_NU=$(echo ${NODES_SEQ} | tr ' ' '\n' | sed '/^$/d' | wc -l)

	# 1. 如果本地没有订阅的节点，同时没有订阅链接，则退出订阅
	local online_sub_nu=$(dbus list ssconf_basic_group_ | sed '/^ssconf_basic_group_[0-9]\+=$/d' | wc -l)
	if [ "${online_sub_nu}" == "0" ];then
		if [ -z "$(dbus get ss_online_links)" ];then
			echo_date "🈳订阅地址输入框为空，请输入订阅链接后重试！"
			exit_sub
		fi
		local online_url_nu=$(dbus get ss_online_links | base64 -d | sed 's/$/\n/' | sed '/^$/d' | sed '/^#/d' | sed 's/^[[:space:]]//g' | sed 's/[[:space:]]&//g' | grep -E "^http" | wc -l)
		if [ "${online_url_nu}" == "0" ];then
			echo_date "🈳未发现任何有效的订阅地址，请检查你的订阅链接！"
			exit_sub
		fi
	fi
	echo_date "✈️开始订阅！"

	# 2. 创建临时文件夹，用于存放订阅过程中的临时文件
	mkdir -p $DIR
	rm -rf $DIR/*

	# 3.订阅前检查节点是否储存正常，不需要了
	# check_nodes

	# 4. skipd节点数据储存到文件
	skipdb2json

	# 4. 储存的节点文件，按照不通机场拆分
	nodes2files
	
	# 5. 用拆分文件统计节点
	nodes_stats

	# 6. 移除没有订阅的节点
	remove_null
	
	# 7. 下载/解析订阅节点
	sub_count=0
	online_url_nu=$(dbus get ss_online_links | base64 -d | sed 's/$/\n/' | sed '/^$/d' | sed '/^#/d' | sed 's/^[[:space:]]//g' | sed 's/[[:space:]]&//g' | grep -E "^http" | wc -l)
	until [ "${sub_count}" == "${online_url_nu}" ]; do
		let sub_count+=1
		url=$(dbus get ss_online_links | base64 -d | sed '/^$/d' | sed '/^#/d' | sed 's/^[[:space:]]//g' | sed 's/[[:space:]]&//g' | grep -E "^http" | sed -n "$sub_count p")
		[ -z "${url}" ] && continue
		echo_date "➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖"
		[ "${online_url_nu}" -gt "1" ] && echo_date "📢开始第【${sub_count}】个订阅！订阅链接如下："
		[ "${online_url_nu}" -eq "1" ] && echo_date "📢开始订阅！订阅链接如下："
		echo_date "🌎${url}"
		exclude=0
		get_online_rule_now "${url}"
		case $? in
		0)
			continue
			;;
		*)
			subscribe_failed
			;;
		esac
	done
	echo_date "➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖"

	# 5. 写入所有节点
	local ISNEW=$(find $DIR -name "local_*_*.txt")
	if [ -n "${ISNEW}" ];then
		find $DIR -name "local_*.txt" | sort -n | xargs cat >$DIR/ss_nodes_new.txt
		local md5sum_old=$(md5sum ${LOCAL_NODES_BAK} 2>/dev/null | awk '{print $1}')
		local md5sum_new=$(md5sum $DIR/ss_nodes_new.txt 2>/dev/null | awk '{print $1}')
		if [ "${md5sum_new}" != "${md5sum_old}" ];then
			clear_nodes
			echo_date "ℹ️开始写入节点..."
			json2skipd "ss_nodes_new"
		else
			echo_date "ℹ️本次订阅没有任何节点发生变化，不进行写入，继续！"
		fi
		# 订阅完成，再次统计
		SEQ_NU=$(dbus list ssconf_basic_name_|wc -l)
		skipdb2json
		nodes2files
		nodes_stats
		echo_date "🧹一点点清理工作..."
		echo_date "🎉所有订阅任务完成，请等待6秒，或者手动关闭本窗口！"
	else
		echo_date "⚠️出错！未找到节点写入文件！"
		echo_date "⚠️退出订阅！"
	fi
	echo_date "==================================================================="
}

subscribe_failed(){
	# 当订阅失败后，在这里进行一些处理...
	rm -rf ${DIR}/sub_file_encode_${SUB_LINK_HASH:0:4}.txt >/dev/null 2>&1
	#echo ""
}

start_offline_update() {
    echo_date "==================================================================="
    echo_date "ℹ️ 正在处理离线链接导入（支持 CHAIN## 串联节点与普通节点混合）..."
    
    mkdir -p $DIR
    rm -rf $DIR/*

    # 1. 获取并解码链接内容
    # 使用 tr 删除可能存在的 Windows 换行符 \r，确保逐行读取正确
    local nodes_raw=$(dbus get ss_base64_links | base64 -d | urldecode | tr -d '\r')

    # 2. 使用 while read 循环逐行处理，支持批量
    # IFS= 防止行首尾空格被截断，-r 防止反斜杠转义
    echo "$nodes_raw" | while IFS= read -r line || [ -n "$line" ]; do
        
        # ----------------- 预处理 -----------------
        # 跳过空行或纯空白行
        if [ -z "$(echo "$line" | tr -d ' ')" ]; then
            continue
        fi
        
        # 去除行首尾的空白字符（增强容错）
        local node=$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')

        # ----------------- 分支 A：处理 CHAIN## 串联节点 -----------------
        # 参考 clash_online_yaml4.sh 的识别逻辑 
        if echo "$node" | grep -q "^CHAIN##"; then
            echo_date "🔗 识别到串联节点 (CHAIN)..."
            
            # A1. 移除前缀
            local content=${node#CHAIN##}
            
            # A2. 分割基础链接与加速命令 (使用 awk 确保能够处理含空格的参数)
            # 格式: hysteria2://... && UDP2RAW://...
            local base_part=$(echo "$content" | awk -F '&&' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//')
            local accel_part=$(echo "$content" | awk -F '&&' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')

            # A3. 识别加速器类型 (UDP2RAW / KCPTUN)
            local kcp_part=""
            local udp_part=""
            
            if echo "$accel_part" | grep -qi "UDP2RAW"; then
                udp_part="$accel_part"
            elif echo "$accel_part" | grep -qi "KCPTUN"; then
                kcp_part="$accel_part"
            else
                # 模糊匹配：如果没写协议头，尝试通过参数特征识别
                if echo "$accel_part" | grep -q "\-c "; then
                     udp_part="UDP2RAW://$accel_part"
                elif echo "$accel_part" | grep -q "\-\-key"; then
                     kcp_part="KCPTUN://$accel_part"
                fi
            fi

            # A4. 执行添加 (调用现有的 add_chained_node 函数)
            if [ -n "$base_part" ]; then
                # 注意：Fancyss 不需要像 Clash 那样做端口递增映射 
                # 因为它一次只运行一个节点，直接保存参数即可
                add_chained_node "$base_part" "$kcp_part" "$udp_part" 2
            else
                echo_date "🔴 串联节点解析失败：基础链接为空"
            fi
            
            # 处理完 CHAIN 节点后，直接进入下一次循环
            continue
        fi

        # ----------------- 分支 B：处理普通节点 -----------------
        # 提取协议头 (如 ss, vmess, hysteria2)
        local node_type=$(echo "$node" | sed -n 's/^\(\w\+\):\/\/.*/\1/p' | tr 'A-Z' 'a-z')
        local node_info=$(echo "$node" | sed -n 's/.\+:\/\/\(.*\)$/\1/p')
        
        case "$node_type" in
            ss)
                add_ss_node "${node_info}" 2 
                ;;
            ssr)
                # 如果支持 SSR，调用相应函数（需确认脚本是否有 add_ssr_node）
                add_ssr_node "${node_info}" 2
                ;;
            vmess)
                # 区分 vmess://JSON(base64) 和 vmess://URI
                if echo "${node_info}" | grep -Eq '@|\?|type='; then
                    add_vless_node "${node_info}" 2 vmess
                else
                    # 兼容旧版 JSON base64 格式
                    add_vmess_node "${node_info}" 2
                fi
                ;;
            vless)
                add_vless_node "${node_info}" 2 vless 
                ;;
            hysteria2)
                add_hy2_node "${node_info}" 2 
                ;;
            trojan)
                add_trojan_node "${node_info}" 2
                ;;
            *)
                # 无法识别的协议，记录日志但不中断循环
                if [ -n "$node" ]; then
                    echo_date "⚠️ 跳过不支持的协议格式: ${node_type:-未知}..."
                fi
                ;;
        esac

    done

    # 3. 清理与写入
    dbus remove ss_base64_links
    echo_date "-------------------------------------------------------------------"
    
    # 检查是否有节点文件生成
    if [ -f "${DIR}/offline_node_new.txt" ];then
        echo_date "ℹ️ 离线节点解析完毕，正在写入数据库..."
        json2skipd "offline_node_new"
    else
        echo_date "⚠️ 未解析到任何有效节点！"
    fi
    echo_date "==================================================================="
}

if [ -z "$2" -a -n "$1" ];then
	SH_ARG=$1
	WEB_ACTION=0
elif [ -n "$2" -a -n "$1" ];then
	SH_ARG=$2
	WEB_ACTION=1
fi

case $SH_ARG in
0)
	# 删除所有节点
	set_lock
	true > $LOG_FILE
	[ "${WEB_ACTION}" == "1" ] && http_response "$1"
	remove_all_node | tee -a $LOG_FILE
	echo XU6J03M6 | tee -a $LOG_FILE
	unset_lock
	;;
1)
	# 删除所有订阅节点
	set_lock
	true > $LOG_FILE
	[ "${WEB_ACTION}" == "1" ] && http_response "$1"
	remove_sub_node | tee -a $LOG_FILE
	echo XU6J03M6 | tee -a $LOG_FILE
	unset_lock
	;;
2)
	# 保存订阅设置但是不订阅
	set_lock
	true > $LOG_FILE
	[ "${WEB_ACTION}" == "1" ] && http_response "$1"
	local_groups=$(dbus list ssconf_basic_group_ | cut -d "=" -f2 | sort -u | wc -l)
	online_group=$(dbus get ss_online_links | base64 -d | awk '{print $1}' | sed '/^$/d' | sed '/^#/d' | sed 's/^[[:space:]]//g' | sed 's/[[:space:]]&//g' | grep -Ec "^http")
	echo_date "保存订阅节点成功！" | tee -a $LOG_FILE
	echo_date "现共有 $online_group 组订阅来源" | tee -a $LOG_FILE
	echo_date "当前节点列表内已经订阅了 $local_groups 组..." | tee -a $LOG_FILE
	sed -i '/ssnodeupdate/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
	if [ "$(dbus get ss_basic_node_update)" = "1" ]; then
		if [ "$(dbus get ss_basic_node_update_day)" = "7" ]; then
			cru a ssnodeupdate "0 $(dbus get ss_basic_node_update_hr) * * * /koolshare/scripts/ss_online_update.sh fancyss 3"
			echo_date "设置自动更新订阅服务在每天 $(dbus get ss_basic_node_update_hr) 点。" | tee -a $LOG_FILE
		else
			cru a ssnodeupdate "0 $(dbus get ss_basic_node_update_hr) * * $(dbus get ss_basic_node_update_day) /koolshare/scripts/ss_online_update.sh fancyss 3"
			echo_date "设置自动更新订阅服务在星期 $(dbus get ss_basic_node_update_day) 的 $(dbus get ss_basic_node_update_hr) 点。" | tee -a $LOG_FILE
		fi
	else
		echo_date "关闭自动更新订阅服务！" | tee -a $LOG_FILE
		sed -i '/ssnodeupdate/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
	fi
	echo XU6J03M6 | tee -a $LOG_FILE
	unset_lock
	;;
3)
	# 使用订阅链接订阅ss/ssr/V2ray节点
	set_lock
	true > $LOG_FILE
	[ "${WEB_ACTION}" == "1" ] && http_response "$1"
	start_online_update | tee -a $LOG_FILE
	echo XU6J03M6 | tee -a $LOG_FILE
	unset_lock
	;;
4)
	# 添加ss:// ssr:// vmess://离线节点
	set_lock
	true > $LOG_FILE
	[ "${WEB_ACTION}" == "1" ] && http_response "$1"
	start_offline_update | tee -a $LOG_FILE
	echo XU6J03M6 | tee -a $LOG_FILE
	unset_lock
	;;
esac
