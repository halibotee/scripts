#!/bin/sh

source /koolshare/scripts/clash_base.sh

CHAIN_DIR="/var/run/merlinclash/chain"
KCPTUN_BIN="/koolshare/bin/kcptun"
UDP2RAW_BIN="/koolshare/bin/udp2raw"
PORT_START=1091
PORT_END=1191

# 检查端口是否可用（将端口转为大写十六进制后直接 grep /proc/net/*）
# 同时检查 CHAIN_DIR 中其他已注册 CHAIN 的端口占用
_check_port() {
    local port=$1
    [ "$port" -ge "$PORT_START" ] && [ "$port" -le "$PORT_END" ] || return 1
    local hex=$(printf '%04X' "$port" 2>/dev/null)
    [ -z "$hex" ] && return 0  # 无法转换，视为空闲
    grep -q ":${hex} " /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null && return 1
    # 检查已注册的 CHAIN 端口文件
    if [ -d "$CHAIN_DIR" ]; then
        for pf in "$CHAIN_DIR"/*/ports; do
            [ -f "$pf" ] && grep -qx "$port" "$pf" 2>/dev/null && return 1
        done
    fi
    return 0
}

# 找到 count 个连续空闲端口，返回起始端口
_find_free_ports() {
    local count=$1
    local i=$PORT_START
    local max=$((PORT_END - count + 1))
    while [ $i -le $max ]; do
        local all_free=1
        local j=0
        while [ $j -lt $count ]; do
            local p=$((i + j))
            _check_port "$p" || { all_free=0; break; }
            j=$((j + 1))
        done
        [ $all_free -eq 1 ] && { echo $i; return 0; }
        i=$((i + 1))
    done
    return 1
}

# 从组件字符串中提取所有 127.0.0.1:PORT 中的端口号
_extract_ports() {
    local str="$1"
    echo "$str" | grep -oE '127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$'
}

# 按分隔符 | 逐个遍历组件，对每个组件调用 handler_func
_foreach_component() {
    local comps="$1"
    local handler_func="$2"
    local rest="$comps"
    while [ -n "$rest" ]; do
        local c=$(echo "$rest" | cut -d'|' -f1)
        rest=$(echo "$rest" | cut -d'|' -f2-)
        [ "$c" = "$rest" ] && rest=""
        eval "$handler_func" "$c"
    done
}

# 解析 CHAIN URL（输出变量赋值语句到 stdout，日志走 stderr）
parse_chain_url() {
    local url="$1"
    local inner tag proxy_comp sidecars

    inner=$(echo "$url" | sed 's/.*\[\([^]]*\)\].*/\1/')
    tag=$(echo "$url" | sed 's/.*#\(.*\)\]/\1/' | sed 's/.*#\(.*\)/\1/')

    [ -z "$inner" ] && { echo "CHAIN_URL_ERROR: 缺少 []" >&2; return 1; }
    [ -z "$tag" ] && { echo "CHAIN_URL_ERROR: 缺少 #TAG" >&2; return 1; }

    # 按 && 分割组件（用已知长度截取，避免 URL 中 & 干扰 sed）
    local tmp="$inner"
    local components=""
    local comp_count=0
    while echo "$tmp" | grep -q ' && '; do
        local c=$(echo "$tmp" | sed 's/ && .*//')
        components="$components|$c"
        comp_count=$((comp_count + 1))
        # 跳过第一组件 + " && "（共 len(c) + 4 个字符）
        local skip=$(( ${#c} + 5 ))
        tmp=$(echo "$tmp" | cut -c${skip}-)
    done
    [ -n "$tmp" ] && { components="$components|$tmp"; comp_count=$((comp_count + 1)); }
    components=$(echo "$components" | sed 's/^|//')

    [ $comp_count -lt 2 ] && { echo "CHAIN_URL_ERROR: 至少需要2个组件" >&2; return 1; }

    # 第一个组件是代理协议(ss/hy2等)，其余是隧道(kcptun/udp2raw)
    proxy_comp=$(echo "$components" | cut -d'|' -f1)
    sidecars=$(echo "$components" | cut -d'|' -f2-)

    # 提取所有本地端口（逐组件以避免空格问题）
    local all_ports=""
    local rest="$components"
    while [ -n "$rest" ]; do
        local c=$(echo "$rest" | cut -d'|' -f1)
        rest=$(echo "$rest" | cut -d'|' -f2-)
        [ "$c" = "$rest" ] && rest=""
        local ports_in_comp=$(_extract_ports "$c")
        all_ports="$all_ports $ports_in_comp"
    done

    # 去重并排序
    local unique_ports=$(echo $all_ports | tr ' ' '\n' | grep -v '^$' | sort -n | uniq | tr '\n' ' ')
    local port_count=$(echo $unique_ports | wc -w | tr -d ' ')

    # 检查是否需要重新分配端口
    local need_realloc=0
    local p
    for p in $unique_ports; do
        _check_port "$p" || { need_realloc=1; break; }
    done

    local old_new_map=""
    if [ $need_realloc -eq 1 ]; then
        local base_port
        base_port=$(_find_free_ports $port_count) || {
            echo "CHAIN_PORT_ERROR: 端口范围 $PORT_START-$PORT_END 无足够空闲端口" >&2
            return 1
        }
        local idx=0
        for p in $unique_ports; do
            local np=$((base_port + idx))
            old_new_map="$old_new_map $p:$np"
            idx=$((idx + 1))
        done
        # echo "CHAIN [$tag] 端口冲突已重新分配" >&2
    fi

    # 替换端口（全局替换组件中的端口号）
    local adjusted_proxy_comp="$proxy_comp"
    local adjusted_sidecars="$sidecars"
    for pair in $old_new_map; do
        local old_port=$(echo $pair | cut -d: -f1)
        local new_port=$(echo $pair | cut -d: -f2)
        adjusted_proxy_comp=$(echo "$adjusted_proxy_comp" | sed "s/:$old_port\([^0-9]\)/:$new_port\1/g; s/:$old_port$/:$new_port/g")
        adjusted_sidecars=$(echo "$adjusted_sidecars" | sed "s/:$old_port\([^0-9]\)/:$new_port\1/g; s/:$old_port$/:$new_port/g")
    done

    # 获取入口端口（第一个组件的目标端口 = 最内层监听端口）
    local entry_port=$(echo "$adjusted_proxy_comp" | grep -oE '127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$')
    [ -z "$entry_port" ] && entry_port=$(_extract_ports "$adjusted_proxy_comp" | head -1)

    # 输出变量赋值（供调用方 eval）
    echo "TAG='$tag'"
    echo "ENTRY_PORT='$entry_port'"
    echo "PROXY_URL='$adjusted_proxy_comp'"

    # 输出侧载命令
    local sc_idx=0
    rest="$sidecars"
    while [ -n "$rest" ]; do
        local sc=$(echo "$rest" | cut -d'|' -f1)
        rest=$(echo "$rest" | cut -d'|' -f2-)
        [ "$sc" = "$rest" ] && rest=""

        local adjusted_sc="$sc"
        for pair in $old_new_map; do
            local old_port=$(echo $pair | cut -d: -f1)
            local new_port=$(echo $pair | cut -d: -f2)
            adjusted_sc=$(echo "$adjusted_sc" | sed "s/:$old_port\([^0-9]\)/:$new_port\1/g; s/:$old_port$/:$new_port/g")
        done

        sc_idx=$((sc_idx + 1))
        echo "SIDECAR_${sc_idx}='$adjusted_sc'"
    done
    echo "SIDECAR_COUNT='$sc_idx'"

    # 注册 CHAIN 节点（保存元数据供 start_all 使用）
    mkdir -p "$CHAIN_DIR/$tag"
    {
        echo "TAG=$tag"
        echo "SIDECAR_COUNT=$sc_idx"
        echo "ENTRY_PORT=$entry_port"
        echo "PROXY_URL=$adjusted_proxy_comp"
        local si=0
        rest="$adjusted_sidecars"
        while [ -n "$rest" ]; do
            local sc=$(echo "$rest" | cut -d'|' -f1)
            rest=$(echo "$rest" | cut -d'|' -f2-)
            [ "$sc" = "$rest" ] && rest=""
            si=$((si + 1))
            echo "SIDECAR_${si}=${sc}"
        done
    } > "$CHAIN_DIR/$tag/meta"

    # 记录端口占用
    for pair in $old_new_map; do
        local new_port=$(echo $pair | cut -d: -f2)
        echo "$new_port" >> "$CHAIN_DIR/$tag/ports"
    done
    [ $need_realloc -eq 0 ] && {
        for p in $unique_ports; do
            echo "$p" >> "$CHAIN_DIR/$tag/ports"
        done
    }

    return 0
}

# 启动单个 CHAIN 的侧载进程
start_chain_node() {
    local tag="$1"
    local meta="$CHAIN_DIR/$tag/meta"

    [ ! -f "$meta" ] && return 1

    local sidecar_count
    sidecar_count=$(grep '^SIDECAR_COUNT=' "$meta" | cut -d= -f2-)

    # 逆序启动（从最外层到最内层）
    local idx=$sidecar_count
    while [ $idx -ge 1 ]; do
        local cmd_line
        cmd_line=$(grep "^SIDECAR_${idx}=" "$meta" | cut -d= -f2-)

        local bin_type=""
        case "$cmd_line" in
            kcptun://*)
                bin_type="kcptun"
                cmd_line=$(echo "$cmd_line" | sed 's/^kcptun:\/\///')
                cmd_line=$(echo "$cmd_line" | sed 's/--listen /-l /g; s/--target /-r /g')
                cmd_line=$(echo "$cmd_line" | sed 's/--tcp false//g; s/--quiet false//g; s/--nocomp true/--nocomp/g; s/--nocomp false//g; s/--acknodelay false//g')
                cmd_line=$(echo "$cmd_line" | sed 's/  */ /g; s/^ *//; s/ *$//')
                cmd_line="$KCPTUN_BIN $cmd_line"
                ;;
            udp2raw://*)
                bin_type="udp2raw"
                cmd_line=$(echo "$cmd_line" | sed 's/^udp2raw:\/\///')
                cmd_line="$UDP2RAW_BIN $cmd_line"
                ;;
        esac

        [ -z "$bin_type" ] && { idx=$((idx - 1)); continue; }

        nohup $cmd_line >/dev/null 2>&1 &
        local pid=$!
        echo "$pid" > "$CHAIN_DIR/$tag/${bin_type}.pid"
        echo "$cmd_line" > "$CHAIN_DIR/$tag/${bin_type}.cmd"
        kill -0 "$pid" 2>/dev/null || echo_date "🔴$tag ${bin_type} 启动失败" >> $LOG_FILE

        idx=$((idx - 1))
    done

    echo_date "🟢CHAIN [$tag] 启动成功" >> $LOG_FILE
    return 0
}

# 停止单个 CHAIN（kill -9 强制）
stop_chain_node() {
    local tag="$1"
    local dir="$CHAIN_DIR/$tag"

    [ ! -d "$dir" ] && return 0

    # 先杀 kcptun（内层），再杀 udp2raw（外层）
    for bin_type in kcptun udp2raw; do
        local pid_file="$dir/${bin_type}.pid"
        [ -f "$pid_file" ] || continue
        local pid=$(cat "$pid_file" 2>/dev/null)
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null && echo_date "🟢强制终止 ${bin_type} (PID: $pid)" >> $LOG_FILE
            fi
        fi
        rm -f "$pid_file"
    done

    rm -f "$dir"/*.pid "$dir"/*.cmd
    # 保留 meta/ports 文件，供后续 start_all 读取

    echo_date "🟢CHAIN [$tag] 已关闭" >> $LOG_FILE
    return 0
}

# 启动所有已注册的 CHAIN
start_all_chains() {
    [ ! -d "$CHAIN_DIR" ] && return 0
    for d in "$CHAIN_DIR"/*/; do
        [ -d "$d" ] || continue
        local tag=$(basename "$d")
        [ -f "$d/meta" ] || continue
        start_chain_node "$tag"
    done
}

# 停止所有 CHAIN
stop_all_chains() {
    [ ! -d "$CHAIN_DIR" ] && return 0
    for d in "$CHAIN_DIR"/*/; do
        [ -d "$d" ] || continue
        local tag=$(basename "$d")
        stop_chain_node "$tag"
    done
}

# 清理所有 CHAIN（停止 + 删除目录）
clean_all_chains() {
    stop_all_chains
    rm -rf "$CHAIN_DIR"
}

# 获取状态
status_all_chains() {
    [ ! -d "$CHAIN_DIR" ] && { echo_date "无 CHAIN 节点" >> $LOG_FILE; return 0; }
    for d in "$CHAIN_DIR"/*/; do
        [ -d "$d" ] || continue
        local tag=$(basename "$d")
        local entry_port=$(grep '^ENTRY_PORT=' "$d/meta" 2>/dev/null | cut -d= -f2-)
        local kcp_pid=""
        local udp_pid=""
        [ -f "$d/kcptun.pid" ] && kcp_pid=$(cat "$d/kcptun.pid" 2>/dev/null)
        [ -f "$d/udp2raw.pid" ] && udp_pid=$(cat "$d/udp2raw.pid" 2>/dev/null)
        local kcp_alive="停"
        local udp_alive="停"
        [ -n "$kcp_pid" ] && kill -0 "$kcp_pid" 2>/dev/null && kcp_alive="运行"
        [ -n "$udp_pid" ] && kill -0 "$udp_pid" 2>/dev/null && udp_alive="运行"
        local icon="🟢"
        [ "$kcp_alive" = "停" ] || [ "$udp_alive" = "停" ] && icon="🔴"
        echo_date "${icon}CHAIN [$tag] 入口: $entry_port | kcptun: $kcp_alive | udp2raw: $udp_alive" >> $LOG_FILE
    done
}

case $1 in
parse)
    parse_chain_url "$2"
    ;;
start)
    [ -z "$2" ] && { echo_date "用法: clash_chain.sh start <TAG>" >> $LOG_FILE; exit 1; }
    start_chain_node "$2"
    ;;
stop)
    [ -z "$2" ] && { echo_date "用法: clash_chain.sh stop <TAG>" >> $LOG_FILE; exit 1; }
    stop_chain_node "$2"
    ;;
start_all)
    start_all_chains
    ;;
stop_all)
    stop_all_chains
    ;;
clean)
    clean_all_chains
    ;;
status)
    status_all_chains
    ;;
*)
    echo "用法: clash_chain.sh {parse|start|stop|start_all|stop_all|clean|status} [参数]"
    exit 1
    ;;
esac
