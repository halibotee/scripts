#!/bin/sh

source /koolshare/scripts/clash_base.sh

CHAIN_DIR="/var/run/merlinclash/chain"
KCPTUN_BIN="/koolshare/bin/kcptun"
UDP2RAW_BIN="/koolshare/bin/udp2raw"

# 端口分层（基准 + 节点索引偏移 i，1 <= i <= PORT_INDEX_MAX）
# ss+kcptun+udp2raw 链路（3 端口）:
#   mihomo/最内层 ss  = 1190 + i
#   kcptun listen     = 1290 + i
#   udp2raw listen    = 1390 + i
# ss+kcptun 链路（2 端口）:
#   mihomo ss         = 1190 + i
#   kcptun listen     = 1290 + i (target = VPS ext)
# hy2+udp2raw 链路（2 端口）:
#   mihomo hy2        = 1190 + i
#   udp2raw listen    = 1290 + i
PORT_BASE_ENTRY=1190       # mihomo/最内层 (ss/hy2 listen)
PORT_BASE_KCPTUN=1290      # kcptun listen
PORT_BASE_UDP2RAW=1390     # udp2raw listen (外层)
PORT_INDEX_MAX=99          # 最多 99 个链/节点
PORT_ENTRY_START=$((PORT_BASE_ENTRY + 1))      # 1191
PORT_ENTRY_END=$((PORT_BASE_ENTRY + PORT_INDEX_MAX))   # 1289
PORT_KCPTUN_START=$((PORT_BASE_KCPTUN + 1))    # 1291
PORT_KCPTUN_END=$((PORT_BASE_KCPTUN + PORT_INDEX_MAX))  # 1389
PORT_UDP2RAW_START=$((PORT_BASE_UDP2RAW + 1))  # 1391
PORT_UDP2RAW_END=$((PORT_BASE_UDP2RAW + PORT_INDEX_MAX)) # 1489
# 兼容旧版（仍允许 1191-1291）
PORT_START=1191
PORT_END=1291

# 检查端口是否在合法范围内（三层：1190+i/1290+i/1390+i，或旧 1191-1291）
# 严格限制本脚本只能使用这些端口，绝不触碰路由器系统端口或其他插件的端口
_is_port_in_range() {
    local port=$1
    # mihomo/最内层 ss/hy2: 1191-1289
    [ "$port" -ge "$PORT_ENTRY_START" ] && [ "$port" -le "$PORT_ENTRY_END" ] && return 0
    # kcptun 中转层: 1291-1389
    [ "$port" -ge "$PORT_KCPTUN_START" ] && [ "$port" -le "$PORT_KCPTUN_END" ] && return 0
    # udp2raw 外层: 1391-1489
    [ "$port" -ge "$PORT_UDP2RAW_START" ] && [ "$port" -le "$PORT_UDP2RAW_END" ] && return 0
    # 兼容旧 1191-1291
    [ "$port" -ge "$PORT_START" ] && [ "$port" -le "$PORT_END" ] && return 0
    return 1
}

# 检查端口是否可用（系统未占用 + ports.db 未注册 + 在合法范围内）
# 关键防御：扫描 /proc/net/{tcp,udp,tcp6,udp6} 检测路由器系统及其他插件占用的端口
_check_port() {
    local port=$1
    # 第一道防线：必须在合法范围内（防止误用路由器端口）
    _is_port_in_range "$port" || return 1
    # 第二道防线：系统端口扫描（路由器所有进程 + 其他插件）
    local hex=$(printf '%04X' "$port" 2>/dev/null)
    [ -z "$hex" ] && return 0  # 无法转换，视为空闲
    grep -q ":${hex} " /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null && return 1
    # 第三道防线：CHAIN 端口文件（兼容旧 CHAIN_DIR/*/ports）
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

# =============================================================================
# 本地端口管理器 (Port Manager)
# 职责：端口冲突检测、分配、注册、释放、查询、健康检查
# 存储：/var/run/merlinclash/ports.db (CSV 格式 PORT|TYPE|TAG|STATUS|EXT)
# =============================================================================

PORTS_DB="/var/run/merlinclash/ports.db"

# 初始化端口数据库
_port_db_init() {
    mkdir -p "$(dirname "$PORTS_DB")"
    [ -f "$PORTS_DB" ] || : > "$PORTS_DB"
}

# 兼容路由器 BusyBox 的 netstat 端口扫描
# 同时检查 /proc/net/tcp, /proc/net/udp, /proc/net/tcp6, /proc/net/udp6
# 命中格式: ":PORT "（TCP/UDP）和 ".PORT "（IPv6）
_port_in_use_by_system() {
    local port=$1
    local hex=$(printf '%04X' "$port" 2>/dev/null)
    [ -z "$hex" ] && return 1
    # 内核端口表（最权威，路由器所有进程 + 其他插件）
    grep -q ":${hex} " /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null && return 0
    # netstat 兜底（兼容旧版本内核）
    if command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -qE "[:.]${port} " && return 0
    fi
    return 1
}

# 动态获取空闲端口（从 start 开始递增，自动跳过冲突）
# 用法: get_free_port <start_port>
# 关键：跳过路由器系统、其他插件、自身已注册的端口
get_free_port() {
    local port=$1
    local max_port=65535
    while [ "$port" -le "$max_port" ]; do
        # 必须在合法范围内
        if _is_port_in_range "$port"; then
            # 系统端口未占用
            if ! _port_in_use_by_system "$port"; then
                # ports.db 未注册
                if ! grep -q "^${port}|" "$PORTS_DB" 2>/dev/null; then
                    echo "$port"
                    return 0
                fi
            fi
        fi
        port=$((port + 1))
    done
    return 1
}

# 检查端口是否可用（系统未占用 + ports.db 未注册 + 在合法范围内）
# 关键防御：扫描 /proc/net/{tcp,udp,tcp6,udp6} 检测路由器系统及其他插件占用的端口
port_check() {
    local port=$1
    # 第一道防线：必须在合法范围内（防止误用路由器端口）
    _is_port_in_range "$port" || return 1
    # 第二道防线：系统端口扫描（路由器所有进程 + 其他插件）
    local hex=$(printf '%04X' "$port" 2>/dev/null)
    if [ -n "$hex" ]; then
        grep -q ":${hex} " /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null && return 1
    fi
    # 第三道防线：ports.db 注册表（merlin clash 自身占用）
    _port_db_init
    grep -q "^${port}|" "$PORTS_DB" 2>/dev/null && return 1
    return 0
}

# 分配一个空闲端口
port_alloc() {
    local i=$PORT_START
    while [ $i -le $PORT_END ]; do
        if port_check $i; then
            echo $i
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

# 分配 count 个连续空闲端口，返回起始端口号
port_alloc_block() {
    local count=$1
    [ "$count" -ge 1 ] || return 1
    local i=$PORT_START
    local max=$((PORT_END - count + 1))
    while [ $i -le $max ]; do
        local all_free=1
        local j=0
        while [ $j -lt $count ]; do
            local p=$((i + j))
            port_check $p || { all_free=0; break; }
            j=$((j + 1))
        done
        if [ $all_free -eq 1 ]; then
            echo $i
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

# 注册端口到数据库
# 用法: port_register <port> <type> <tag> [ext_addr] [status]
port_register() {
    local port=$1
    local type=$2
    local tag=$3
    local ext="${4:-}"
    local status="${5:-reserved}"
    _port_db_init
    # 已存在则更新
    if grep -q "^${port}|" "$PORTS_DB" 2>/dev/null; then
        local tmp="/tmp/_pdb_$$_${0##*/}_${LINENO}"
        grep -v "^${port}|" "$PORTS_DB" > "$tmp" 2>/dev/null
        mv "$tmp" "$PORTS_DB"
    fi
    echo "${port}|${type}|${tag}|${status}|${ext}" >> "$PORTS_DB"
}

# 释放端口（按 tag 释放该 tag 下所有端口）
port_release() {
    local tag=$1
    _port_db_init
    [ -f "$PORTS_DB" ] || return 0
    local tmp="/tmp/_pdb_$$_${0##*/}_${LINENO}"
    grep -v "|${tag}|" "$PORTS_DB" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$PORTS_DB"
}

# 释放单个端口
port_release_port() {
    local port=$1
    _port_db_init
    [ -f "$PORTS_DB" ] || return 0
    local tmp="/tmp/_pdb_$$_${0##*/}_${LINENO}"
    grep -v "^${port}|" "$PORTS_DB" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$PORTS_DB"
}

# 更新端口状态
port_set_status() {
    local port=$1
    local new_status=$2
    _port_db_init
    [ -f "$PORTS_DB" ] || return 1
    local line=$(grep "^${port}|" "$PORTS_DB" 2>/dev/null | head -1)
    [ -z "$line" ] && return 1
    local new_line=$(echo "$line" | awk -F'|' -v s="$new_status" 'BEGIN{OFS="|"} {$4=s; print}')
    local tmp="/tmp/_pdb_$$_${0##*/}_${LINENO}"
    grep -v "^${port}|" "$PORTS_DB" > "$tmp" 2>/dev/null || true
    echo "$new_line" >> "$tmp"
    mv "$tmp" "$PORTS_DB"
}

# 查询端口所属: 输出 TYPE|TAG 或空
port_owner() {
    local port=$1
    _port_db_init
    grep "^${port}|" "$PORTS_DB" 2>/dev/null | head -1 | cut -d'|' -f2,3
}

# 列出已注册端口
port_list() {
    local type_filter="${1:-}"
    _port_db_init
    if [ -n "$type_filter" ]; then
        grep "|${type_filter}|" "$PORTS_DB" 2>/dev/null
    else
        cat "$PORTS_DB" 2>/dev/null
    fi
}

# 健康检查：清理僵尸条目（DB 中存在但 CHAIN_DIR 对应 meta 已丢失）
port_gc() {
    _port_db_init
    [ -f "$PORTS_DB" ] || return 0
    local tmp="/tmp/_pdb_$$_${0##*/}_${LINENO}"
    while IFS='|' read -r port type tag status ext; do
        [ -z "$port" ] && continue
        case "$type" in
            kcptun|udp2raw|ss)
                # CHAIN 端口：如果 meta 文件不存在，释放
                if [ ! -f "$CHAIN_DIR/$tag/meta" ]; then
                    continue
                fi
                ;;
        esac
        echo "${port}|${type}|${tag}|${status}|${ext}" >> "$tmp"
    done < "$PORTS_DB"
    mv "$tmp" "$PORTS_DB"
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
# 用法: parse_chain_url <url> [chain_idx]
# chain_idx: 节点索引（1-based），用于按 base+i 算法分配端口；0 表示自动探测
parse_chain_url() {
    local url="$1"
    local chain_idx="${2:-0}"
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

    # ---------------------------------------------------------------------
    # 端口分配（使用 port_manager）
    # 算法：基准端口 + 节点索引偏移（base + i）
    #   ss+kcptun+udp2raw: entry=1190+i, kcp=1290+i, udp=1390+i
    #   ss+kcptun (2 端口):  entry=1190+i, kcp=1290+i
    #   hy2+udp2raw (2 端口): entry=1190+i, udp=1290+i
    # chain_idx = 1-based 节点索引（由订阅脚本传入，0 表示自动探测）
    # ---------------------------------------------------------------------

    # 自动探测 chain_idx（如果未传入）：基于当前已注册链数 + 1
    if [ "$chain_idx" = "0" ] || [ -z "$chain_idx" ]; then
        # 用 ports.db 中已有的最大 idx 估算
        local used_max=0
        if [ -f "$PORTS_DB" ]; then
            # 取所有 entry 端口（1191-1289）的最大 idx
            local used_entry=$(awk -F'|' '$1>=1191 && $1<=1289 {print $1}' "$PORTS_DB" 2>/dev/null | sort -n | tail -1)
            if [ -n "$used_entry" ]; then
                used_max=$((used_entry - PORT_BASE_ENTRY))
            fi
        fi
        chain_idx=$((used_max + 1))
    fi

    # chain_idx 范围校验
    if [ "$chain_idx" -lt 1 ] || [ "$chain_idx" -gt "$PORT_INDEX_MAX" ]; then
        echo "CHAIN_PORT_ERROR: chain_idx=$chain_idx 超出范围 1-$PORT_INDEX_MAX" >&2
        return 1
    fi

    # 释放该 tag 旧端口（重新解析时清理）
    port_release "$tag"

    # ---------------------------------------------------------------------
    # 端口分配：base + chain_idx 算法 + 动态冲突顺延
    # 算法：mihomo = 1190 + chain_idx，kcp = 1290 + chain_idx，udp = 1390 + chain_idx
    # 如果规划的端口被路由器系统或其他插件占用，自动向后递增寻找空闲端口
    # 顺延后 chain_idx 保持不变，端口号随之偏移
    # ---------------------------------------------------------------------
    local entry_port=$((PORT_BASE_ENTRY + chain_idx))      # mihomo/最内层
    local kcp_port=$((PORT_BASE_KCPTUN + chain_idx))       # kcptun 中转
    local udp_port=$((PORT_BASE_UDP2RAW + chain_idx))      # udp2raw 外层

    # 动态冲突检测：端口被占用时自动递增顺延（与 netstat 一致：扫描系统所有监听端口）
    # get_free_port 实现见脚本顶部 port_manager 段
    entry_port=$(get_free_port $entry_port)
    kcp_port=$(get_free_port $kcp_port)
    udp_port=$(get_free_port $udp_port)

    # 范围校验（顺延可能超出最大索引）
    local max_entry=$((PORT_BASE_ENTRY + PORT_INDEX_MAX))
    local max_kcp=$((PORT_BASE_KCPTUN + PORT_INDEX_MAX))
    local max_udp=$((PORT_BASE_UDP2RAW + PORT_INDEX_MAX))
    if [ "$entry_port" -gt "$max_entry" ] || [ "$kcp_port" -gt "$max_kcp" ] || [ "$udp_port" -gt "$max_udp" ]; then
        echo "CHAIN_PORT_ERROR: 顺延后端口超出范围（entry=$entry_port kcp=$kcp_port udp=$udp_port）" >&2
        return 1
    fi

    # 提取 udp2raw 外部地址（保留 VPS 地址不变）
    local udp_ext=""
    local rest_e="$components"
    while [ -n "$rest_e" ]; do
        local ce=$(echo "$rest_e" | cut -d'|' -f1)
        rest_e=$(echo "$rest_e" | cut -d'|' -f2-)
        [ "$ce" = "$rest_e" ] && rest_e=""
        case "$ce" in
            udp2raw://*)
                udp_ext=$(echo "$ce" | grep -oE -- '-r[[:space:]]+[^ ]+' | head -1 | sed -E 's/^.*-r[[:space:]]+//')
                # 域名替换为 IP（udp2raw 内部 Go DNS 无法解析）
                if [ -n "$udp_ext" ] && ! echo "$udp_ext" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'; then
                    local ext_host=$(echo "$udp_ext" | cut -d: -f1)
                    local resolved_ip=$(ping -n -c 1 "$ext_host" 2>/dev/null | head -1 | sed 's/.*(\([^)]*\)).*/\1/')
                    if [ -n "$resolved_ip" ] && [ "$resolved_ip" != "$ext_host" ]; then
                        udp_ext=$(echo "$udp_ext" | sed "s|^$ext_host|$resolved_ip|")
                    fi
                fi
                ;;
        esac
    done

    # ---------------------------------------------------------------------
    # 按组件类型分配具体端口
    # 顺序: ss/hy2 → kcp → udp
    # ---------------------------------------------------------------------
    local adjusted_components=""
    local sc_idx=0
    local rest_proc="$components"
    while [ -n "$rest_proc" ]; do
        local sp=$(echo "$rest_proc" | cut -d'|' -f1)
        rest_proc=$(echo "$rest_proc" | cut -d'|' -f2-)
        [ "$sp" = "$rest_proc" ] && rest_proc=""
        [ -z "$sp" ] && continue
        sc_idx=$((sc_idx + 1))

        # 决定本组件的 listen 端口和 target
        # 拓扑（按用户参考）：
        #   3 组件链 [ss, kcp, udp]:
        #     ss:  mihomo proxy type, port 指向 kcp listen (= entry_port)
        #     kcp: listen = entry_port, target = udp_port (kcp_port + 100)
        #     udp: listen = kcp_port, target = VPS ext
        #   2 组件链 [hy2, udp]:
        #     hy2: mihomo proxy type, port 指向 udp listen (= entry_port)
        #     udp: listen = entry_port, target = VPS ext
        #   2 组件链 [ss, kcp]:
        #     ss:  mihomo proxy type, port 指向 kcp listen (= entry_port)
        #     kcp: listen = entry_port, target = VPS ext
        local cur_port=""
        local my_target=""
        case "$sc_idx" in
            1)
                # 第 1 个组件（ss/hy2）：仅作为 mihomo proxy 类型，端口指向下一个组件的 listen
                # clash server:port = 第 2 个组件的 listen
                cur_port=$entry_port
                # ss/hy2 没有自己的 listen 端口（mihomo 内部协议），不分配进程端口
                # 但 URL 中的 @127.0.0.1:PORT 替换为 entry_port（统一指向 entry 层）
                ;;
            2)
                # 第 2 个组件（kcp 或 udp）：监听 entry_port
                cur_port=$entry_port
                # target = 第 3 个组件的 listen（如果有）或 VPS ext
                if [ $comp_count -ge 3 ]; then
                    my_target="127.0.0.1:$udp_port"
                elif [ -n "$udp_ext" ]; then
                    my_target="$udp_ext"
                fi
                ;;
            3)
                # 第 3 个组件（udp）：监听 kcp_port
                cur_port=$kcp_port
                if [ -n "$udp_ext" ]; then
                    my_target="$udp_ext"
                fi
                ;;
        esac

        case "$sp" in
            ss://*|hysteria2://*)
                sp=$(echo "$sp" | sed "s|@127\.0\.0\.1:[0-9]*|@127.0.0.1:$cur_port|")
                port_register $cur_port ss "$tag" "" reserved
                ;;
            kcptun://*)
                local kcp_params=$(echo "$sp" | sed 's/^kcptun:\/\///' | sed 's/--listen /-l /g; s/--target /-r /g')
                kcp_params=$(echo "$kcp_params" | sed 's/--tcp false//g; s/--quiet false//g; s/--nocomp true/--nocomp/g; s/--nocomp false//g; s/--acknodelay false//g')
                kcp_params=$(echo "$kcp_params" | sed 's/  */ /g; s/^ *//; s/ *$//')
                kcp_params=$(echo "$kcp_params" | sed "s|-l [^ ]*|-l 127.0.0.1:$cur_port|")
                if [ -n "$my_target" ]; then
                    kcp_params=$(echo "$kcp_params" | sed "s|-r [^ ]*|-r $my_target|")
                fi
                sp="kcptun://$(echo "$kcp_params" | sed 's/^-l /--listen /g; s/^-r /--target /g')"
                port_register $cur_port kcptun "$tag" "" reserved
                ;;
            udp2raw://*)
                local udp_params=$(echo "$sp" | sed 's/^udp2raw:\/\///')
                udp_params=$(echo "$udp_params" | sed "s|-l [^ ]*|-l 127.0.0.1:$cur_port|")
                if [ -n "$my_target" ]; then
                    udp_params=$(echo "$udp_params" | sed "s|-r [^ ]*|-r $my_target|")
                fi
                sp="udp2raw://$udp_params"
                port_register $cur_port udp2raw "$tag" "$udp_ext" reserved
                ;;
        esac

        adjusted_components="${adjusted_components}|${sp}"
    done
    adjusted_components=$(echo "$adjusted_components" | sed 's/^|//')

    # 构建 adjusted_proxy_comp（clash 配置使用的 URL，指向 ss/hy2 listen）
    # ss/hy2 是 adjusted_components 的第一个，提取出来作为 PROXY_URL
    local first_component=$(echo "$adjusted_components" | cut -d'|' -f1)
    local adjusted_proxy_comp="$first_component"

    # 输出变量赋值
    echo "TAG='$tag'"
    echo "ENTRY_PORT='$entry_port'"
    echo "PROXY_URL='$adjusted_proxy_comp'"

    # 输出所有 sidecar（包括 ss/hy2）
    local sc_out_idx=0
    local rest_out="$adjusted_components"
    while [ -n "$rest_out" ]; do
        local sc_out=$(echo "$rest_out" | cut -d'|' -f1)
        rest_out=$(echo "$rest_out" | cut -d'|' -f2-)
        [ "$sc_out" = "$rest_out" ] && rest_out=""
        sc_out_idx=$((sc_out_idx + 1))
        echo "SIDECAR_${sc_out_idx}='$sc_out'"
    done
    echo "SIDECAR_COUNT='$sc_out_idx'"

    # 注册 CHAIN 节点
    mkdir -p "$CHAIN_DIR/$tag"
    {
        echo "TAG=$tag"
        echo "ENTRY_PORT=$entry_port"
        echo "PROXY_URL=$adjusted_proxy_comp"
        echo "SIDECAR_COUNT=$sc_out_idx"
        local si=0
        local rest_meta="$adjusted_components"
        while [ -n "$rest_meta" ]; do
            local sc_m=$(echo "$rest_meta" | cut -d'|' -f1)
            rest_meta=$(echo "$rest_meta" | cut -d'|' -f2-)
            [ "$sc_m" = "$rest_meta" ] && rest_meta=""
            si=$((si + 1))
            echo "SIDECAR_${si}=${sc_m}"
        done
    } > "$CHAIN_DIR/$tag/meta"

    # 记录端口占用（兼容旧的 ports 文件，_check_port 会扫描）
    # 只记录实际使用的端口（用于 _check_port 的旧路径检测）
    : > "$CHAIN_DIR/$tag/ports"
    echo "$entry_port" >> "$CHAIN_DIR/$tag/ports"
    [ "$kcp_port" != "$entry_port" ] && echo "$kcp_port" >> "$CHAIN_DIR/$tag/ports"
    [ "$udp_port" != "$entry_port" ] && [ "$udp_port" != "$kcp_port" ] && echo "$udp_port" >> "$CHAIN_DIR/$tag/ports"
    sort -u "$CHAIN_DIR/$tag/ports" -o "$CHAIN_DIR/$tag/ports"

    return 0
}

# 提取侧载命令中的 -r 远端 host（去掉端口）
_extract_remote_host() {
    local sc="$1"
    echo "$sc" | grep -oE -- '-r[[:space:]]+[^ ]+' | head -1 | sed -E 's/^.*-r[[:space:]]+//; s/:[0-9]+$//'
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
    local chain_failed=0
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
                local raw_sc="$cmd_line"
                cmd_line=$(echo "$cmd_line" | sed 's/^udp2raw:\/\///')
                cmd_line="$UDP2RAW_BIN $cmd_line"
                # 域名解析预检：仅对 udp2raw 的 -r 远端进行探测
                # 若为域名则 ping 解析后替换 -r 参数（udp2raw 内部 Go DNS 无法解析部分域名）
                local remote_host=$(_extract_remote_host "$raw_sc")
                if [ -n "$remote_host" ] && ! echo "$remote_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                    local resolved
                    resolved=$(ping -n -c 1 "$remote_host" 2>/dev/null | head -1 | sed 's/.*(\([^)]*\)).*/\1/')
                    if [ -z "$resolved" ]; then
                        echo_date "🔴$tag ${bin_type} 域名解析失败: $remote_host" >> $LOG_FILE
                        echo "$cmd_line" > "$CHAIN_DIR/$tag/${bin_type}.cmd"
                        chain_failed=1
                        idx=$((idx - 1))
                        continue
                    fi
                    # 替换 raw_sc 中的 -r host:port 为 -r resolved_ip:port
                    # 用 | 作 delimiter 避免 $remote_host 中 . 被 sed 当通配符
                    local r_arg=$(echo "$raw_sc" | grep -oE -- '-r[[:space:]]+[^ ]+' | head -1)
                    local r_replacement=$(echo "$r_arg" | sed "s|$remote_host|$resolved|")
                    raw_sc=$(echo "$raw_sc" | sed "s|$r_arg|$r_replacement|")
                    cmd_line=$(echo "$cmd_line" | sed "s|$r_arg|$r_replacement|")
                fi
                ;;
        esac

        [ -z "$bin_type" ] && { idx=$((idx - 1)); continue; }

        local err_log="$CHAIN_DIR/$tag/${bin_type}.err"
        nohup $cmd_line >/dev/null 2>"$err_log" &
        local pid=$!
        echo "$pid" > "$CHAIN_DIR/$tag/${bin_type}.pid"
        echo "$cmd_line" > "$CHAIN_DIR/$tag/${bin_type}.cmd"
        if ! kill -0 "$pid" 2>/dev/null; then
            local err_tail
            err_tail=$(head -c 300 "$err_log" 2>/dev/null | tr '\n' ' ' | tr -s ' ')
            [ -n "$err_tail" ] && err_tail=" | $err_tail"
            echo_date "🔴$tag ${bin_type} 启动失败${err_tail}" >> $LOG_FILE
            chain_failed=1
        else
            # 启动成功 → 更新端口状态为 active
            local bin_port=$(echo "$cmd_line" | grep -oE -- '-l[[:space:]]+[^ ]+' | head -1 | sed 's/.*://; s/[^0-9].*//')
            [ -n "$bin_port" ] && port_set_status "$bin_port" active
        fi

        idx=$((idx - 1))
    done

    if [ "$chain_failed" = "1" ]; then
        echo_date "🔴CHAIN [$tag] 侧载启动失败，请检查上述错误" >> $LOG_FILE
        return 1
    fi
    # 生成端口详情日志
    local ep=$(grep '^ENTRY_PORT=' "$meta" | cut -d= -f2-)
    local log_detail="$ep"
    local sc1=$(grep "^SIDECAR_1=" "$meta" | cut -d= -f2-)
    local sc2=$(grep "^SIDECAR_2=" "$meta" | cut -d= -f2-)
    local p1=""
    if echo "$sc1" | grep -q "kcptun"; then
        p1=$(echo "$sc1" | grep -oE '--listen[[:space:]]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | head -1)
        [ -n "$p1" ] && log_detail="$log_detail kcptun:$p1"
    elif echo "$sc1" | grep -q "udp2raw"; then
        p1=$(echo "$sc1" | grep -oE '-l[[:space:]]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | head -1)
        [ -n "$p1" ] && log_detail="$log_detail udp2raw:$p1"
    fi
    if echo "$sc2" | grep -q "udp2raw"; then
        local p2=$(echo "$sc2" | grep -oE '-l[[:space:]]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | head -1)
        [ -n "$p2" ] && log_detail="$log_detail udp2raw:$p2"
    fi
    echo_date "🟢CHAIN [$tag] entry:$log_detail 启动成功" >> $LOG_FILE
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
    # 释放该 tag 的所有端口
    port_release "$tag"

    # 保留 meta/ports 文件，供后续 start_all 读取

    echo_date "🟢CHAIN [$tag] 已关闭" >> $LOG_FILE
    return 0
}

# 启动所有已注册的 CHAIN
start_all_chains() {
    port_gc
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
    : > "$PORTS_DB"
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
