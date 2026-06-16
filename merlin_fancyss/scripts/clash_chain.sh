#!/bin/sh
export KSROOT=/koolshare
source $KSROOT/scripts/clash_base.sh

CHAIN_CONF="/koolshare/merlinclash/chain.conf"
CHAIN_RUN="/tmp/merlinclash_chain_runtime.conf"

sanitize_name(){
    echo "$1" | sed 's/[^a-zA-Z0-9_-]/_/g'
}

start_chain_daemons(){
    if [ ! -f "$CHAIN_CONF" ]; then return 0; fi
    while IFS='|' read -r name type inner_uri outer_cmd extra; do
        [ -z "$name" ] && continue
        local safe_name=$(sanitize_name "$name")
        local pid_file="/tmp/merlinclash_chain_${safe_name}.pid"
        if [ -f "$pid_file" ]; then
            local old_pid=$(cat "$pid_file")
            if kill -0 "$old_pid" 2>/dev/null; then
                continue
            fi
        fi
        if [ "$type" = "ss+kcptun+udp2raw" ] && [ -n "$extra" ]; then
            nohup $outer_cmd >/dev/null 2>&1 &
            local kcp_pid=$!
            nohup $extra >/dev/null 2>&1 &
            local udp_pid=$!
            echo "$kcp_pid" > "/tmp/merlinclash_chain_${safe_name}_kcp.pid"
            echo "$udp_pid" > "/tmp/merlinclash_chain_${safe_name}_udp.pid"
            echo "$name|$kcp_pid" >> "$CHAIN_RUN"
            echo "$name|$udp_pid" >> "$CHAIN_RUN"
        else
            nohup $outer_cmd >/dev/null 2>&1 &
            local new_pid=$!
            echo "$new_pid" > "$pid_file"
            echo "$name|$new_pid" >> "$CHAIN_RUN"
        fi
    done < "$CHAIN_CONF"
    return 0
}

stop_chain_daemons(){
    if [ ! -f "$CHAIN_RUN" ]; then return 0; fi
    while IFS='|' read -r name pid; do
        [ -z "$pid" ] && continue
        kill "$pid" 2>/dev/null
        local safe_name=$(sanitize_name "$name")
        rm -f "/tmp/merlinclash_chain_${safe_name}.pid"
        rm -f "/tmp/merlinclash_chain_${safe_name}_kcp.pid"
        rm -f "/tmp/merlinclash_chain_${safe_name}_udp.pid"
    done < "$CHAIN_RUN"
    rm -f "$CHAIN_RUN"
    return 0
}

register_chain(){
    local name="$1" type="$2" inner_uri="$3" outer_cmd="$4"
    local tmp_conf=$(mktemp)
    if [ -f "$CHAIN_CONF" ]; then
        grep -v "^${name}|" "$CHAIN_CONF" > "$tmp_conf"
    fi
    echo "${name}|${type}|${inner_uri}|${outer_cmd}" >> "$tmp_conf"
    mv "$tmp_conf" "$CHAIN_CONF"
    return 0
}

unregister_chain(){
    local name="$1"
    if [ ! -f "$CHAIN_CONF" ]; then return 0; fi
    local tmp_conf=$(mktemp)
    grep -v "^${name}|" "$CHAIN_CONF" > "$tmp_conf"
    mv "$tmp_conf" "$CHAIN_CONF"
    local safe_name=$(sanitize_name "$name")
    for sfx in "" "_kcp" "_udp"; do
        local pid_file="/tmp/merlinclash_chain_${safe_name}${sfx}.pid"
        if [ -f "$pid_file" ]; then
            kill $(cat "$pid_file") 2>/dev/null
            rm -f "$pid_file"
        fi
    done
    return 0
}

case $1 in
start)
    start_chain_daemons
    ;;
stop)
    stop_chain_daemons
    ;;
esac
