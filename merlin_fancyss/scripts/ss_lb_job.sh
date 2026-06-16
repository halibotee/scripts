#!/bin/sh

source /koolshare/scripts/base.sh
eval $(dbus export ss_)

# 带日期时间的日志输出函数
log() {
    echo "[$(date '+%F %T')] $*" | tee -a /tmp/upload/ss_lb_job.log
}

# 判断某时间窗口内，返回0=在窗口, 1=不在
in_minutes_range() {
    local ch=$(echo "$1" | sed 's/^0*//')
    local cm=$(echo "$2" | sed 's/^0*//')
    local th=$(echo "$3" | sed 's/^0*//')
    local tm=$(echo "$4" | sed 's/^0*//')
    local wd=$5
    [ -z "$ch" ] && ch=0
    [ -z "$cm" ] && cm=0
    [ -z "$th" ] && th=0
    [ -z "$tm" ] && tm=0
    local diff=$(( (ch - th)*60 + (cm - tm) ))
    [ $diff -ge 0 ] && [ $diff -le $wd ]
}

# 读取主配置
ss_failover_enable=${ss_failover_enable:-"0"}
ss_daily_switch_enable=${ss_daily_switch_enable:-"0"}
ss_daily_switch_interval_enable=${ss_daily_switch_interval_enable:-"0"}

# 主开关未开直接退出
[ "$ss_failover_enable" != "1" ] && log "❎ 故障转移未启用，退出。" && exit 0

triggered=0

# 每日/每隔几日定时切换
if [ "$ss_daily_switch_enable" = "1" ]; then
    # 读取设置 (默认 0日, 0:0) - 需与 ssconfig.sh 保持一致
    set_days_raw=$(dbus get ss_daily_switch_days)
    set_hour_raw=$(dbus get ss_daily_switch_hour)
    set_minute_raw=$(dbus get ss_daily_switch_minute)
    
    # 应用默认值和健壮性检查 (允许 0)
    set_days=$((${set_days_raw:-0}))
    set_hour=$((${set_hour_raw:-0}))
    set_minute=$((${set_minute_raw:-0}))
    
    [ "$set_days" -lt 0 -o "$set_days" -gt 360 ] && set_days=0
    [ "$set_hour" -lt 0 -o "$set_hour" -gt 23 ] && set_hour=0
    [ "$set_minute" -lt 0 -o "$set_minute" -gt 59 ] && set_minute=0

    now_day=$(date +%d | sed 's/^0*//') # 当前日期 (e.g., 9)
    now_hour=$(date +%H)
    now_minute=$(date +%M)
    
    set_hour_fmt=$(printf '%02d' "$set_hour")
    set_minute_fmt=$(printf '%02d' "$set_minute")
    
    if [ "${set_days}" -gt 0 ]; then
        log "(每隔X日检查) 目标：每隔 ${set_days} 天 ${set_hour_fmt}:${set_minute_fmt}。 当前：${now_day} 号 ${now_hour}:${now_minute}。"
    else
        log "(每日检查) 目标：每天 ${set_hour_fmt}:${set_minute_fmt}。 当前：${now_hour}:${now_minute}。"
    fi

    # 1. 检查日期是否匹配 (取模运算)
    is_correct_day=0
    if [ "${set_days}" -eq 0 ]; then
        # 0 = 每天都匹配
        is_correct_day=1
        log "(每日检查) ➔ 日期匹配 (设置为每天)"
    elif [ $((${now_day} % ${set_days})) -eq 0 ]; then
        is_correct_day=1
        log "(每隔X日检查) ➔ 日期匹配 (${now_day}号 是 ${set_days} 的倍数)"
    elif [ "${now_day}" -eq 1 ]; then
        # 兼容 cron 的 */X (X>31) 逻辑，在1号触发
        is_correct_day=1
        log "(每隔X日检查) ➔ 日期匹配 (今天是 1 号，触发长周期检查)"
    else
        log "(每隔X日检查) ➔ 日期不匹配 (今天 ${now_day}号)"
    fi

    # 2. 检查时间是否在窗口期
    is_correct_time=0
    if in_minutes_range "$now_hour" "$now_minute" "$set_hour" "$set_minute" 5; then
        is_correct_time=1
        log "(每日/每隔X日检查) ➔ 时间匹配 (当前 ${now_hour}:${now_minute} 在 ${set_hour_fmt}:${set_minute_fmt} 窗口期)"
    else
        log "(每日/每隔X日检查) ➔ 时间不匹配"
    fi

    # 3. 必须日期和时间都匹配
    if [ "${is_correct_day}" = "1" ] && [ "${is_correct_time}" = "1" ]; then
        log "⏰ 满足定时切换条件。"
        triggered=1
    fi
fi


[ "$triggered" != "1" ] && log "🚫 没有检测到有效的定时任务触发，退出。" && exit 0

# 节点切换主逻辑
CURRENT=$(dbus get ssconf_basic_node)
SWITCH_POLICY=$(dbus get ss_failover_s4_2)
log "当前节点:[$CURRENT] 切换策略:[$SWITCH_POLICY]"

case "$SWITCH_POLICY" in
    1)
        TARGET=$(dbus get ss_failover_s4_3)
        log "策略1：备用节点，目标[$TARGET]"
        dbus set ss_failover_s4_3=$CURRENT
        ;;
    2)
        # 自动循环切换
        [ -z "$CURRENT" ] || ! [ "$CURRENT" -eq "$CURRENT" ] 2>/dev/null && log "❌ 当前节点号非法，退出。" && exit 1
        NEXT=$((CURRENT + 1))
        MAX=$(dbus list ssconf_basic_name_ | cut -d "=" -f1 | cut -d "_" -f4 | sort -rn | head -n1)
        [ "$NEXT" -gt "$MAX" ] && NEXT=1
        TARGET=$NEXT
        log "策略2：顺序切换，目标[$TARGET]"
        ;;
    3)
        log "策略3：最低延迟节点..."
        [ ! -f "/tmp/upload/webtest_bakcup.txt" ] && log "❌ 延迟测试结果不存在，切换失败。" && exit 1
        FAST=$(awk -F ">" '!/failed|stop|ns/ && $1!=""{print $1,$2}' /tmp/upload/webtest_bakcup.txt | sort -k2n | awk '{print $1;exit}')
        [ -z "$FAST" ] && log "❌ 未找到有效候选节点，切换失败。" && exit 1
        TARGET=$FAST
        log "策略3：低延迟节点[$TARGET]"
        ;;
    *)
        log "❌ 未知切换策略[$SWITCH_POLICY]，退出。" && exit 1
        ;;
esac

[ -z "$TARGET" ] && log "❌ 未获取到目标节点，退出。" && exit 1

log "执行切换:[$CURRENT]→[$TARGET]"
# 设置目标节点为当前节点
dbus set ssconf_basic_node=$TARGET

log "重启服务以应用新节点..."
sh /koolshare/ss/ssconfig.sh restart

log "✅ 节点切换流程结束。"
exit 0