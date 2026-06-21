#!/bin/sh

# fancyss script for asuswrt/merlin based router with software center

source /koolshare/scripts/base.sh
# (修改) 加载所有 ss_ 和 ss_failover_ 的配置
eval $(dbus export ss)
eval $(dbus export ss_failover)

alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'

LOGFILE_F=/tmp/upload/ssf_status.txt
LOGFILE_C=/tmp/upload/ssc_status.txt
LOGFILE=/tmp/upload/ss_log.txt

# "每日定时切换"的 cron 任务管理函数
set_daily_switch_job(){
    # 先删除旧任务（兼容性清理）
    sed -i '/ss_daily_switch/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
    sed -i '/ss_lb_job/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
    
    # 根据新设置创建定时任务
    if [ "${ss_daily_switch_enable}" == "1" ]; then
        # 读取设置，默认值为 0 (每天), 0:0
        local days=$((${ss_daily_switch_days:-0}))
        local hour=$((${ss_daily_switch_hour:-0}))
        local min=$((${ss_daily_switch_minute:-0}))

        # 健壮性校验 (允许 0, 0=每天)
        [ "$days" -lt 0 -o "$days" -gt 360 ] && days=0
        [ "$hour" -lt 0 -o "$hour" -gt 23 ] && hour=0
        [ "$min" -lt 0 -o "$min" -gt 59 ] && min=0

        # 格式化为两位数
        local hour_fmt=$(printf "%02d" $hour)
        local min_fmt=$(printf "%02d" $min)
    
        # 根据 "日" 的设置生成 cron 规则
        local day_cron_rule="*"
        if [ "${days}" -gt 0 ]; then
            day_cron_rule="*/${days}"
            echo_date "⏰️fancyss每隔 ${days} 日 ${hour_fmt}:${min_fmt} 自动切换节点任务启用"
        else
            echo_date "⏰️fancyss每天 ${hour_fmt}:${min_fmt} 自动切换节点任务启用"
        fi

        # 生成 cron 命令
        cru a ss_daily_switch "${min_fmt} ${hour_fmt} ${day_cron_rule} * * /koolshare/scripts/ss_lb_job.sh"
    else
        echo_date "❎️fancyss每隔几日定时切换节点任务未启用！"
    fi
    
    # 移除"每隔几小时"的定时任务（因为它已被删除）
    sed -i '/ss_daily_switch_interval/d' /var/spool/cron/crontabs/* >/dev/null 2>&1
}

stop_status(){
    kill -9 $(pidof ss_status_main.sh) >/dev/null 2>&1
    kill -9 $(pidof ss_status.sh) >/dev/null 2>&1
    killall curl >/dev/null 2>&1
    killall curl-fancyss >/dev/null 2>&1
    killall httping >/dev/null 2>&1
    rm -rf /tmp/upload/ss_status.txt
}

check_status(){
    if [ "$ss_failover_enable" == "1" ];then
        echo "=========================================== 故障检测脚本重启 ==========================================" >> $LOGFILE_F
        echo "=========================================== 故障检测脚本重启 ==========================================" >> $LOGFILE_C
        start-stop-daemon -S -q -b -x /koolshare/scripts/ss_status_main.sh
    fi
}

true > $LOGFILE
http_response "$1"
usleep 200000

# (修改) 调用新的定时任务管理函数
set_daily_switch_job >> $LOGFILE

if [ "$ss_failover_enable" == "1" ];then
    echo_date "重启故障转移功能" >> $LOGFILE
    stop_status
    check_status
    echo_date "完成！" >> $LOGFILE
else
    echo_date "关闭故障转移功能" >> $LOGFILE
    stop_status
    echo_date "完成！" >> $LOGFILE
fi
echo XU6J03M6 >> $LOGFILE