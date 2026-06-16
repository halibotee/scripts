#!/bin/sh
source /koolshare/scripts/base.sh
eval $(dbus export ss_basic_)
alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'

case $2 in
1)
    true > /tmp/upload/ss_log.txt
    http_response "$1"
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
    echo_date "                Hysteria2 程序更新" | tee -a /tmp/upload/ss_log.txt
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt

    CUR_VER=$(/koolshare/bin/hysteria2 version 2>&1 | grep "^Version:" | cut -d: -f2 | sed 's/v//g' | tr -d '[:space:]')
    [ -z "${CUR_VER}" ] && CUR_VER="0"
    echo_date "当前版本：${CUR_VER}" | tee -a /tmp/upload/ss_log.txt

    echo_date "检查最新版本..." | tee -a /tmp/upload/ss_log.txt
    LATEST_JSON=$(curl -sL --connect-timeout 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" 2>/dev/null)
    if [ -z "${LATEST_JSON}" ]; then
        echo_date "获取最新版本信息失败！请检查网络连接。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    LATEST_TAG=$(echo "${LATEST_JSON}" | /koolshare/bin/jq -r '.tag_name' 2>/dev/null)
    LATEST_VER=$(echo "${LATEST_TAG}" | sed 's/^app\/v//;s/^v//')
    [ -z "${LATEST_VER}" ] && LATEST_VER="0"
    echo_date "最新版本：${LATEST_VER}" | tee -a /tmp/upload/ss_log.txt

    COMP=$(versioncmp "${CUR_VER}" "${LATEST_VER}")
    if [ "${COMP}" == "1" ]; then
        echo_date "发现新版本，开始下载..." | tee -a /tmp/upload/ss_log.txt
    elif [ "${COMP}" == "-1" ]; then
        echo_date "当前版本高于最新版本，跳过更新。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 0
    else
        echo_date "当前已是最新版本，无需更新。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 0
    fi

    DOWNLOAD_URL=$(echo "${LATEST_JSON}" | /koolshare/bin/jq -r '.assets[] | select(.name | test("hysteria-linux-arm64$")) | .browser_download_url' 2>/dev/null)
    if [ -z "${DOWNLOAD_URL}" ]; then
        echo_date "获取下载地址失败！" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    echo_date "下载地址：${DOWNLOAD_URL}" | tee -a /tmp/upload/ss_log.txt
    echo_date "下载中，请稍候..." | tee -a /tmp/upload/ss_log.txt
    curl -L --connect-timeout 10 --max-time 300 -o /tmp/hysteria-linux-arm64 "${DOWNLOAD_URL}" 2>&1 | tee -a /tmp/upload/ss_log.txt

    if [ ! -f /tmp/hysteria-linux-arm64 ] || [ ! -s /tmp/hysteria-linux-arm64 ]; then
        echo_date "下载失败！文件不存在或为空。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    echo_date "下载成功！文件大小：$(ls -lh /tmp/hysteria-linux-arm64 | awk '{print $5}')" | tee -a /tmp/upload/ss_log.txt

    echo_date "停止旧 Hysteria2 进程 ..." | tee -a /tmp/upload/ss_log.txt
    killall hysteria2 >/dev/null 2>&1
    sleep 1

    echo_date "安装新 Hysteria2 二进制文件 ..." | tee -a /tmp/upload/ss_log.txt
    chmod +x /tmp/hysteria-linux-arm64
    mv /tmp/hysteria-linux-arm64 /koolshare/bin/hysteria2
    chmod +x /koolshare/bin/hysteria2

    echo_date "Hysteria2 版本信息：" | tee -a /tmp/upload/ss_log.txt
    /koolshare/bin/hysteria2 version 2>&1 | head -n 10 | tee -a /tmp/upload/ss_log.txt

    echo_date "重启 fancyss 服务 ..." | tee -a /tmp/upload/ss_log.txt
    sh /koolshare/ss/ssconfig.sh restart >/dev/null 2>&1

    echo_date "Hysteria2 更新完成！" | tee -a /tmp/upload/ss_log.txt
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
    echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
    ;;
esac
