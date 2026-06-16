#!/bin/sh
source /koolshare/scripts/base.sh
eval $(dbus export ss_basic_)
alias echo_date='echo 【$(TZ=UTC-8 date -R +%Y年%m月%d日\ %X)】:'

case $2 in
1)
    true > /tmp/upload/ss_log.txt
    http_response "$1"
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
    echo_date "                Xray 程序更新" | tee -a /tmp/upload/ss_log.txt
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt

    CUR_VER=$(/koolshare/bin/xray -version 2>/dev/null | head -n 1 | cut -d " " -f2 | sed 's/v//g')
    [ -z "${CUR_VER}" ] && CUR_VER="0"
    echo_date "当前版本：${CUR_VER}" | tee -a /tmp/upload/ss_log.txt

    echo_date "检查最新版本..." | tee -a /tmp/upload/ss_log.txt
    LATEST_JSON=$(curl -sL --connect-timeout 10 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null)
    if [ -z "${LATEST_JSON}" ]; then
        echo_date "获取最新版本信息失败！请检查网络连接。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    LATEST_VER=$(echo "${LATEST_JSON}" | /koolshare/bin/jq -r '.tag_name | sub("^v"; "")' 2>/dev/null)
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

    DOWNLOAD_URL=$(echo "${LATEST_JSON}" | /koolshare/bin/jq -r '.assets[] | select(.name=="Xray-linux-arm64-v8a.zip") | .browser_download_url' 2>/dev/null)
    if [ -z "${DOWNLOAD_URL}" ]; then
        echo_date "获取下载地址失败！" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    echo_date "下载地址：${DOWNLOAD_URL}" | tee -a /tmp/upload/ss_log.txt
    echo_date "下载中，请稍候..." | tee -a /tmp/upload/ss_log.txt
    curl -L --connect-timeout 10 --max-time 300 -o /tmp/Xray-linux-arm64-v8a.zip "${DOWNLOAD_URL}" 2>&1 | tee -a /tmp/upload/ss_log.txt

    if [ ! -f /tmp/Xray-linux-arm64-v8a.zip ] || [ ! -s /tmp/Xray-linux-arm64-v8a.zip ]; then
        echo_date "下载失败！文件不存在或为空。" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    echo_date "下载成功！文件大小：$(ls -lh /tmp/Xray-linux-arm64-v8a.zip | awk '{print $5}')" | tee -a /tmp/upload/ss_log.txt

    echo_date "解压 Xray 压缩包 ..." | tee -a /tmp/upload/ss_log.txt
    rm -rf /tmp/xray_extract
    mkdir -p /tmp/xray_extract
    unzip -o /tmp/Xray-linux-arm64-v8a.zip -d /tmp/xray_extract 2>&1 | tee -a /tmp/upload/ss_log.txt

    if [ ! -f /tmp/xray_extract/xray ]; then
        echo_date "解压后未找到 xray 二进制文件！" | tee -a /tmp/upload/ss_log.txt
        echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
        echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
        exit 1
    fi

    echo_date "停止旧 Xray 进程 ..." | tee -a /tmp/upload/ss_log.txt
    killall xray >/dev/null 2>&1
    sleep 1

    echo_date "安装新 Xray 二进制文件 ..." | tee -a /tmp/upload/ss_log.txt
    chmod +x /tmp/xray_extract/xray
    mv /tmp/xray_extract/xray /koolshare/bin/xray
    chmod +x /koolshare/bin/xray

    echo_date "Xray 版本信息：" | tee -a /tmp/upload/ss_log.txt
    /koolshare/bin/xray -version 2>&1 | head -n 1 | tee -a /tmp/upload/ss_log.txt

    echo_date "重启 fancyss 服务 ..." | tee -a /tmp/upload/ss_log.txt
    sh /koolshare/ss/ssconfig.sh restart >/dev/null 2>&1

    echo_date "Xray 更新完成！" | tee -a /tmp/upload/ss_log.txt
    echo_date "===================================================================" | tee -a /tmp/upload/ss_log.txt
    echo XU6J03M6 | tee -a /tmp/upload/ss_log.txt
    ;;
esac
