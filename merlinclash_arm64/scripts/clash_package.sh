#!/bin/sh

export KSROOT=/koolshare
source /koolshare/scripts/clash_base.sh
eval $(dbus export merlinclash_)
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOG_FILE=/tmp/upload/merlinclash_log.txt

package_plugin(){
	rm -rf /tmp/merlinclash

	echo_date "检测架构..." >> $LOG_FILE
	local ROT_ARCH=$(uname -m)
	local PKG_ARCH="arm32"
	[ "$ROT_ARCH" = "aarch64" ] && PKG_ARCH="arm64"
	echo_date "架构: $PKG_ARCH (uname: $ROT_ARCH)" >> $LOG_FILE

	local PKG_FILENAME="mc_package_${PKG_ARCH}.tar.gz"
	rm -rf /tmp/upload/$PKG_FILENAME

	local PKG_DIR=/tmp/merlinclash
	mkdir -p $PKG_DIR/bin64
	mkdir -p $PKG_DIR/bin32
	mkdir -p $PKG_DIR/clash
	mkdir -p $PKG_DIR/conf
	mkdir -p $PKG_DIR/dashboard
	mkdir -p $PKG_DIR/res
	mkdir -p $PKG_DIR/rule_configs
	mkdir -p $PKG_DIR/scripts
	mkdir -p $PKG_DIR/webs
	mkdir -p $PKG_DIR/yaml_basic
	mkdir -p $PKG_DIR/yaml_dns

	echo_date "收集二进制文件..." >> $LOG_FILE
	if [ "$PKG_ARCH" = "arm64" ]; then
		cp -rf /koolshare/bin/clash $PKG_DIR/bin64/
		[ -f /koolshare/bin/yq ] && cp -rf /koolshare/bin/yq $PKG_DIR/bin64/
		[ -f /koolshare/bin/jq ] && cp -rf /koolshare/bin/jq $PKG_DIR/bin64/
		[ -f /koolshare/bin/haveged ] && cp -rf /koolshare/bin/haveged $PKG_DIR/bin64/
		[ -f /koolshare/bin/kcptun ] && cp -rf /koolshare/bin/kcptun $PKG_DIR/bin64/
		[ -f /koolshare/bin/udp2raw ] && cp -rf /koolshare/bin/udp2raw $PKG_DIR/bin64/
		rm -rf $PKG_DIR/bin32
	else
		cp -rf /koolshare/bin/clash $PKG_DIR/bin32/
		[ -f /koolshare/bin/yq ] && cp -rf /koolshare/bin/yq $PKG_DIR/bin32/
		[ -f /koolshare/bin/jq ] && cp -rf /koolshare/bin/jq $PKG_DIR/bin32/
		[ -f /koolshare/bin/haveged ] && cp -rf /koolshare/bin/haveged $PKG_DIR/bin32/
		[ -f /koolshare/bin/kcptun ] && cp -rf /koolshare/bin/kcptun $PKG_DIR/bin32/
		[ -f /koolshare/bin/udp2raw ] && cp -rf /koolshare/bin/udp2raw $PKG_DIR/bin32/
		rm -rf $PKG_DIR/bin64
	fi

	echo_date "收集插件文件..." >> $LOG_FILE
	[ -f /koolshare/merlinclash/Shanghai ] && cp -rf /koolshare/merlinclash/Shanghai $PKG_DIR/clash/
	[ -f /koolshare/merlinclash/GeoSite.dat ] && cp -rf /koolshare/merlinclash/GeoSite.dat $PKG_DIR/clash/
	[ -f /koolshare/merlinclash/GeoIP.dat ] && cp -rf /koolshare/merlinclash/GeoIP.dat $PKG_DIR/clash/
	cp -rf /koolshare/merlinclash/version $PKG_DIR/
	cp -rf /koolshare/merlinclash/dashboard/* $PKG_DIR/dashboard/
	cp -rf /koolshare/merlinclash/conf/* $PKG_DIR/conf/
	cp -rf /koolshare/merlinclash/rule_configs/* $PKG_DIR/rule_configs/
	cp -rf /koolshare/merlinclash/yaml_basic/* $PKG_DIR/yaml_basic/
	cp -rf /koolshare/merlinclash/yaml_dns/* $PKG_DIR/yaml_dns/

	echo_date "收集脚本文件..." >> $LOG_FILE
	cp -rf /koolshare/scripts/clash*.sh $PKG_DIR/scripts/
	[ -f /koolshare/scripts/merlinclash_install.sh ] && cp -rf /koolshare/scripts/merlinclash_install.sh $PKG_DIR/install.sh
	[ -f /koolshare/scripts/uninstall_merlinclash.sh ] && cp -rf /koolshare/scripts/uninstall_merlinclash.sh $PKG_DIR/uninstall.sh

	echo_date "收集网页文件..." >> $LOG_FILE
	cp -rf /koolshare/webs/Module_merlinclash.asp $PKG_DIR/webs/
	cp -rf /koolshare/res/* $PKG_DIR/res/

	echo_date "创建平台标识文件..." >> $LOG_FILE
	if [ "$PKG_ARCH" = "arm64" ]; then
		printf "hnd\nmtk\nipq64\n" > $PKG_DIR/.valid
	else
		printf "hnd\nqca\nipq32\n" > $PKG_DIR/.valid
	fi

	echo_date "设置权限..." >> $LOG_FILE
	chmod 755 $PKG_DIR/bin64/* $PKG_DIR/bin32/* 2>/dev/null
	chmod 755 $PKG_DIR/scripts/*.sh 2>/dev/null

	echo_date "正在打包..." >> $LOG_FILE
	cd /tmp
	tar -czf /tmp/$PKG_FILENAME merlinclash
	if [ -s /tmp/$PKG_FILENAME ]; then
		mv -f /tmp/$PKG_FILENAME /tmp/upload/$PKG_FILENAME
		local SIZE=$(du -h /tmp/upload/$PKG_FILENAME | awk '{print $1}')
		echo_date "打包完成，文件: $PKG_FILENAME，大小: $SIZE" >> $LOG_FILE
		rm -rf /tmp/merlinclash
	else
		echo_date "打包失败，文件为空" >> $LOG_FILE
		rm -rf /tmp/merlinclash
		rm -rf /tmp/$PKG_FILENAME
	fi
}

case $2 in
package)
	echo_date "============= 开始打包插件 =============" > $LOG_FILE
	(package_plugin; echo BBABBBBC >> $LOG_FILE) &
	http_response "$1"
	;;
esac
