#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export LANG=en_US.UTF-8
endpoint=
red='\033[0;31m'
bblue='\033[0;34m'
yellow='\033[0;33m'
green='\033[0;32m'
plain='\033[0m'
red(){ echo -e "\033[31m\033[01m$1\033[0m";}
green(){ echo -e "\033[32m\033[01m$1\033[0m";}
yellow(){ echo -e "\033[33m\033[01m$1\033[0m";}
blue(){ echo -e "\033[36m\033[01m$1\033[0m";}
white(){ echo -e "\033[37m\033[01m$1\033[0m";}
bblue(){ echo -e "\033[34m\033[01m$1\033[0m";}
rred(){ echo -e "\033[35m\033[01m$1\033[0m";}
readtp(){ read -t5 -n26 -p "$(yellow "$1")" $2;}
readp(){ read -p "$(yellow "$1")" $2;}

# --- [修改] 版本号定义 ---
SCRIPT_VERSION="1.3.0 from halibotee"
# --- [新增] 日志文件定义 ---
FULL_LOG_FILE="/var/log/cfwarp_socks5.log"
ERROR_LOG_FILE="/var/log/cfwarp_socks5.error.log"

[[ $EUID -ne 0 ]] && yellow "请以root模式运行脚本" && exit

if [[ -f /etc/redhat-release ]]; then
release="Centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
release="Debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
release="Ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
release="Centos"
elif cat /proc/version | grep -q -E -i "debian"; then
release="Debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
release="Ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
release="Centos"
else 
red "不支持当前的系统，请选择使用Ubuntu,Debian,Centos系统。" && exit
fi
vsid=$(grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1)
op=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty_name | cut -d \" -f2)
version=$(uname -r | cut -d "-" -f1)
main=$(uname -r | cut -d "." -f1)
minor=$(uname -r | cut -d "." -f2)
vi=$(systemd-detect-virt)
case "$release" in
"Centos") yumapt='yum -y';;
"Ubuntu"|"Debian") yumapt="apt-get -y";;
esac
cpujg(){
case $(uname -m) in
aarch64) cpu=arm64;;
x86_64) cpu=amd64;;
*) red "目前脚本不支持$(uname -m)架构" && exit;;
esac
}

nf4(){
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
result=$(curl -4fsL --user-agent "${UA_Browser}" --write-out %{http_code} --output /dev/null --max-time 10 "https://www.netflix.com/title/70143836" 2>&1)
if [[ "$result" == "404" ]]; then 
NF="遗憾，当前IP仅解锁Netflix自制剧"
elif [[ "$result" == "403" ]]; then
NF="杯具，当前IP不能看Netflix"
elif [[ "$result" == "200" ]]; then
NF="恭喜，当前IP完整解锁Netflix非自制剧"
else
NF="死心吧，Netflix不服务当前IP地区"
fi
}

nf6(){
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
result=$(curl -6fsL --user-agent "${UA_Browser}" --write-out %{http_code} --output /dev/null --max-time 10 "https://www.netflix.com/title/70143836" 2>&1)
if [[ "$result" == "404" ]]; then 
NF="遗憾，当前IP仅解锁Netflix自制剧"
elif [[ "$result" == "403" ]]; then
NF="杯具，当前IP不能看Netflix"
elif [[ "$result" == "200" ]]; then
NF="恭喜，当前IP完整解锁Netflix非自制剧"
else
NF="死心吧，Netflix不服务当前IP地区"
fi
}

nfs5() {
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
result=$(curl --user-agent "${UA_Browser}" --write-out %{http_code} --output /dev/null --max-time 10 -sx socks5h://localhost:$mport -4sL "https://www.netflix.com/title/70143836" 2>&1)
if [[ "$result" == "404" ]]; then 
NF="遗憾，当前IP仅解锁Netflix自制剧"
elif [[ "$result" == "403" ]]; then
NF="杯具，当前IP不能看Netflix"
elif [[ "$result" == "200" ]]; then
NF="恭喜，当前IP完整解锁Netflix非自制剧"
else
NF="死心吧，Netflix不服务当前IP地区"
fi
}

v4v6(){
v4=$(curl -s4m5 icanhazip.com -k)
v6=$(curl -s6m5 icanhazip.com -k)
}

warpip(){
mkdir -p /root/warpip
v4v6
if [[ -z $v4 ]]; then
endpoint=[2606:4700:d0::a29f:c001]:2408
else
endpoint=162.159.192.1:2408
fi
}

restwarpgo(){
# 保留此函数仅用于 SOCKS5ins 中的冲突检查
kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
systemctl restart warp-go >/dev/null 2>&1
systemctl enable warp-go >/dev/null 2>&1
systemctl start warp-go >/dev/null 2>&1
}

chatgpt4(){
gpt1=$(curl -s4 https://chat.openai.com 2>&1)
gpt2=$(curl -s4 https://ios.chat.openai.com 2>&1)
}
chatgpt6(){
gpt1=$(curl -s6 https://chat.openai.com 2>&1)
gpt2=$(curl -s6 https://ios.chat.openai.com 2>&1)
}
checkgpt(){
if [[ $gpt2 == *VPN* ]]; then
chat='遗憾，当前IP仅解锁ChatGPT网页，未解锁客户端'
elif [[ $gpt2 == *Request* ]]; then
chat='恭喜，当前IP完整解锁ChatGPT (网页+客户端)'
else
chat='杯具，当前IP无法解锁ChatGPT服务'
fi
}

checkgemini(){
if echo "$gemini_raw" | grep -q "not available in your country" || echo "$gemini_raw" | grep -q "unavailable in your region"; then
    gemini='杯具，当前IP地区不可用'
elif [[ -n "$gemini_raw" ]]; then
    gemini='恭喜，可访问Gemini'
else
    gemini='检测失败 (超时或连接错误)'
fi
}

# --- [修改] ShowSOCKS5 函数, 增加日志提示 ---
ShowSOCKS5(){
    blue " 脚本版本: $(green "$SCRIPT_VERSION")"
    
    if [[ $(systemctl is-active warp-svc) = active ]]; then
        mport=`warp-cli --accept-tos settings 2>/dev/null | grep 'WarpProxy on port' | awk -F "port " '{print $2}'`
        
        # 检查SOCKS5是否真的在工作
        socks5=$(curl -sx socks5h://localhost:$mport www.cloudflare.com/cdn-cgi/trace -k --connect-timeout 4 | grep warp | cut -d= -f2) 
        
        if [[ $socks5 =~ on|plus ]]; then
            s5ip=`curl -sx socks5h://localhost:$mport icanhazip.com -k --max-time 5`
            nfs5
            gpt1=$(curl -sx socks5h://localhost:$mport https://chat.openai.com 2>&1)
            gpt2=$(curl -sx socks5h://localhost:$mport https://android.chat.openai.com 2>&1)
            checkgpt
            gemini_raw=$(curl -sx socks5h://localhost:$mport -sL --user-agent "${UA_Browser}" --max-time 5 https://gemini.google.com/ 2>&1)
            checkgemini
            nonf=$(curl -sx socks5h://localhost:$mport --user-agent "${UA_Browser}" http://ip-api.com/json/$s5ip?lang=zh-CN -k | cut -f2 -d"," | cut -f4 -d '"')
            country=$nonf

            if [[ $socks5 = plus ]]; then
                echo -e " $(blue "Socks5 WARP+状态：") $(rred "运行中 (WARP+账户)")"
                echo -e " $(blue "剩余WARP+流量：") $(rred "$((`warp-cli --accept-tos account | grep Quota | awk '{ print $(NF) }'`/1000000000)) GB")"
            else
                echo -e " $(blue "Socks5 WARP状态：") $(green "运行中 (WARP普通账户)")"
            fi
            
            echo -e " $(blue "Socks5 端口：") $(green "$mport")"
            echo -e " $(blue "Cloudflare IPV4：") $(green "$s5ip  $country")"
            echo -e " $(blue "奈飞NF解锁：") $(green "$NF")"
            echo -e " $(blue "ChatGPT解锁：") $(green "$chat")"
            # --- [修改] 移除 Gemini 文本空格 ---
            echo -e " $(blue "Gemini解锁：") $(green "$gemini")"

        else
            echo -e " $(blue "Socks5 WARP状态：") $(yellow "已安装，但Socks5代理连接失败 (端口: $mport)")"
        fi
    else
        echo -e " $(blue "Socks5 WARP状态：") $(red "未安装或服务未运行")"
    fi
    
    # --- [新增] 三日志提示 ---
    echo
    echo -e " $(yellow "提示: 使用 'cat $FULL_LOG_FILE' 查看完整日志")"
    echo -e " $(yellow "提示: 使用 'cat $ERROR_LOG_FILE' 查看错误日志")"
    echo -e " $(yellow "提示: 使用 'journalctl -u warp-svc -f' 查看服务日志")"
}


cso(){
warp-cli --accept-tos disconnect >/dev/null 2>&1
warp-cli --accept-tos disable-always-on >/dev/null 2>&1
warp-cli --accept-tos delete >/dev/null 2>&1
if [[ $release = Centos ]]; then
yum autoremove cloudflare-warp -y
else
apt purge cloudflare-warp -y
rm -f /etc/apt/sources.list.d/cloudflare-client.list /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
fi
$yumapt autoremove
green "Socks5-WARP 卸载完成。"
}

# --- [修改] v1.2.6 端口修改 Bug 修复 ---
SOCKS5WARPPORT(){
[[ ! $(type -P warp-cli) ]] && red "未安装Socks5-WARP，无法更改端口" && return 1
readp "请输入自定义socks5端口[2000～65535]（回车跳过为2000-65535之间的随机端口）:" port
if [[ -z $port ]]; then
port=$(shuf -i 2000-65535 -n 1)
until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]
do
[[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]] && yellow "\n端口被占用，请重新输入端口" && readp "自定义socks5端口:" port
done
else
until [[ -z $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]]
do
[[ -n $(ss -ntlp | awk '{print $4}' | sed 's/.*://g' | grep -w "$port") ]] && yellow "\n端口被占用，请重新输入端口" && readp "自定义socks5端口:" port
done
fi

if [[ -n $port ]]; then
    green "新端口设置成功：$port"
    yellow "正在应用新端口并重启服务 (约 10-12 秒)..."
    
    # [v1.2.6 修复方案]
    # 1. (服务运行时) 修改配置
    warp-cli --accept-tos set-proxy-port $port >/dev/null 2>&1
    # 2. 断开连接
    warp-cli --accept-tos disconnect >/dev/null 2>&1
    # 3. 停止服务 (强制释放旧端口)
    systemctl stop warp-svc
    sleep 2
    # 4. 启动服务 (强制读取新配置)
    systemctl start warp-svc
    sleep 3
    # 5. 重新连接
    warp-cli --accept-tos connect
    sleep 3 # 等待连接建立
    
    green "服务已重启并连接。"
else
    red "端口设置失败。"
fi
}

install_socks5(){
    # 1. 检查状态
    yellow "正在检查 Cloudflare WARP Socks5 (warp-cli) 状态..."
    if [[ $(systemctl is-active warp-svc) = active ]] && [[ $(warp-cli --accept-tos status 2>/dev/null) =~ 'Connected' ]]; then
        green "Socks5-WARP 已在运行中。无需重复安装。"
        return 0
    fi

    # 2. 检查环境
    yellow "检测Socks5-WARP安装环境中……"
    if [[ $release = Centos ]]; then
    [[ ! ${vsid} =~ 8 ]] && yellow "当前系统版本号：Centos $vsid \nSocks5-WARP仅支持Centos 8 " && return 1
    elif [[ $release = Ubuntu ]]; then
    [[ ! ${vsid} =~ 20|22|24 ]] && yellow "当前系统版本号：Ubuntu $vsid \nSocks5-WARP仅支持 Ubuntu 20.04/22.04/24.04系统 " && return 1
    elif [[ $release = Debian ]]; then
    [[ ! ${vsid} =~ 10|11|12|13 ]] && yellow "当前系统版本号：Debian $vsid \nSocks5-WARP仅支持 Debian 10/11/12/13系统 " && return 1
    fi

    # 3. 冲突检查
    systemctl stop wg-quick@wgcf >/dev/null 2>&1
    kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
    
    v4v6
    if [[ -n $v6 && -z $v4 ]]; then
    systemctl start wg-quick@wgcf >/dev/null 2>&1
    restwarpgo
    red "纯IPV6的VPS目前不支持安装Socks5-WARP" && sleep 2 && return 1
    else
    systemctl start wg-quick@wgcf >/dev/null 2>&1
    restwarpgo
    fi

    # 4. 开始安装
    yellow "正在执行一键安装/启动 Socks5-WARP..."
    if [[ $release = Centos ]]; then 
    yum -y install epel-release && yum -y install net-tools
    curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | tee /etc/yum.repos.d/cloudflare-warp.repo
    yum update
    yum -y install cloudflare-warp
    fi
    if [[ $release = Debian ]]; then
    [[ ! $(type -P gpg) ]] && apt update && apt install gnupg -y
    [[ ! $(apt list 2>/dev/null | grep apt-transport-https | grep installed) ]] && apt update && apt install apt-transport-https -y
    fi
    if [[ $release != Centos ]]; then 
    apt install net-tools -y
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
    # --- [修改] 自动同意 [Y/n] ---
    sudo apt-get update && sudo apt-get install -y cloudflare-warp
    fi
    
    # 5. 配置
    warpip
    yellow "正在自动注册新账户 (--accept-tos)..."
    warp-cli --accept-tos registration new
    warp-cli mode proxy 
    warp-cli proxy port 40000
    warp-cli --accept-tos connect
    
    yellow "正在等待连接稳定 (5 秒)..."
    sleep 5
    
    # 6. 确认
    if [[ $(systemctl is-active warp-svc) = active ]] && [[ $(warp-cli --accept-tos status 2>/dev/null) =~ 'Connected' ]]; then
        green "Socks5-WARP 已成功启动。"
    else
        red "Socks5-WARP 安装或启动失败。请检查日志。"
    fi
}

checkyl(){
if [ ! -f warp_update ]; then
green "首次运行，安装必要的依赖……请稍等"
if [[ $release = Centos && ${vsid} =~ 8 ]]; then
cd /etc/yum.repos.d/ && mkdir backup && mv *repo backup/ 
curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-8.repo
sed -i -e "s|mirrors.cloud.aliyuncs.com|mirrors.aliyun.com|g " /etc/yum.repos.d/CentOS-*
sed -i -e "s|releasever|releasever-stream|g" /etc/yum.repos.d/CentOS-*
yum clean all && yum makecache
cd
fi
if [ -x "$(command -v apt-get)" ]; then
apt update -y && apt install curl wget -y
elif [ -x "$(command -v yum)" ]; then
yum update && yum install epel-release -y && yum install curl wget -y
elif [ -x "$(command -v dnf)" ]; then
dnf update -y && dnf install curl wget -y
fi
if [ -x "$(command -v yum)" ] || [ -x "$(command -v dnf)" ]; then
if ! command -v "cronie" &> /dev/null; then
if [ -x "$(command -v yum)" ]; then
yum install -y cronie
elif [ -x "$(command -v dnf)" ]; then
dnf install -y cronie
fi
fi
fi
touch warp_update
fi
}

warpyl(){
if [[ $release = Centos ]]; then
    packages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "ss")
    inspackages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "net-tools")
else
    packages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "ss")
    inspackages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "iproute2")
fi

for i in "${!packages[@]}"; do
package="${packages[$i]}"
inspackage="${inspackages[i]}"
if ! command -v "$package" &> /dev/null; then
if [ -x "$(command -v apt-get)" ]; then
apt-get install -y "$inspackage"
elif [ -x "$(command -v yum)" ]; then
yum install -y "$inspackage"
elif [ -x "$(command -v dnf)" ]; then
dnf install -y "$inspackage"
fi
fi
done
}

main_menu() {
    while true; do
        clear
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        bblue " CFwarp Socks5 (warp-cli) 管理脚本"
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        # 实时显示状态
        yellow " 正在获取实时状态 (可能需要几秒钟)..."
        echo
        blue "------------------------------------------------------------------------------------------------"
        ShowSOCKS5
        blue "------------------------------------------------------------------------------------------------"
        echo
        
        # 菜单选项
        # --- [修改] 移除菜单 1 的 (默认端口) ---
        green " 1. 安装/启动 Socks5-WARP"
        green " 2. 修改 Socks5 端口"
        red   " 3. 卸载 Socks5-WARP"
        echo
        green " 0. 退出脚本"
        echo
        
        readp " 请输入数字 [0-3]: " choice
        
        case "$choice" in
            1)
                install_socks5
                readp "操作完成。按 [Enter] 键返回菜单..."
                ;;
            2)
                SOCKS5WARPPORT
                readp "操作完成。按 [Enter] 键返回菜单..."
                ;;
            3)
                cso
                readp "操作完成。按 [Enter] 键返回菜单..."
                ;;
            0)
                exit 0
                ;;
            *)
                red "输入错误，请重新输入。"
                sleep 1
                ;;
        esac
    done
}

# --- [新增] 脚本主包裹函数 (用于日志捕获) ---
script_main_wrapper() {
    # --- [新增] 日志生命周期管理 ---
    rm -f "$FULL_LOG_FILE" "$ERROR_LOG_FILE"
    echo "CFwarp v$SCRIPT_VERSION - 完整日志 - 开始于: $(date)" >> "$FULL_LOG_FILE"
    echo "CFwarp v$SCRIPT_VERSION - 错误日志 - 开始于: $(date)" >> "$ERROR_LOG_FILE"

    # 1. 运行必要的依赖检查
    checkyl
    warpyl
    cpujg

    # 2. 进入主菜单
    main_menu
}

# --- [修改] 脚本主入口 (用于双日志捕获) ---
# 1. 所有 stderr (错误) 都被 'tee' 捕获到 ERROR_LOG_FILE
# 2. stdout (标准输出) 和 stderr (错误) 都被 |& (管道) 合并，并 'tee' 捕获到 FULL_LOG_FILE
script_main_wrapper 2> >(tee -a "$ERROR_LOG_FILE") |& tee -a "$FULL_LOG_FILE"
