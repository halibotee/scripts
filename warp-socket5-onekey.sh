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
SCRIPT_VERSION="1.1.0-Menu-Lite"
# ------------------------

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

ShowSOCKS5(){
# 此函数现在只设置 S5Status 变量, 不打印它
if [[ $(systemctl is-active warp-svc) = active ]]; then
mport=`warp-cli --accept-tos settings 2>/dev/null | grep 'WarpProxy on port' | awk -F "port " '{print $2}'`
s5ip=`curl -sx socks5h://localhost:$mport icanhazip.com -k`
nfs5
gpt1=$(curl -sx socks5h://localhost:$mport https://chat.openai.com 2>&1)
gpt2=$(curl -sx socks5h://localhost:$mport https://android.chat.openai.com 2>&1)
checkgpt
nonf=$(curl -sx socks5h://localhost:$mport --user-agent "${UA_Browser}" http://ip-api.com/json/$s5ip?lang=zh-CN -k | cut -f2 -d"," | cut -f4 -d '"')
country=$nonf
socks5=$(curl -sx socks5h://localhost:$mport www.cloudflare.com/cdn-cgi/trace -k --connect-timeout 2 | grep warp | cut -d= -f2) 
case ${socks5} in 
plus) 
S5Status=$(white "Socks5 WARP+状态：\c" ; rred "运行中，WARP+账户(剩余WARP+流量：$((`warp-cli --accept-tos account | grep Quota | awk '{ print $(NF) }'`/1000000000)) GB)" ; white " Socks5 端口：\c" ; rred "$mport" ; white " 服务商 Cloudflare 获取IPV4地址：\c" ; rred "$s5ip  $country" ; white " 奈飞NF解锁情况：\c" ; rred "$NF" ; white " ChatGPT解锁情况：\c" ; rred "$chat");;  
on) 
S5Status=$(white "Socks5 WARP状态：\c" ; green "运行中，WARP普通账户(无限WARP流量)" ; white " Socks5 端口：\c" ; green "$mport" ; white " 服务商 Cloudflare 获取IPV4地址：\c" ; green "$s5ip  $country" ; white " 奈飞NF解锁情况：\c" ; green "$NF" ; white " ChatGPT解锁情况：\c" ; green "$chat");;  
*) 
S5Status=$(white "Socks5 WARP状态：\c" ; yellow "已安装Socks5-WARP客户端，但端口处于关闭状态")
esac 
else
S5Status=$(white "Socks5 WARP状态：\c" ; red "未安装Socks5-WARP客户端")
fi
}

# --- [新增] 复活 cso (卸载) 函数 ---
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

# --- [新增] 复活 SOCKS5WARPPORT (改端口) 函数 ---
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
[[ -n $port ]] && warp-cli --accept-tos set-proxy-port $port >/dev/null 2>&1
green "当前socks5端口：$port"
}

# --- [重构] 重命名为 install_socks5 ---
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
    curl -fsSl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
    sudo apt-get update && sudo apt-get install cloudflare-warp
    fi
    
    # 5. 配置
    warpip
    echo y | warp-cli registration new
    warp-cli mode proxy 
    warp-cli proxy port 40000
    warp-cli connect
    
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
# --- [修改] 增加 ss (iproute2/net-tools) 依赖 ---
if [[ $release = Centos ]]; then
    packages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "ss")
    inspackages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "net-tools")
else
    packages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "ss")
    inspackages=("curl" "openssl" "bc" "python3" "screen" "qrencode" "wget" "iproute2")
fi

for i in "${!packages[@]}"; do
package="${packages[$i]}"
inspackage="${inspackages[$i]}"
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

# --- [新增] 脚本主菜单 ---
main_menu() {
    while true; do
        clear
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        bblue " CFwarp Socks5 (warp-cli) 管理脚本"
        white " 脚本版本: $(blue "$SCRIPT_VERSION")"
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        # 实时显示状态
        ShowSOCKS5
        echo
        white "------------------------------------------------------------------------------------------------"
        echo -e " ${S5Status}"
        white "------------------------------------------------------------------------------------------------"
        echo
        
        # 菜单选项
        green " 1. 安装/启动 Socks5-WARP (默认端口 40000)"
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


# --- 脚本主入口 ---
# 1. 运行必要的依赖检查
checkyl
warpyl
cpujg

# 2. 进入主菜单
main_menu
