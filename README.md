# VPS Scripts

VPS 一键脚本集，支持 VLESS+Reality / Hysteria2 / Shadowsocks 隧道（UDP2RAW / KCPTUN）部署。

## 目录结构

```
├── vps_scripts/             # 主脚本目录
│   ├── ax-singbox-proxy.sh  # 多合一隧道管理脚本 (Sing-box)
│   ├── ax.sh                # (旧版) 多合一隧道管理脚本
│   ├── ax-acme.sh           # ACME 证书管理
│   ├── ax-optz.sh           # VPS 优化脚本
│   ├── ax-warpWireProxy.sh  # WARP WireGuard 代理
│   ├── ax-warpsocket5.sh    # WARP SOCKS5 代理
│   ├── CFwarp.sh            # WARP 配置工具
│   └── ...
├── package/                 # 二进制包/依赖
├── merlin_fancyss/          # 路由器 koolshare 完整备份 (~150M)
│   ├── scripts/             # 插件脚本 (75个 .sh)
│   ├── ss/                  # 科学上网配置 (SS/Xray/Hysteria2)
│   ├── webs/                # WebUI (ASP 页面)
│   ├── bin/                 # 二进制工具 (xray, clash, hysteria2...)
│   ├── init.d/              # 开机启动脚本
│   ├── res/                 # 前端资源
│   └── merlinclash/         # Magic Catling 子目录
├── merlin_Mihomo/           # Magic Catling (MerlinClash) 独立备份 (~6M)
├── merlinclash/             # Magic Catling 独立安装包 (~17M)
├── shadowsocks/             # 科学上网 (fancyss) 独立安装包 (~73M)
└── package/                 # 二进制/依赖包
```
