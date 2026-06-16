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
├── merlin_fancyss/          # 路由器 Merlin 固件 (fancyss)
└── merlin_Mihomo/           # 路由器 Mihomo (Clash Meta)
```
