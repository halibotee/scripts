# Repo: VPS Scripts + Merlin Clash Plugin

Two parts: `vps_scripts/` (VPS deployment shell scripts) and `merlinclash/` (koolshare Merlin Clash plugin for ASUS routers). Active development is in `merlinclash/`.

## Router: RT-AX86U, koolshare merlin, aarch64

Sync command:
```sh
sshpass -p 'ha257j5' ssh -p 2233 AX86U@192.168.50.1 'cat > /koolshare/PATH' < local_file
```
After sync: `chmod 755` for .sh, `sh -n` to syntax check. `sftp-server` unavailable — use `cat >` pipe.

## Key files (merlinclash/)

| File | Role |
|---|---|
| `scripts/clash_config.sh` | Main flow: `apply_mc()`, `start_chain_daemons()`, `kill_chain_daemons()` |
| `scripts/clash_subscribe.sh` | Subscription parsing, CHAIN:// processing, `process_chain_link()` |
| `scripts/clash_base.sh` | `find_free_port()`, shared helpers |
| `scripts/clash_package.sh` | Package running plugin into `AX-MerlinClash.tar.gz` |
| `webs/Module_merlinclash.asp` | WebUI — ASP + JS, ~3800 lines |
| `install.sh` | Install: sets dbus values, deploys files |
| `uninstall.sh` | Uninstall: preserves kcptun/jq/udp2raw |

## Busybox ash constraints

- No `timeout` command; use `sleep` + PID polling
- `netstat -anu` for UDP ports, `netstat -anp` for TCP
- `iptables-save | grep -v | iptables-restore` works
- `grep -q` supported; `nslookup` returns multi-line with `Address 1:` lines

## Daemon startup race condition

Multiple udp2raw processes starting simultaneously corrupt iptables. Solution in `start_chain_daemons()`: `sleep 1` between each config file's daemons. Verified: all 10 processes (4 kcptun + 6 udp2raw) start reliably with this stagger.

## Chain node architecture

CHAIN:// nodes layer: `ss/hysteria2 → kcptun → udp2raw`
- kcptun uses `-l`/`-r` flags (NOT `--listen`/`--target` — different from upstream kcptun)
- udp2raw uses `--raw-mode faketcp`
- DNS resolution for `-r` domain: done at daemon startup (not subscribe time) with fallback to subscribe-time resolved IP
- Port range: 1191-1391, allocated from smallest, tracked in `/tmp/.merlinclash_chain_assigned`
- Startup port mapping logged: `CA_SKU kcptun :1192 -> udp2raw :1191 -> ca.xshine.top:31853`

## Daemon kill order & SIGKILL fallback

`kill_chain_daemons()` 在 `clash_config.sh`:
1. **kcptun**: `killall` → sleep 1 → `pidof` 检查 → 再 sleep 1 → 还活着则 `killall -9`
2. **udp2raw**: `killall` → 5 轮 sleep 1 → `pidof` 检查 → 还活着则 `killall -9`
3. 清理 `/tmp/.merlinclash_chain_assigned` + `iptables-save | grep -v udp2rawDwrW`
4. 最终 `pidof` 双重确认 + `netstat` 检查端口释放

杀前记录 PID 数量和进程号，杀后确认关闭或标记残留。日志示例：
```
关闭串联节点进程...
  kcptun: 5个 PID:9142 9237 9291 9341 9392
  udp2raw: 10个 PID:9141 9193 9236 ...
串联节点进程已全部关闭
串联端口已全部释放
```

`kill_process()` 同理记录 clash/haveged 的 PID 并确认关闭。

## Known port mapping issue

`find_free_port()` 在订阅时分配端口，若 `/tmp/.merlinclash_chain_assigned` 跨订阅残留，
会导致 `Custom.yaml` 的内层 URL 端口与 `chain_configs` 守护进程端口不匹配。
**修复:** 重新订阅 (`clash_subscribe.sh subscribe`) 可刷新全部端口分配。

## WebUI (ASP) conventions

- Progress polling: `push_data`/`intoQueue`/`get_realtime_log` pattern
- JS recursion: `setTimeout("funcName();", 500)` string format (not function reference)
- Dedicated polling vars per feature (e.g., `_pkg_respLen`, `_pkg_noChange`) to avoid global conflicts
- Loading bar: `showMCLoadingBar(seconds)` — must pass `seconds` param

## Package plugin (clash_package.sh)

### Router-side packaging
- Output: `/tmp/upload/AX-MerlinClash_ARM64.tar.gz` (arm64) or `..._ARM32.tar.gz` (arm32)
- Run: `sh /koolshare/scripts/clash_package.sh "" package`
- `.valid` file:
  - ARM64: `hnd\nmtk\nipq64\n`
  - ARM32: `hnd\nqca\nipq32\n`
- `chmod 755` must be applied after `cat >` pipe (pipe loses permissions)
- Background: `(package_plugin; echo BBABBBBC >> $LOG_FILE) &` then `http_response`

### Local packaging (from repo)
```sh
# ARM64
cd merlinclash_arm64
tar -czf /tmp/upload/AX-MerlinClash_ARM64.tar.gz \
  --transform='s|^|merlinclash/|' \
  bin64/ clash/ conf/ dashboard/ install.sh res/ rule_configs/ scripts/ \
  uninstall.sh version webs/ yaml_basic/ yaml_dns/ .valid

# ARM32
cd merlinclash_arm32
tar -czf /tmp/upload/AX-MerlinClash_ARM32.tar.gz \
  --transform='s|^|merlinclash/|' \
  bin32/ clash/ conf/ dashboard/ install.sh res/ rule_configs/ scripts/ \
  uninstall.sh version webs/ yaml_basic/ yaml_dns/ .valid
```
Note: `kcptun`/`udp2raw` binaries are NOT in the repo — they must be fetched from a running router for arm64 packages.

## Git & Versioning

Commits pushed to `origin/main`. No CI, no tests, no lint. Manual testing on router.

**After every file modification, automatically:**
1. Bump patch version for scripts that track `SCRIPT_VERSION`:
   - `ax-singbox-proxy.sh` → `bash ax-singbox-proxy.sh --bump-version=patch`
   - `ax-acme.sh` → edit `SCRIPT_VERSION` line manually (no built-in bump)
2. `git add` modified files + `.bak.*` backups
3. `git commit -m "..."` with descriptive message
4. `git push origin main`
