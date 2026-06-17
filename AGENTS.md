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

## WebUI (ASP) conventions

- Progress polling: `push_data`/`intoQueue`/`get_realtime_log` pattern
- JS recursion: `setTimeout("funcName();", 500)` string format (not function reference)
- Dedicated polling vars per feature (e.g., `_pkg_respLen`, `_pkg_noChange`) to avoid global conflicts
- Loading bar: `showMCLoadingBar(seconds)` — must pass `seconds` param

## Package plugin (clash_package.sh)

- Output: `/tmp/upload/AX-MerlinClash.tar.gz`
- Must have execute permission (`chmod 755`) — `cat >` pipe loses it
- `.valid` file mandatory for koolshare offline installer (contains `hnd\nmtk\nipq64`)
- Background: `(package_plugin; echo BBABBBBC >> $LOG_FILE) &` then `http_response`

## Git

Commits pushed to `origin/main`. No CI, no tests, no lint. Manual testing on router.
