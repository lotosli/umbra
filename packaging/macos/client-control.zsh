#!/bin/zsh
# Private migration payloads are supplied alongside this generic controller.
emulate -LR zsh
setopt ERR_EXIT NO_UNSET PIPE_FAIL
umask 077

readonly release_version='1.0.0-alpha'
readonly label='com.umbra.client'
readonly domain="gui/$(/usr/bin/id -u)"
readonly service="$domain/$label"
readonly support="$HOME/Library/Application Support/Umbra"
readonly logs="$HOME/Library/Logs/Umbra"
readonly agent="$HOME/Library/LaunchAgents/$label.plist"
readonly config="$support/client.toml"
readonly binary_dir="$HOME/.local/share/umbra/v$release_version"
readonly binary="$binary_dir/umbra"
readonly controller="$support/control.zsh"
readonly shortcut="$HOME/Applications/Umbra客户端.command"
readonly bundle="${0:A:h:h}"
transaction=0
previous_loaded=0
previous_disabled=0
backup=''

pause_if_terminal() {
    if [[ -t 0 && -t 1 ]]; then
        print ''
        read -r '?按回车关闭窗口……' || true
    fi
}
fail() { print -u2 -- "$1"; return 1; }
loaded() { /bin/launchctl print "$service" >/dev/null 2>&1; }
service_pid() {
    /bin/launchctl print "$service" 2>/dev/null |
        /usr/bin/awk '$1 == "pid" && $2 == "=" { print $3; exit }'
}
stop_loaded() { if loaded; then /bin/launchctl bootout "$service"; fi; }
check_owner() {
    [[ -f "$agent" ]] || fail '尚未安装 Umbra，请先运行“安装.command”。'
    local current
    current=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$agent")
    [[ "$current" == "$binary" ]] || fail '当前服务由其他版本管理，请使用对应版本的控制脚本。'
}
backup_one() {
    local item=$1 name=$2
    if [[ -e "$item" ]]; then /bin/cp -p "$item" "$backup/$name"; fi
}
restore_one() {
    local item=$1 name=$2
    if [[ -f "$backup/$name" ]]; then
        /bin/cp -p "$backup/$name" "$item"
    else
        /bin/rm -f "$item"
    fi
}
finish() {
    local result=$?
    trap - EXIT INT TERM
    if (( transaction )); then
        set +e
        stop_loaded
        restore_one "$config" client.toml
        restore_one "$agent" launch-agent.plist
        restore_one "$binary" umbra
        restore_one "$controller" control.zsh
        restore_one "$shortcut" shortcut.command
        if (( previous_loaded )) && [[ -f "$agent" ]]; then
            /bin/launchctl bootstrap "$domain" "$agent" >/dev/null 2>&1
        fi
        if (( previous_disabled )); then
            /bin/launchctl disable "$service" >/dev/null 2>&1
        fi
        print -u2 '安装未完成，已恢复原配置和服务文件。'
        print -u2 -- "备份位置：$backup"
    fi
    pause_if_terminal
    exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$OSTYPE" == darwin* ]] || fail '此安装包仅适用于 macOS。'
(( EUID != 0 )) || fail '请直接双击脚本，以当前用户安装，不要使用 sudo。'
local_version=$(/usr/bin/sw_vers -productVersion)
(( ${local_version%%.*} >= 11 )) || fail '此安装包需要 macOS 11 或更新版本。'
/bin/launchctl print "$domain" >/dev/null 2>&1 || fail '请登录 Mac 桌面后，以该用户运行脚本。'

make_agent() {
    local staged="$agent.stage.$$"
    print -r -- '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict/></plist>' > "$staged"
    /usr/bin/plutil -insert Label -string "$label" "$staged"
    /usr/bin/plutil -insert ProgramArguments -json '["","client","--config",""]' "$staged"
    /usr/bin/plutil -replace ProgramArguments.0 -string "$binary" "$staged"
    /usr/bin/plutil -replace ProgramArguments.3 -string "$config" "$staged"
    /usr/bin/plutil -insert RunAtLoad -bool true "$staged"
    /usr/bin/plutil -insert KeepAlive -bool true "$staged"
    /usr/bin/plutil -insert ThrottleInterval -integer 10 "$staged"
    /usr/bin/plutil -insert ProcessType -string Background "$staged"
    /usr/bin/plutil -insert Umask -integer 63 "$staged"
    /usr/bin/plutil -insert StandardOutPath -string "$logs/client.out.log" "$staged"
    /usr/bin/plutil -insert StandardErrorPath -string "$logs/client.err.log" "$staged"
    /bin/chmod 600 "$staged"
    /bin/mv -f "$staged" "$agent"
}
check_port() {
    local check_config=$1 listener own_pid
    # The exported profile's SOCKS endpoint must stay compatible with Clash.
    local listen
    listen=$(/usr/bin/awk -F '"' '/^[[:space:]]*socks_listen[[:space:]]*=/ { print $2; exit }' "$check_config")
    [[ "$listen" == '127.0.0.1:1080' ]] || fail '配套配置需要 socks_listen = "127.0.0.1:1080"。'
    own_pid=$(service_pid || true)
    for listener in ${(f)"$(/usr/sbin/lsof -nP -t -iTCP:1080 -sTCP:LISTEN 2>/dev/null || true)"}; do
        [[ -z "$listener" ]] && continue
        [[ -n "$own_pid" && "$listener" == "$own_pid" ]] ||
            fail '1080 端口已被其他程序占用，请先停止该程序后再安装或启动。'
    done
}
ready() {
    local pid
    for attempt in {1..80}; do
        pid=$(service_pid || true)
        if [[ -n "$pid" ]] && /usr/sbin/lsof -nP -a -p "$pid" -iTCP:1080 -sTCP:LISTEN >/dev/null 2>&1; then
            return 0
        fi
        /bin/sleep 0.25
    done
    fail "客户端未能启动。可查看日志：$logs/client.err.log"
}
start_client() {
    check_owner
    [[ -f "$config" && -x "$binary" ]] || fail '安装文件不完整，请重新运行“安装.command”。'
    check_port "$config"
    /bin/mkdir -p "$logs"
    /bin/launchctl enable "$service"
    if ! loaded; then /bin/launchctl bootstrap "$domain" "$agent"; fi
    /bin/launchctl kickstart "$service"
    ready
    print 'Umbra 已启动：127.0.0.1:1080（TCP Vision + QUIC UDP）。'
}
install_client() {
    [[ -f "$bundle/配置/Umbra-client.toml" && -f "$bundle/程序/umbra" ]] ||
        fail '文件不完整。请先解压整个 ZIP，再运行解压目录中的“安装.command”。'
    [[ -f "$bundle/程序/control.zsh" ]] || fail '缺少控制脚本，请重新解压完整安装包。'
    check_port "$bundle/配置/Umbra-client.toml"
    if loaded; then
        [[ -f "$agent" ]] || fail '当前已有同名服务，但找不到可备份的服务文件，请先处理原服务。'
        previous_loaded=1
    fi
    if /bin/launchctl print-disabled "$domain" | /usr/bin/grep -Eq '"com\.umbra\.client"[[:space:]]*=>[[:space:]]*true'; then
        previous_disabled=1
    fi
    print '正在安装 Umbra 1.0.0-alpha……'
    /bin/mkdir -p "$support/backups" "$logs" "${agent:h}" "$binary_dir" "${shortcut:h}"
    backup=$(/usr/bin/mktemp -d "$support/backups/migration-$(/bin/date +%Y%m%d-%H%M%S)-XXXXXX")
    backup_one "$config" client.toml
    backup_one "$agent" launch-agent.plist
    backup_one "$binary" umbra
    backup_one "$controller" control.zsh
    backup_one "$shortcut" shortcut.command
    transaction=1
    stop_loaded
    /bin/cp -X "$bundle/程序/umbra" "$binary.stage.$$"
    /bin/chmod 700 "$binary.stage.$$"
    /bin/mv -f "$binary.stage.$$" "$binary"
    /bin/cp "$bundle/配置/Umbra-client.toml" "$config.stage.$$"
    /bin/chmod 600 "$config.stage.$$"
    /bin/mv -f "$config.stage.$$" "$config"
    /bin/cp -X "$bundle/程序/control.zsh" "$controller"
    /bin/chmod 700 "$controller"
    cat > "$shortcut" <<'SHORTCUT'
#!/bin/zsh
exec /bin/zsh "$HOME/Library/Application Support/Umbra/control.zsh" menu
SHORTCUT
    /bin/chmod 700 "$shortcut"
    make_agent
    /bin/launchctl enable "$service"
    /bin/launchctl bootstrap "$domain" "$agent"
    ready
    transaction=0
    print '安装完成，客户端已在后台运行，并已设置登录自动启动。'
    print '接下来在 Clash 中手动导入“配置”目录中的 YAML 文件。'
    print -- "控制入口：$shortcut"
    print -- "原文件备份：$backup"
}
show_status() {
    if loaded; then
        local pid
        pid=$(service_pid || true)
        if [[ -n "$pid" ]]; then print -- "Umbra 正在运行（PID $pid）。";
        else print '服务已加载，进程暂未运行。'; fi
    else
        print 'Umbra 已停止，或尚未安装。'
    fi
    print -- "客户端配置：$config"
    print -- "日志目录：$logs"
}
uninstall_client() {
    check_owner
    stop_loaded
    /bin/rm -f "$agent" "$binary" "$shortcut"
    /bin/rmdir "$binary_dir" 2>/dev/null || true
    print 'Umbra 服务和程序已卸载。配置、日志和历史备份已保留。'
}
action=${1:-menu}
if [[ "$action" == menu ]]; then
    print 'Umbra 客户端：1 启动　2 停止　3 状态　4 卸载　其他键退出'
    read -r '?请选择：' selection
    case "$selection" in
        1) action=start ;; 2) action=stop ;; 3) action=status ;; 4) action=uninstall ;;
        *) exit 0 ;;
    esac
fi
case "$action" in
    install) install_client ;;
    start) start_client ;;
    stop) check_owner; stop_loaded; print 'Umbra 已停止，本次登录不会自动重启。下次登录仍会自动启动。' ;;
    status) show_status ;;
    uninstall) uninstall_client ;;
    *) fail '未知操作。' ;;
esac
