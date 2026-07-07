#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

LABEL="${UMBRA_LAUNCHD_LABEL:-com.umbra.client}"
BIN_PATH="${UMBRA_BIN:-${REPO_ROOT}/target/release/umbra}"
SOCKS_LISTEN="${UMBRA_SOCKS_LISTEN:-127.0.0.1:1080}"
NETWORK_SERVICE="${UMBRA_NETWORK_SERVICE:-Wi-Fi}"
REMOTE_SSH="${UMBRA_CLIENT_INFO_SSH:-root@104.105.128.62}"
REMOTE_INFO_PATH="${UMBRA_CLIENT_INFO_PATH:-/root/umbra-client-info.env}"

APP_DIR="${UMBRA_APP_DIR:-${HOME}/Library/Application Support/Umbra}"
LOG_DIR="${UMBRA_LOG_DIR:-${HOME}/Library/Logs/Umbra}"
LAUNCH_AGENTS_DIR="${HOME}/Library/LaunchAgents"
CONFIG_FILE="${UMBRA_CONFIG_FILE:-${APP_DIR}/client.toml}"
ENV_FILE="${APP_DIR}/client-info.env"
PLIST_FILE="${LAUNCH_AGENTS_DIR}/${LABEL}.plist"
OUT_LOG="${LOG_DIR}/client.out.log"
ERR_LOG="${LOG_DIR}/client.err.log"

COMMAND="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

PROXY_ACTION="unchanged"
BUILD_RELEASE="false"
FETCH_REMOTE="true"

usage() {
  cat <<EOF
Usage:
  scripts/umbra-local.sh start [--proxy] [--build] [--no-fetch]
  scripts/umbra-local.sh stop [--no-proxy]
  scripts/umbra-local.sh reload [--proxy|--no-proxy] [--build] [--no-fetch]
  scripts/umbra-local.sh status
  scripts/umbra-local.sh doctor
  scripts/umbra-local.sh proxy-on
  scripts/umbra-local.sh proxy-off
  scripts/umbra-local.sh logs

Options:
  --proxy                 Enable macOS SOCKS proxy after start/reload.
  --no-proxy              Disable macOS SOCKS proxy after stop/reload.
  --build                 Build target/release/umbra before start/reload.
  --no-fetch              Reuse the existing local client.toml.
  --socks HOST:PORT       Override SOCKS listener. Default: ${SOCKS_LISTEN}
  --service NAME          macOS network service. Default: ${NETWORK_SERVICE}
  --remote-ssh USER@HOST  SSH source for client-info env. Default: ${REMOTE_SSH}
  --remote-info PATH      Remote client-info env path. Default: ${REMOTE_INFO_PATH}
  --bin PATH              Umbra binary path. Default: ${BIN_PATH}

Environment overrides:
  UMBRA_BIN, UMBRA_SOCKS_LISTEN, UMBRA_NETWORK_SERVICE,
  UMBRA_CLIENT_INFO_SSH, UMBRA_CLIENT_INFO_PATH, UMBRA_APP_DIR,
  UMBRA_CONFIG_FILE, UMBRA_LOG_DIR, UMBRA_LAUNCHD_LABEL.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

info() {
  echo "umbra-local: $*"
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "this script currently supports macOS launchd/networksetup only"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proxy)
        PROXY_ACTION="enable"
        shift
        ;;
      --no-proxy)
        PROXY_ACTION="disable"
        shift
        ;;
      --build)
        BUILD_RELEASE="true"
        shift
        ;;
      --no-fetch)
        FETCH_REMOTE="false"
        shift
        ;;
      --socks)
        [[ $# -ge 2 ]] || die "--socks requires HOST:PORT"
        SOCKS_LISTEN="$2"
        shift 2
        ;;
      --service)
        [[ $# -ge 2 ]] || die "--service requires a network service name"
        NETWORK_SERVICE="$2"
        shift 2
        ;;
      --remote-ssh)
        [[ $# -ge 2 ]] || die "--remote-ssh requires USER@HOST"
        REMOTE_SSH="$2"
        shift 2
        ;;
      --remote-info)
        [[ $# -ge 2 ]] || die "--remote-info requires a path"
        REMOTE_INFO_PATH="$2"
        shift 2
        ;;
      --bin)
        [[ $# -ge 2 ]] || die "--bin requires a path"
        BIN_PATH="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

launchctl_domain() {
  printf 'gui/%s' "$(id -u)"
}

launchctl_service() {
  printf '%s/%s' "$(launchctl_domain)" "${LABEL}"
}

socks_host() {
  printf '%s' "${SOCKS_LISTEN%:*}"
}

socks_port() {
  printf '%s' "${SOCKS_LISTEN##*:}"
}

plist_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "${value}"
}

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "${value}"
}

ensure_dirs() {
  mkdir -p "${APP_DIR}" "${LOG_DIR}" "${LAUNCH_AGENTS_DIR}"
  chmod 700 "${APP_DIR}"
}

build_release() {
  info "building release binary"
  (
    cd "${REPO_ROOT}"
    cargo build --release -p umbra
  )
}

ensure_binary() {
  if [[ "${BUILD_RELEASE}" == "true" || ! -x "${BIN_PATH}" ]]; then
    build_release
  fi
  [[ -x "${BIN_PATH}" ]] || die "missing executable: ${BIN_PATH}; rerun with --build"
}

fetch_remote_info() {
  ensure_dirs
  info "fetching client info from ${REMOTE_SSH}:${REMOTE_INFO_PATH}"
  ssh -o BatchMode=yes "${REMOTE_SSH}" "cat '${REMOTE_INFO_PATH}'" > "${ENV_FILE}.tmp"
  chmod 600 "${ENV_FILE}.tmp"
  mv "${ENV_FILE}.tmp" "${ENV_FILE}"
}

require_env_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "missing ${name} in ${ENV_FILE}"
}

write_client_config() {
  [[ -f "${ENV_FILE}" ]] || die "missing ${ENV_FILE}; run start without --no-fetch first"

  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  require_env_value server
  require_env_value transport
  require_env_value public_key
  require_env_value short_id
  require_env_value server_name
  require_env_value fingerprint
  require_env_value mldsa_verify
  require_env_value spider_path
  require_env_value mux
  require_env_value padding_scheme
  require_env_value tcp_evasion

  cat > "${CONFIG_FILE}.tmp" <<EOF
server = "$(toml_escape "${server}")"
transport = "$(toml_escape "${transport}")"
public_key = "$(toml_escape "${public_key}")"
short_id = "$(toml_escape "${short_id}")"
server_name = "$(toml_escape "${server_name}")"
fingerprint = "$(toml_escape "${fingerprint}")"
mldsa_verify = "$(toml_escape "${mldsa_verify}")"
spider_path = "$(toml_escape "${spider_path}")"
socks_listen = "$(toml_escape "${SOCKS_LISTEN}")"
mux = ${mux}
padding_scheme = "$(toml_escape "${padding_scheme}")"
tcp_evasion = "$(toml_escape "${tcp_evasion}")"
EOF
  chmod 600 "${CONFIG_FILE}.tmp"
  mv "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
  info "wrote ${CONFIG_FILE}"
}

write_plist() {
  cat > "${PLIST_FILE}.tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$(plist_escape "${LABEL}")</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(plist_escape "${BIN_PATH}")</string>
    <string>client</string>
    <string>--config</string>
    <string>$(plist_escape "${CONFIG_FILE}")</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$(plist_escape "${REPO_ROOT}")</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$(plist_escape "${OUT_LOG}")</string>
  <key>StandardErrorPath</key>
  <string>$(plist_escape "${ERR_LOG}")</string>
</dict>
</plist>
EOF
  mv "${PLIST_FILE}.tmp" "${PLIST_FILE}"
}

service_loaded() {
  launchctl print "$(launchctl_service)" >/dev/null 2>&1
}

stop_service() {
  if service_loaded || [[ -f "${PLIST_FILE}" ]]; then
    launchctl bootout "$(launchctl_domain)" "${PLIST_FILE}" >/dev/null 2>&1 || true
  fi
}

wait_for_listener() {
  local port
  port="$(socks_port)"
  for _ in $(seq 1 80); do
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN | grep -q "${BIN_PATH##*/}"; then
      return 0
    fi
    sleep 0.1
  done

  echo "Umbra client did not start listening on ${SOCKS_LISTEN}" >&2
  print_logs
  return 1
}

start_service() {
  require_macos
  ensure_dirs
  ensure_binary
  if [[ "${FETCH_REMOTE}" == "true" ]]; then
    fetch_remote_info
    write_client_config
  else
    [[ -f "${CONFIG_FILE}" ]] || die "missing ${CONFIG_FILE}; cannot use --no-fetch"
  fi
  write_plist
  stop_service
  info "starting LaunchAgent ${LABEL}"
  launchctl bootstrap "$(launchctl_domain)" "${PLIST_FILE}"
  wait_for_listener
}

network_service_exists() {
  networksetup -listallnetworkservices | tail -n +2 | grep -Fx -- "${NETWORK_SERVICE}" >/dev/null
}

enable_proxy() {
  require_macos
  network_service_exists || die "network service not found: ${NETWORK_SERVICE}"
  info "enabling SOCKS proxy on ${NETWORK_SERVICE}: ${SOCKS_LISTEN}"
  networksetup -setsocksfirewallproxy "${NETWORK_SERVICE}" "$(socks_host)" "$(socks_port)"
  networksetup -setsocksfirewallproxystate "${NETWORK_SERVICE}" on
}

disable_proxy() {
  require_macos
  network_service_exists || die "network service not found: ${NETWORK_SERVICE}"
  info "disabling SOCKS proxy on ${NETWORK_SERVICE}"
  networksetup -setsocksfirewallproxystate "${NETWORK_SERVICE}" off
}

apply_proxy_action() {
  case "${PROXY_ACTION}" in
    enable) enable_proxy ;;
    disable) disable_proxy ;;
    unchanged) ;;
    *) die "invalid proxy action: ${PROXY_ACTION}" ;;
  esac
}

print_logs() {
  echo "== ${OUT_LOG} =="
  tail -n 80 "${OUT_LOG}" 2>/dev/null || true
  echo "== ${ERR_LOG} =="
  tail -n 80 "${ERR_LOG}" 2>/dev/null || true
}

print_status() {
  require_macos
  echo "label: ${LABEL}"
  echo "binary: ${BIN_PATH}"
  echo "config: ${CONFIG_FILE}"
  echo "socks: ${SOCKS_LISTEN}"
  echo "plist: ${PLIST_FILE}"
  if service_loaded; then
    echo "launchd: loaded"
  else
    echo "launchd: not loaded"
  fi
  lsof -nP -iTCP:"$(socks_port)" -sTCP:LISTEN || true
  if network_service_exists; then
    networksetup -getsocksfirewallproxy "${NETWORK_SERVICE}" || true
  else
    echo "network service not found: ${NETWORK_SERVICE}"
  fi
  print_server_route_diagnostics
}

configured_server_host() {
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    return 1
  fi
  awk -F '"' '/^[[:space:]]*server[[:space:]]*=/ { print $2; exit }' "${CONFIG_FILE}" \
    | sed -E 's/^\[?([^]]+)\]?:[0-9]+$/\1/'
}

print_server_route_diagnostics() {
  local host
  host="$(configured_server_host || true)"
  if [[ -z "${host}" ]]; then
    return 0
  fi

  echo "route to server (${host}):"
  local route
  route="$(route -n get "${host}" 2>/dev/null || true)"
  if [[ -z "${route}" ]]; then
    echo "  unavailable"
    return 0
  fi
  echo "${route}" | awk '
    /gateway:/ { print "  gateway: " $2 }
    /interface:/ { print "  interface: " $2 }
  '
  if echo "${route}" | grep -Eq 'interface: utun|gateway: 198\.18\.'; then
    echo "  warning: server traffic appears to be routed through a TUN/proxy."
    echo "  add the Umbra server IP to your existing proxy DIRECT/bypass rules before using Umbra as the proxy."
  fi
}

parse_args "$@"

case "${COMMAND}" in
  start)
    start_service
    apply_proxy_action
    print_status
    ;;
  stop)
    require_macos
    stop_service
    apply_proxy_action
    print_status
    ;;
  reload|restart)
    require_macos
    stop_service
    start_service
    apply_proxy_action
    print_status
    ;;
  status)
    print_status
    ;;
  doctor)
    print_status
    ;;
  proxy-on)
    PROXY_ACTION="enable"
    apply_proxy_action
    ;;
  proxy-off)
    PROXY_ACTION="disable"
    apply_proxy_action
    ;;
  logs)
    print_logs
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    die "unknown command: ${COMMAND}"
    ;;
esac
