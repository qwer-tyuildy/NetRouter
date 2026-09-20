#!/usr/bin/env bash
# ============================================================
# NetRouter 一键部署脚本
# ------------------------------------------------------------
# 用法：
#   sudo ./setup_netrouter.sh --install                 # 一键安装
#   sudo ./setup_netrouter.sh --uninstall               # 一键卸载（保留配置）
#   sudo ./setup_netrouter.sh --uninstall --purge       # 卸载并删除配置
#   sudo ./setup_netrouter.sh --status                  # 查看状态
#   sudo ./setup_netrouter.sh --restart                 # 重启服务
#   sudo ./setup_netrouter.sh --logs                    # 跟踪日志
#
# 安装参数（环境变量覆盖）：
#   NETROUTER_INSTALL_DIR   安装目录，默认 /opt/netrouter
#   NETROUTER_DIR           配置目录，默认 /etc/netrouter
#   NETROUTER_HOST          监听地址，默认 0.0.0.0
#   NETROUTER_PORT          监听端口，默认 8080
#   NETROUTER_PASSWORD      初始密码，默认随机生成
#   NETROUTER_PYTHON        系统 Python，默认 /usr/bin/python3
#   NETROUTER_PIP_INDEX     pip 索引（仅 venv 回退时使用）
# ------------------------------------------------------------
# 依赖：同目录下的 route.py
# 策略：优先 apt 装 Python 依赖；apt 不全时自动 venv 回退
# ============================================================
set -euo pipefail

APP_NAME="netrouter"
SERVICE_NAME="${APP_NAME}.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

INSTALL_DIR="${NETROUTER_INSTALL_DIR:-/opt/netrouter}"
CONF_DIR="${NETROUTER_DIR:-/etc/netrouter}"
PY_BIN="${NETROUTER_PYTHON:-/usr/bin/python3}"
HOST="${NETROUTER_HOST:-0.0.0.0}"
PORT="${NETROUTER_PORT:-8080}"
INIT_PWD="${NETROUTER_PASSWORD:-}"
PIP_INDEX="${NETROUTER_PIP_INDEX:-}"
ENV_FILE="${CONF_DIR}/netrouter.env"

C_RED='\033[31m'; C_GRN='\033[32m'; C_YEL='\033[33m'
C_CYN='\033[36m'; C_DIM='\033[2m';  C_RST='\033[0m'
info()  { echo -e "${C_CYN}==>${C_RST} $*"; }
ok()    { echo -e "${C_GRN} ✓ ${C_RST} $*"; }
warn()  { echo -e "${C_YEL} ! ${C_RST} $*"; }
err()   { echo -e "${C_RED} ✗ ${C_RST} $*" >&2; }
die()   { err "$*"; exit 1; }

require_root()    { [[ "${EUID}" -eq 0 ]] || die "需要 root，请用 sudo 执行"; }
require_systemd() { command -v systemctl >/dev/null 2>&1 || die "需要 systemd"; }
require_route_py(){ [[ -f "./route.py" ]] || die "未在当前目录找到 route.py"; }

# ---------------- 卸载 ----------------
do_uninstall() {
  local purge="${1:-0}"
  require_root
  info "停止 NetRouter 服务"
  systemctl stop    "${SERVICE_NAME}" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

  info "删除 systemd 单元"
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload
  systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

  if [[ -d "${INSTALL_DIR}" ]]; then
    info "删除安装目录 ${INSTALL_DIR}"
    rm -rf "${INSTALL_DIR}"
  fi

  if [[ "${purge}" -eq 1 ]]; then
    warn "[--purge] 删除配置目录 ${CONF_DIR}"
    rm -rf "${CONF_DIR}"
  else
    ok "保留配置目录 ${CONF_DIR}"
    echo -e "    ${C_DIM}如需彻底删除：sudo rm -rf ${CONF_DIR}${C_RST}"
  fi
  echo; ok "卸载完成"
}

do_status() {
  require_systemd
  if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}"; then
    warn "NetRouter 服务未安装"; return 1
  fi
  systemctl --no-pager status "${SERVICE_NAME}" || true
  echo
  echo -e "${C_DIM}安装目录: ${INSTALL_DIR}${C_RST}"
  echo -e "${C_DIM}配置目录: ${CONF_DIR}${C_RST}"
  echo -e "${C_DIM}开机启动: $(systemctl is-enabled ${SERVICE_NAME} 2>/dev/null || echo 'no')${C_RST}"
}

do_restart() {
  require_root; require_systemd
  info "重启 ${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
  sleep 1
  systemctl --no-pager status "${SERVICE_NAME}" | head -n 12
}

do_logs() { require_systemd; journalctl -u "${SERVICE_NAME}" -f; }

# ---------------- 安装 ----------------
do_install() {
  require_root; require_systemd; require_route_py

  echo
  echo -e "${C_CYN}NetRouter 安装${C_RST}"
  echo -e "  安装目录 : ${INSTALL_DIR}"
  echo -e "  配置目录 : ${CONF_DIR}"
  echo -e "  监听地址 : ${HOST}:${PORT}"
  echo -e "  Python   : ${PY_BIN}"
  echo

  # ---------- 1. 系统依赖 ----------
  info "[1/6] 安装系统依赖"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq

  BASE_PKGS=(
    python3 python3-pip python3-venv
    iproute2 iputils-ping dnsutils
    nftables net-tools
  )
  apt-get install -y -qq "${BASE_PKGS[@]}" >/dev/null
  ok "基础工具就绪"

  info "安装路由器必备 + Python 运行库（缺一不阻塞）"
  OPT_PKGS=(
    hostapd dnsmasq wireguard-tools bridge-utils iw rfkill
    python3-fastapi python3-uvicorn python3-starlette
    python3-yaml python3-psutil
  )
  for p in "${OPT_PKGS[@]}"; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      continue
    fi
    if apt-get install -y -qq "$p" >/dev/null 2>&1; then
      ok "  + $p"
    else
      warn "  - $p 不可用（apt 未提供或安装失败）"
    fi
  done

  # ---------- 2. 创建目录 ----------
  info "[2/6] 创建目录"
  mkdir -p "${INSTALL_DIR}" "${CONF_DIR}"
  chmod 0700 "${CONF_DIR}"
  chmod 0755 "${INSTALL_DIR}"
  ok "目录已创建"

  # ---------- 3. 部署 route.py ----------
  info "[3/6] 部署 route.py"
  install -m 0755 ./route.py "${INSTALL_DIR}/route.py"
  ok "route.py 已部署"

  # ---------- 4. Python 依赖 ----------
  info "[4/6] 检查 Python 依赖"
  local exec_py="${PY_BIN}"
  apt_ok=0

  if "${PY_BIN}" - <<'PYEOF' >/dev/null 2>&1
import fastapi, uvicorn, starlette, yaml, psutil
PYEOF
  then
    apt_ok=1
    ok "系统 Python 依赖齐全，直接使用 ${PY_BIN}"
    "${PY_BIN}" - <<'PYEOF' || true
import fastapi, uvicorn, starlette, yaml, psutil
print(f"    fastapi={fastapi.__version__}  starlette={starlette.__version__}")
print(f"    uvicorn={uvicorn.__version__}  pyyaml={yaml.__version__}  psutil={psutil.__version__}")
PYEOF
  fi

  if [[ "${apt_ok}" -ne 1 ]]; then
    # ---- 回退：venv + pip ----
    warn "系统 Python 缺少部分依赖，回退到 venv"
    local venv_dir="${INSTALL_DIR}/venv"
    info "创建 venv: ${venv_dir}"
    if [[ ! -x "${venv_dir}/bin/python" ]]; then
      "${PY_BIN}" -m venv "${venv_dir}" \
        || die "创建 venv 失败，请先安装 python3-venv"
    fi
    local pip_bin="${venv_dir}/bin/pip"

    info "升级 venv 内 pip / setuptools / wheel"
    "${pip_bin}" install --upgrade pip setuptools wheel \
      --no-cache-dir --retries 3 --timeout 30 \
      || die "pip 自身升级失败，请检查网络"

    local pargs=()
    [[ -n "${PIP_INDEX}" ]] && pargs+=( -i "${PIP_INDEX}" )

    info "安装 fastapi uvicorn pyyaml psutil（仅 wheel 优先）"
    if ! "${pip_bin}" install "${pargs[@]}" \
            --only-binary=:all: --prefer-binary \
            --retries 3 --timeout 30 \
            fastapi uvicorn pyyaml psutil; then
      warn "仅 wheel 安装失败，尝试允许源码构建"
      if ! "${pip_bin}" install "${pargs[@]}" \
              --prefer-binary --retries 3 --timeout 30 \
              fastapi uvicorn pyyaml psutil; then
        die "venv 依赖安装失败，请检查网络或 Python 版本"
      fi
    fi
    exec_py="${venv_dir}/bin/python"
    ok "venv 依赖安装完成：${venv_dir}"
  fi

  # ---------- 5. 环境变量文件 ----------
  info "[5/6] 写入环境变量 ${ENV_FILE}"
  {
    echo "# NetRouter systemd 环境变量"
    echo "# 修改后执行: sudo systemctl restart ${SERVICE_NAME}"
    echo "NETROUTER_HOST=${HOST}"
    echo "NETROUTER_PORT=${PORT}"
    echo "NETROUTER_DIR=${CONF_DIR}"
    if [[ -n "${INIT_PWD}" ]]; then
      echo "NETROUTER_PASSWORD=${INIT_PWD}"
    fi
  } > "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  ok "环境变量已写入"

  # ---------- 6. systemd 服务 ----------
  info "[6/6] 注册 systemd 服务"
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=NetRouter - Ubuntu 一体化路由器软件
Documentation=file://${INSTALL_DIR}/route.py
After=network-online.target
Wants=network-online.target
Before=nftables.service
Conflicts=shutdown.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=${exec_py} ${INSTALL_DIR}/route.py
Restart=on-failure
RestartSec=5s
KillSignal=SIGINT
TimeoutStopSec=15
ProtectSystem=off
ProtectHome=off
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${APP_NAME}

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "${SERVICE_FILE}"
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null
  ok "服务已注册并设为开机启动"

  echo
  ok "安装完成"
  echo

  if [[ -f "${CONF_DIR}/password.json" ]]; then
    echo -e "  ${C_YEL}检测到已有密码文件，沿用旧密码${C_RST}"
  elif [[ -n "${INIT_PWD}" ]]; then
    echo -e "  初始密码: ${C_GRN}${INIT_PWD}${C_RST}"
  else
    echo -e "  ${C_YEL}初始密码将在首次启动时随机生成${C_RST}"
    echo -e "  查看: ${C_DIM}sudo journalctl -u ${SERVICE_NAME} -n 60 --no-pager | sed -n '/初始密码/,+2p'${C_RST}"
  fi
  echo
  echo -e "  ${C_DIM}启动: sudo systemctl start ${SERVICE_NAME}${C_RST}"
  echo -e "  ${C_DIM}状态: sudo systemctl status ${SERVICE_NAME}${C_RST}"
  echo -e "  ${C_DIM}日志: sudo journalctl -u ${SERVICE_NAME} -f${C_RST}"
  echo -e "  ${C_DIM}访问: http://<服务器IP>:${PORT}${C_RST}"
  echo

  if [[ -t 0 ]]; then
    local ans
    read -r -p "是否立即启动 NetRouter 服务？[Y/n] " ans
    ans="${ans:-Y}"
    if [[ "${ans}" =~ ^[Yy]$ ]]; then
      systemctl restart "${SERVICE_NAME}"
      sleep 2
      systemctl --no-pager status "${SERVICE_NAME}" | head -n 15 || true
    fi
  fi
}

# ---------------- 帮助 ----------------
usage() {
  cat <<EOF
NetRouter 一键部署脚本

用法:
  sudo \$0 --install                 一键安装
  sudo \$0 --uninstall               卸载（保留配置）
  sudo \$0 --uninstall --purge       卸载并删除配置
  sudo \$0 --status                  查看状态
  sudo \$0 --restart                 重启服务
  sudo \$0 --logs                    跟踪日志
  sudo \$0 --help                    显示帮助

安装参数（环境变量）:
  NETROUTER_INSTALL_DIR   安装目录，默认 /opt/netrouter
  NETROUTER_DIR           配置目录，默认 /etc/netrouter
  NETROUTER_HOST          监听地址，默认 0.0.0.0
  NETROUTER_PORT          监听端口，默认 8080
  NETROUTER_PASSWORD      初始密码，默认随机生成
  NETROUTER_PYTHON        系统 Python 路径，默认 /usr/bin/python3
  NETROUTER_PIP_INDEX     pip 索引（仅当 apt 不全、回退 venv 时使用）

示例:
  sudo ./setup_netrouter.sh --install
  sudo NETROUTER_PORT=9090 NETROUTER_PASSWORD='StrongPwd123' \\
       ./setup_netrouter.sh --install
  sudo ./setup_netrouter.sh --uninstall --purge
EOF
}

# ---------------- 主流程 ----------------
main() {
  [[ $# -eq 0 ]] && { usage; exit 1; }
  local cmd="" purge=0
  for arg in "$@"; do
    case "${arg}" in
      --install|-i)                       cmd="install" ;;
      --uninstall|--unistall|--remove|-u) cmd="uninstall" ;;
      --purge)                            purge=1 ;;
      --status|-s)                        cmd="status" ;;
      --restart|-r)                       cmd="restart" ;;
      --logs|-l)                          cmd="logs" ;;
      --help|-h)                          usage; exit 0 ;;
      *) die "未知参数: ${arg}（--help 查看用法）" ;;
    esac
  done
  case "${cmd}" in
    install)   do_install ;;
    uninstall) do_uninstall "${purge}" ;;
    status)    do_status ;;
    restart)   do_restart ;;
    logs)      do_logs ;;
    *)         usage; exit 1 ;;
  esac
}
main "$@"