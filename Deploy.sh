#!/usr/bin/env bash
#
# deploy.sh — Installeert de Subdomain Scanner als systemd-service
#
# Gebruik:
#   sudo ./deploy.sh install    Installeert/update de service (idempotent)
#   sudo ./deploy.sh start      Start de service
#   sudo ./deploy.sh stop       Stopt de service
#   sudo ./deploy.sh restart    Herstart de service
#   sudo ./deploy.sh status     Toont de status
#   sudo ./deploy.sh logs       Volgt de live logs (journalctl -f)
#   sudo ./deploy.sh uninstall  Verwijdert de service (laat bestanden staan)
#
set -euo pipefail

# ---------- Configuratie ----------
APP_NAME="subscanner"
SERVICE_NAME="subscanner.service"
APP_PORT="5065"

# Installatiemap: standaard /opt/subscanner, override met INSTALL_DIR=... ./deploy.sh install
INSTALL_DIR="${INSTALL_DIR:-/opt/${APP_NAME}}"

# Gebruiker waaronder de service draait. Standaard: een dedicated systeemgebruiker
# ipv root, uit veiligheidsoverwegingen. Override met SERVICE_USER=jouwuser.
SERVICE_USER="${SERVICE_USER:-subscanner}"
SERVICE_GROUP="${SERVICE_GROUP:-${SERVICE_USER}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

# ---------- Helpers ----------
log()  { echo -e "\033[1;32m[deploy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[deploy]\033[0m $*"; }
err()  { echo -e "\033[1;31m[deploy]\033[0m $*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Dit commando moet als root draaien (gebruik sudo)."
        exit 1
    fi
}

# ---------- Subcommando's ----------

check_deps() {
    local missing=()
    for bin in python3 rsync systemctl; do
        command -v "${bin}" &>/dev/null || missing+=("${bin}")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Ontbrekende vereisten: ${missing[*]}"
        err "Installeer deze eerst (bv. apt install python3 rsync)."
        exit 1
    fi
}

cmd_install() {
    require_root
    check_deps
    log "Installeren van ${APP_NAME} naar ${INSTALL_DIR}..."

    # 1. Systeemgebruiker aanmaken (indien nodig), zonder login-shell/home
    if ! id "${SERVICE_USER}" &>/dev/null; then
        log "Systeemgebruiker '${SERVICE_USER}' aanmaken..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    else
        log "Systeemgebruiker '${SERVICE_USER}' bestaat al, sla over."
    fi

    # 2. Bestanden kopiëren
    mkdir -p "${INSTALL_DIR}"
    rsync -a --delete \
        --exclude 'venv' \
        --exclude '__pycache__' \
        --exclude '*.pyc' \
        --exclude '.git' \
        "${SCRIPT_DIR}/" "${INSTALL_DIR}/"

    # 3. Python venv opzetten + dependencies
    if [[ ! -d "${INSTALL_DIR}/venv" ]]; then
        log "Virtualenv aanmaken..."
        python3 -m venv "${INSTALL_DIR}/venv"
    fi
    log "Dependencies installeren..."
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

    # 4. Rechten zetten
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
    chmod -R u+rwX,go+rX,go-w "${INSTALL_DIR}"

    # 5. systemd unit-bestand schrijven
    log "systemd service-bestand schrijven naar ${SERVICE_FILE}..."
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Subdomain Scanner (${APP_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=3

# --- Hardening ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}
# AF_INET nodig voor DNS/HTTP/poortchecks; geen netwerknamespace-restrictie.
CapabilityBoundingSet=
AmbientCapabilities=
# Poort 5065 is unprivileged (>1024), dus geen CAP_NET_BIND_SERVICE nodig.

[Install]
WantedBy=multi-user.target
EOF

    # 6. systemd herladen + enablen
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"

    log "Installatie voltooid."
    log "Start de service met: sudo ./deploy.sh start"
    log "De tool draait dan op poort ${APP_PORT} — http://<server-ip>:${APP_PORT}"
}

cmd_start() {
    require_root
    systemctl start "${SERVICE_NAME}"
    log "Service gestart."
    cmd_status
}

cmd_stop() {
    require_root
    systemctl stop "${SERVICE_NAME}"
    log "Service gestopt."
}

cmd_restart() {
    require_root
    systemctl restart "${SERVICE_NAME}"
    log "Service herstart."
    cmd_status
}

cmd_status() {
    systemctl status "${SERVICE_NAME}" --no-pager || true
    echo ""
    if command -v curl &>/dev/null; then
        log "Health check..."
        curl -s -o /dev/null -w "HTTP status: %{http_code}\n" "http://localhost:${APP_PORT}/api/health" || warn "Kon health endpoint niet bereiken."
    fi
}

cmd_logs() {
    journalctl -u "${SERVICE_NAME}" -f
}

cmd_uninstall() {
    require_root
    warn "Service stoppen en verwijderen (bestanden in ${INSTALL_DIR} blijven staan)..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    log "Service verwijderd. Verwijder handmatig ${INSTALL_DIR} en gebruiker '${SERVICE_USER}' als gewenst:"
    log "  sudo rm -rf ${INSTALL_DIR}"
    log "  sudo userdel ${SERVICE_USER}"
}

usage() {
    cat <<EOF
Gebruik: sudo ./deploy.sh <commando>

Commando's:
  install     Installeer/update de service (kopieert bestanden, zet venv op, maakt systemd unit)
  start       Start de service
  stop        Stop de service
  restart     Herstart de service
  status      Toon status + health check
  logs        Volg live logs (journalctl -f)
  uninstall   Verwijder de systemd service

Omgevingsvariabelen:
  INSTALL_DIR    Installatiemap (default: /opt/${APP_NAME})
  SERVICE_USER   Gebruiker waaronder de service draait (default: ${APP_NAME})

Voorbeeld:
  sudo ./deploy.sh install
  sudo ./deploy.sh start
  sudo ./deploy.sh logs
EOF
}

# ---------- Entry point ----------
case "${1:-}" in
    install)   cmd_install ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    restart)   cmd_restart ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    uninstall) cmd_uninstall ;;
    *)         usage; exit 1 ;;
esac
