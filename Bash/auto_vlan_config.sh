#!/usr/bin/env bash
# =============================================================================
# auto_vlan_config.sh
# Automatically configures Cisco IOS switch ports to a specified VLAN
# using LLDP discovery. Credentials are never stored — SSH ControlMaster
# authenticates once interactively and reuses the socket for all connections.
# =============================================================================

set -euo pipefail

# ── Dependencies ──────────────────────────────────────────────────────────────
REQUIRED_CMDS=(lldpcli ssh ip awk grep sed date)
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" &>/dev/null || { echo "[ERROR] Missing dependency: $cmd"; exit 1; }
done

# ── Log setup ─────────────────────────────────────────────────────────────────
LOG_DIR="${HOME}/.vlan_config_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/vlan_config_$(date +%Y%m%d_%H%M%S).log"

log() {
    local level="$1"; shift
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $*" | tee -a "$LOG_FILE"
}

separator() { echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"; }

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── SSH ControlMaster setup ───────────────────────────────────────────────────
# One interactive login per switch IP. All subsequent commands reuse the socket.
SSH_SOCKET_DIR=$(mktemp -d)
trap 'rm -rf "$SSH_SOCKET_DIR"' EXIT   # clean up sockets on exit

ssh_socket() { echo "${SSH_SOCKET_DIR}/ctl_%h"; }

# Open a persistent SSH connection to a switch (called once per new switch IP)
open_ssh_session() {
    local ip="$1"
    local socket; socket=$(ssh_socket)
    if ! ssh -O check -o ControlPath="$socket" "${SSH_USER}@${ip}" &>/dev/null 2>&1; then
        echo -e "\n${YELLOW}  Opening SSH session to ${BOLD}${ip}${NC}${YELLOW} — enter password when prompted.${NC}"
        ssh \
            -M \
            -o ControlPath="$socket" \
            -o ControlPersist=yes \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=10 \
            "${SSH_USER}@${ip}" "echo __connected__" 2>/dev/null | grep -q "__connected__" \
            && echo -e "${GREEN}  ✔ Session established.${NC}" \
            || { echo -e "${RED}  [ERROR] Could not connect to $ip.${NC}"; return 1; }
    fi
}

# Run commands over the existing ControlMaster socket — no password needed
run_ssh() {
    local ip="$1"; shift
    local socket; socket=$(ssh_socket)
    ssh \
        -o ControlPath="$socket" \
        -o ControlMaster=no \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${SSH_USER}@${ip}" "$@" 2>/dev/null
}

# ── Gather initial inputs ─────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║      Auto VLAN Port Configurator     ║"
echo "  ║           Cisco IOS Edition          ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

while true; do
    read -rp "$(echo -e "${BOLD}Enter target VLAN ID:${NC} ")" VLAN_ID
    [[ "$VLAN_ID" =~ ^[0-9]+$ ]] && (( VLAN_ID >= 1 && VLAN_ID <= 4094 )) && break
    echo -e "${RED}Invalid VLAN. Must be 1–4094.${NC}"
done

echo ""
read -rp "$(echo -e "${BOLD}SSH Username:${NC} ")" SSH_USER

log "INFO" "Session started — VLAN: $VLAN_ID | User: $SSH_USER"
separator

# ── Cisco IOS helpers ─────────────────────────────────────────────────────────
check_vlan_exists() {
    local ip="$1" vlan="$2"
    run_ssh "$ip" "show vlan id $vlan" | grep -qE "^${vlan}\b"
}

check_port_config() {
    local ip="$1" port="$2"
    run_ssh "$ip" "show running-config interface $port"
}

configure_access_port() {
    local ip="$1" port="$2" vlan="$3"
    run_ssh "$ip" \
        "$(printf 'enable\nconfigure terminal\ninterface %s\nswitchport mode access\nswitchport access vlan %s\nend\nwrite memory' "$port" "$vlan")"
}

# ── Wait for a new Ethernet link ─────────────────────────────────────────────
wait_for_link() {
    local prev_iface="${1:-}"
    echo -e "\n${CYAN}Waiting for a new Ethernet connection...${NC}"
    echo -e "${YELLOW}  → Plug into the next port now.${NC}\n"
    while true; do
        local iface
        iface=$(ip -o link show | awk -F': ' '
            /state UP/ && !/LOOPBACK/ && !/^[0-9]+: lo/ {
                gsub(/@.*/, "", $2); print $2; exit
            }')
        if [[ -n "$iface" && "$iface" != "$prev_iface" ]]; then
            echo -e "${GREEN}Link detected on: ${BOLD}$iface${NC}"
            echo "$iface"
            return
        fi
        sleep 2
    done
}

# ── LLDP discovery ────────────────────────────────────────────────────────────
# TODO: Update field parsing once you share the exact lldpcli output format.
#       Current keys are best-guess — will confirm and lock down.
get_lldp_info() {
    local iface="$1"
    log "INFO" "Running LLDP discovery on $iface — waiting up to 60s..."
    local lldp_output="" attempts=0
    while (( attempts < 12 )); do
        sleep 5
        lldp_output=$(lldpcli show neighbors detail ports "$iface" 2>/dev/null || true)
        echo "$lldp_output" | grep -q "PortID" && break
        (( attempts++ ))
        echo -e "  ${YELLOW}LLDP not yet seen on $iface — retry ${attempts}/12${NC}"
    done
    if ! echo "$lldp_output" | grep -q "PortID"; then
        log "WARN" "No LLDP neighbors found on $iface after 60s."
        return 1
    fi
    echo "$lldp_output"
}

parse_lldp() {
    local raw="$1" field="$2"
    echo "$raw" | grep -i "^\s*${field}:" | head -1 | awk -F': ' '{$1=""; print $0}' | sed 's/^ //'
}

# Dedicated parsers matched to confirmed lldpcli output format
parse_switch_name() { parse_lldp "$1" "SysName"; }
parse_switch_ip()   { parse_lldp "$1" "MgmtIP"; }
parse_switch_port() { parse_lldp "$1" "PortID" | awk '{print $NF}'; }  # strips leading "ifname"
parse_current_vlan() {
    echo "$1" | grep -E "^\s*VLAN:" | head -1 | awk '{print $2}' | tr -d ','
}

# ── Record keeping ────────────────────────────────────────────────────────────
record_change() {
    local switch_ip="$1" port="$2" prev_cfg="$3"
    {
        separator
        echo "Timestamp  : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Switch IP  : $switch_ip"
        echo "Port       : $port"
        echo "VLAN set   : $VLAN_ID"
        echo ""
        echo "── Previous config ──"
        echo "$prev_cfg"
        separator
    } >> "$LOG_FILE"
}

# ── Main loop ─────────────────────────────────────────────────────────────────
PORT_COUNT=0
PREV_IFACE=""

echo -e "\n${BOLD}Starting port configuration loop.${NC}"
echo -e "Press ${BOLD}Ctrl+C${NC} to exit when all ports are done.\n"
separator

while true; do

    # 1. Wait for plug-in
    IFACE=$(wait_for_link "$PREV_IFACE")
    PREV_IFACE="$IFACE"
    sleep 3

    # 2. LLDP discovery
    LLDP_RAW=$(get_lldp_info "$IFACE") || {
        echo -e "${RED}[SKIP] No LLDP data — move to next port.${NC}"
        continue
    }

    SWITCH_NAME=$(parse_switch_name "$LLDP_RAW")
    SWITCH_IP=$(parse_switch_ip "$LLDP_RAW")
    SWITCH_PORT=$(parse_switch_port "$LLDP_RAW")
    CURRENT_VLAN=$(parse_current_vlan "$LLDP_RAW")

    if [[ -z "$SWITCH_PORT" || -z "$SWITCH_IP" ]]; then
        log "WARN" "LLDP parse failed (port='$SWITCH_PORT' ip='$SWITCH_IP'). Skipping."
        echo -e "${RED}[SKIP] Could not parse LLDP output. Check lldpd is running on the switch.${NC}"
        continue
    fi

    echo ""
    echo -e "${CYAN}  Switch : ${BOLD}${SWITCH_NAME}${NC}"
    echo -e "${CYAN}  IP     : ${BOLD}${SWITCH_IP}${NC}"
    echo -e "${CYAN}  Port   : ${BOLD}${SWITCH_PORT}${NC}"
    echo -e "${CYAN}  VLAN   : ${BOLD}${CURRENT_VLAN:-unknown}${NC} → ${BOLD}${VLAN_ID}${NC}"
    echo ""
    log "INFO" "LLDP → $SWITCH_NAME ($SWITCH_IP) port $SWITCH_PORT"

    # 3. Open SSH session if not already connected to this switch
    open_ssh_session "$SWITCH_IP" || { separator; continue; }

    # 4. Verify VLAN exists
    echo -e "  Checking VLAN ${BOLD}${VLAN_ID}${NC} exists on switch..."
    if ! check_vlan_exists "$SWITCH_IP" "$VLAN_ID"; then
        echo -e "${RED}  [STOP] VLAN $VLAN_ID does not exist on $SWITCH_NAME. Skipping port.${NC}"
        log "WARN" "VLAN $VLAN_ID not found on $SWITCH_IP — skipping $SWITCH_PORT"
        separator; continue
    fi
    echo -e "${GREEN}  ✔ VLAN $VLAN_ID exists.${NC}"

    # 5. Pull current port config and run safety checks
    echo -e "  Checking current config on ${BOLD}${SWITCH_PORT}${NC}..."
    PREV_CFG=$(check_port_config "$SWITCH_IP" "$SWITCH_PORT")

    if echo "$PREV_CFG" | grep -qiE "switchport mode trunk"; then
        echo -e "${RED}  [STOP] $SWITCH_PORT is a TRUNK port. Skipping.${NC}"
        log "WARN" "$SWITCH_PORT on $SWITCH_IP is a trunk — not modifying."
        separator; continue
    fi

    if echo "$PREV_CFG" | grep -qiE "channel-group|port-channel"; then
        echo -e "${RED}  [STOP] $SWITCH_PORT is part of a Port-Channel. Skipping.${NC}"
        log "WARN" "$SWITCH_PORT on $SWITCH_IP is in a port-channel — not modifying."
        separator; continue
    fi

    # 802.1x / MAB check — any combination of these lines requires manual cleanup
    DOT1X_LINES=$(echo "$PREV_CFG" | grep -iE "authentication host-mode|authentication port-control|^[[:space:]]*mab$" || true)
    if [[ -n "$DOT1X_LINES" ]]; then
        echo -e "${RED}  [STOP] $SWITCH_PORT has 802.1x/MAB config present:${NC}"
        echo "$DOT1X_LINES" | while IFS= read -r line; do
            echo -e "${RED}         $line${NC}"
        done
        echo -e "${YELLOW}         Remove 802.1x config manually before configuring this port.${NC}"
        log "WARN" "$SWITCH_PORT on $SWITCH_IP has 802.1x/MAB config — not modifying. Lines: $(echo "$DOT1X_LINES" | tr '\n' '|')"
        separator; continue
    fi

    echo -e "${GREEN}  ✔ Port checks passed.${NC}"

    # 6. Apply the VLAN
    echo -e "  Configuring VLAN ${BOLD}${VLAN_ID}${NC} on ${BOLD}${SWITCH_PORT}${NC}..."
    configure_access_port "$SWITCH_IP" "$SWITCH_PORT" "$VLAN_ID"

    # 7. Log the change
    record_change "$SWITCH_IP" "$SWITCH_PORT" "$PREV_CFG"

    (( PORT_COUNT++ ))
    echo -e "${GREEN}  ✔ Done! ${BOLD}${SWITCH_PORT}${NC}${GREEN} → VLAN ${BOLD}${VLAN_ID}${NC}${GREEN} (${PORT_COUNT} ports configured this session)${NC}"
    separator
    echo -e "${YELLOW}  Unplug and move to the next port...${NC}\n"

done
