#!/usr/bin/env python3
"""
rogue_switch_hunter.py
==================
Cisco Switch VLAN MAC Audit & Port Security Enforcement Tool

Reads switch IPs from inventory.txt, SSHes in via Netmiko,
checks for ports with multiple MAC addresses on specified VLANs,
then optionally applies port-security max 1 (non-sticky) to offending
or all ports.

All changes are logged with timestamps to audit_<datetime>.log.

Requirements:
    pip install netmiko
"""

import sys
import getpass
import logging
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    print("[ERROR] Netmiko is not installed. Run:  pip install netmiko")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """Configure dual logging: file (all details) + console (info+)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = Path(f"audit_{timestamp}.log")

    logger = logging.getLogger("vlan_audit")
    logger.setLevel(logging.DEBUG)

    # File handler – captures everything including raw CLI commands
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                                       datefmt="%Y-%m-%d %H:%M:%S"))

    # Console handler – info and above only
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info(f"[*] Audit log: {log_file.resolve()}")
    return logger


# ---------------------------------------------------------------------------
# Inventory loader
# ---------------------------------------------------------------------------

def load_inventory(path: str = "inventory.txt") -> list[str]:
    """Return list of switch IPs/hostnames from inventory.txt (one per line)."""
    inv = Path(path)
    if not inv.exists():
        print(f"[ERROR] Inventory file '{path}' not found.")
        sys.exit(1)

    ips = []
    for line in inv.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)

    if not ips:
        print(f"[ERROR] No entries found in '{path}'.")
        sys.exit(1)

    return ips


# ---------------------------------------------------------------------------
# VLAN input
# ---------------------------------------------------------------------------

def prompt_vlans() -> list[str]:
    """
    Ask the user which VLANs to audit.
    Returns a list of VLAN ID strings, or ["ALL"] as a sentinel
    meaning: query each switch dynamically via 'show vlan brief'.
    """
    print("\n" + "="*60)
    print("  VLAN MAC Audit & Port-Security Enforcement")
    print("="*60)
    raw = input("\nEnter VLAN(s) to review (comma-separated, e.g. 10,20,30)\n"
                "or type 'all' to check every active VLAN on each switch: ").strip()

    if raw.lower() == "all":
        print("[*] Mode: ALL VLANs — will query each switch dynamically")
        return ["ALL"]

    vlans = [v.strip() for v in raw.split(",") if v.strip().isdigit()]
    if not vlans:
        print("[ERROR] No valid VLAN IDs entered.")
        sys.exit(1)
    return vlans


def get_vlans_from_switch(conn, logger: logging.Logger) -> list[str]:
    """
    Parse 'show vlan brief' and return a list of active VLAN ID strings.
    Skips reserved/internal VLANs (1002-1005) and VLANs not in active state.
    """
    output = send_command(conn, "show vlan brief", logger)
    vlans = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        vlan_id = parts[0]
        if not vlan_id.isdigit():
            continue
        vlan_num = int(vlan_id)
        # Skip VLAN 1 (default/untagged), reserved VLANs 1002-1005
        if vlan_num == 1 or 1002 <= vlan_num <= 1005:
            continue
        # Must be in 'active' state
        if "active" in line.lower():
            vlans.append(vlan_id)
    logger.info(f"  [*] {conn.host}: found {len(vlans)} active VLANs: {', '.join(vlans)}")
    return vlans


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def connect(ip: str, username: str, password: str, logger: logging.Logger):
    """Return a Netmiko SSH session or None on failure."""
    logger.debug(f"Connecting to {ip}")
    try:
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip,
            username=username,
            password=password,
            timeout=20,
            session_log=None,       # We handle logging ourselves
        )
        conn.enable()
        logger.debug(f"Connected and in enable mode: {ip}")
        return conn
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {ip}")
    except NetmikoTimeoutException:
        logger.error(f"Timeout connecting to {ip}")
    except Exception as exc:
        logger.error(f"Error connecting to {ip}: {exc}")
    return None


def send_command(conn, command: str, logger: logging.Logger) -> str:
    """Send a show command and return output, logging the command."""
    logger.debug(f"[CMD] {conn.host}  >>  {command}")
    output = conn.send_command(command, read_timeout=30)
    logger.debug(f"[OUT] {conn.host}\n{output}\n")
    return output


def send_config(conn, commands: list[str], logger: logging.Logger) -> str:
    """Push config commands, logging each one with timestamp."""
    for cmd in commands:
        logger.info(f"  [CONFIG] {conn.host}  >>  {cmd}")
    logger.debug(f"[CONFIG BLOCK] {conn.host}\n" + "\n".join(commands))
    output = conn.send_config_set(commands, read_timeout=30)
    logger.debug(f"[CONFIG OUT] {conn.host}\n{output}\n")
    return output


# ---------------------------------------------------------------------------
# MAC table parsing
# ---------------------------------------------------------------------------

def get_mac_table(conn, vlans: list[str], logger: logging.Logger) -> dict[str, dict[str, list[str]]]:
    """
    Returns: { vlan_id: { interface: [mac1, mac2, ...] } }
    Queries each VLAN separately so we capture all entries.
    """
    result: dict[str, dict[str, list[str]]] = {}

    for vlan in vlans:
        output = send_command(conn, f"show mac address-table vlan {vlan}", logger)
        iface_macs: dict[str, list[str]] = defaultdict(list)

        for line in output.splitlines():
            # Typical format:
            #   10    aabb.cc00.0101    DYNAMIC     Gi1/0/1
            parts = line.split()
            if len(parts) < 4:
                continue
            # First column should match the VLAN number
            if not parts[0].isdigit() or parts[0] != vlan:
                continue
            mac = parts[1]
            iface = parts[-1]
            # Only include physical access port types.
            # Explicitly excludes: Po (Port-Channel), Tu (Tunnel), Vl (SVI),
            # Lo (Loopback), Ap (AppGigE), CPU, and anything else non-physical.
            if re.match(r"(GigabitEthernet|Gi|FastEthernet|Fa|TenGigabitEthernet|Te|"
                        r"TwentyFiveGigE|Tw|HundredGigE|Hu|FiveGigabitEthernet|Fi)\d",
                        iface, re.IGNORECASE):
                iface_macs[iface].append(mac)

        result[vlan] = dict(iface_macs)

    return result


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

def get_access_ports_for_vlan(conn, vlan: str, logger: logging.Logger) -> list[str]:
    """
    Returns all physical access ports assigned to a given VLAN by parsing
    'show interfaces status'. This catches ports with zero MAC addresses
    that would be invisible to the MAC table alone.
    """
    output = send_command(conn, "show interfaces status", logger)
    ports = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[0]
        # Must be a physical port type
        if not re.match(r"(GigabitEthernet|Gi|FastEthernet|Fa|TenGigabitEthernet|Te|"
                        r"TwentyFiveGigE|Tw|HundredGigE|Hu|FiveGigabitEthernet|Fi)\d",
                        iface, re.IGNORECASE):
            continue
        # show interfaces status columns:
        #   Port      Name    Status      Vlan  Duplex Speed Type
        # VLAN column is index 3 when no name, or further right with a name.
        # Most reliable: find the field that matches our VLAN number.
        # It will appear as a plain integer in the 'Vlan' column.
        # We look for the vlan id somewhere in cols 2-5 to handle name spacing.
        fields = parts[1:]  # everything after the interface name
        for i, field in enumerate(fields[:5]):
            if field == vlan:
                ports.append(iface)
                break
    logger.debug(f"  Access ports for VLAN {vlan} on {conn.host}: {ports}")
    return ports


# ---------------------------------------------------------------------------
# Port-security application
# ---------------------------------------------------------------------------

def is_access_port(conn, interface: str, logger: logging.Logger) -> bool:
    """
    Check show run for the interface and confirm it is explicitly configured
    as an access port. Trunks, routed ports, and anything without
    'switchport mode access' are skipped.
    """
    output = send_command(conn, f"show run interface {interface}", logger)
    if "switchport mode access" in output.lower():
        return True
    logger.warning(f"  [SKIP] {conn.host} / {interface} — 'switchport mode access' not found, "
                   f"skipping (trunk or routed port)")
    return False


def apply_port_security(conn, interface: str, logger: logging.Logger):
    """
    Apply port-security max 1 (non-sticky, violation restrict) to a single interface.
    Verifies the port is explicitly configured as an access port first.
    """
    if not is_access_port(conn, interface, logger):
        return

    cmds = [
        f"interface {interface}",
        "switchport mode access",
        "switchport port-security",
        "switchport port-security maximum 1",
        "switchport port-security violation restrict",
        "end",
    ]
    send_config(conn, cmds, logger)


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

def print_report(switch_ip: str, vlan: str, multi_mac_ports: dict[str, list[str]],
                 single_mac_ports: list[str], zero_mac_ports: list[str]):
    """Pretty-print the findings for one switch / VLAN."""
    print(f"\n{'─'*60}")
    print(f"  Switch : {switch_ip}")
    print(f"  VLAN   : {vlan}")
    print(f"{'─'*60}")

    if multi_mac_ports:
        print(f"  Ports with MULTIPLE MAC addresses ({len(multi_mac_ports)}):")
        for iface, macs in sorted(multi_mac_ports.items()):
            print(f"    {iface:<20}  {len(macs)} MACs: {', '.join(macs)}")
    else:
        print("  No ports with multiple MAC addresses found.")

    print(f"  Ports with single MAC address : {len(single_mac_ports)}")
    print(f"  Ports with zero MAC addresses  : {len(zero_mac_ports)}")


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def main():
    logger = setup_logging()

    vlans = prompt_vlans()
    switches = load_inventory()

    print(f"\n[*] VLANs   : {', '.join(vlans)}")
    print(f"[*] Switches: {len(switches)} loaded from inventory.txt")

    # Prompt credentials – password uses getpass so it never echoes.
    # Re-prompts on auth failure (up to 3 attempts per switch).
    print()
    username = input("SSH Username: ").strip()
    password = getpass.getpass("SSH Password: ")

    # -----------------------------------------------------------------------
    # Phase 1: Collect data from all switches
    # -----------------------------------------------------------------------
    # Structure: { switch_ip: { vlan: { multi: {iface:[macs]}, single: [iface] } } }
    all_data: dict[str, dict] = {}

    logger.info("\n[*] Connecting to switches and collecting MAC tables...")

    for ip in switches:
        conn = None
        current_user = username
        current_pass = password
        for attempt in range(1, 4):
            conn = connect(ip, current_user, current_pass, logger)
            if conn is not None:
                # Sync back in case the user entered different creds
                username = current_user
                password = current_pass
                break
            # Only re-prompt on auth failure (connect() logs the reason)
            # Check the log — if it was a timeout/other error, don't loop
            print(f"\n[!] Authentication failed for {ip} (attempt {attempt}/3)")
            if attempt < 3:
                retry = input("    Re-enter credentials? [y/n]: ").strip().lower()
                if retry != "y":
                    break
                current_user = input("    SSH Username: ").strip()
                current_pass = getpass.getpass("    SSH Password: ")
            else:
                print(f"[!] Max attempts reached for {ip}, skipping.")
                logger.warning(f"Max credential attempts reached for {ip}, skipping.")
        if conn is None:
            continue

        all_data[ip] = {}

        # Resolve VLAN list — either use what the user specified, or
        # query the switch directly if they chose 'all'
        switch_vlans = get_vlans_from_switch(conn, logger) if vlans == ["ALL"] else vlans
        if not switch_vlans:
            logger.warning(f"  [!] No active VLANs found on {ip}, skipping.")
            conn.disconnect()
            continue

        for vlan in switch_vlans:
            mac_table = get_mac_table(conn, [vlan], logger)
            vlan_data = mac_table.get(vlan, {})

            multi = {iface: macs for iface, macs in vlan_data.items() if len(macs) > 1}
            single = [iface for iface, macs in vlan_data.items() if len(macs) == 1]

            # Find ports assigned to this VLAN that had zero MACs in the table
            # (empty ports, recently cleared, devices powered off, etc.)
            all_vlan_ports = get_access_ports_for_vlan(conn, vlan, logger)
            seen_ports = set(multi.keys()) | set(single)
            zero_mac = [p for p in all_vlan_ports if p not in seen_ports]

            all_data[ip][vlan] = {"multi": multi, "single": single, "zero": zero_mac}
            print_report(ip, vlan, multi, single, zero_mac)

        conn.disconnect()
        logger.debug(f"Disconnected from {ip}")

    # -----------------------------------------------------------------------
    # Phase 2: Action menu
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  ACTION MENU")
    print("="*60)
    print("  a) Exit – make no changes")
    print("  b) Lock ZERO & SINGLE-MAC ports only  (port-security max 1, non-sticky)")
    print("  c) Lock ALL ports              (port-security max 1, non-sticky,")
    print("                                  INCLUDING ports with multiple MACs)")
    print()

    choice = input("Choose [a/b/c]: ").strip().lower()

    if choice == "a" or choice not in ("b", "c"):
        logger.info("[*] User selected EXIT. No changes made.")
        print("\n[*] Exiting. No changes applied.")
        return

    # -----------------------------------------------------------------------
    # Phase 3: Apply port-security
    # -----------------------------------------------------------------------
    logger.info(f"[*] User selected option '{choice}'. Beginning configuration...")

    for ip, vlan_results in all_data.items():
        conn = connect(ip, username, password, logger)
        if conn is None:
            logger.error(f"Could not reconnect to {ip} for config push – skipping.")
            continue

        for vlan, data in vlan_results.items():
            targets: list[str] = []

            if choice == "b":
                targets = data["single"] + data["zero"]
                logger.info(f"[{ip}] VLAN {vlan}: locking {len(targets)} port(s) "
                             f"({len(data['single'])} single-MAC + {len(data['zero'])} zero-MAC)")
            elif choice == "c":
                targets = list(data["multi"].keys()) + data["single"] + data["zero"]
                logger.info(f"[{ip}] VLAN {vlan}: locking {len(targets)} total port(s) "
                             f"({len(data['multi'])} multi-MAC + {len(data['single'])} single-MAC "
                             f"+ {len(data['zero'])} zero-MAC)")

            for iface in targets:
                logger.info(f"  -> Applying port-security to {ip} / {iface}")
                apply_port_security(conn, iface, logger)

        # Save config
        logger.info(f"[{ip}] Saving configuration (write memory)")
        send_command(conn, "write memory", logger)
        conn.disconnect()
        logger.debug(f"Disconnected from {ip}")

    logger.info("\n[*] All done. Review the audit log for a full record of changes.")
    print("\n[*] Complete. Check the audit_*.log file for a full timestamped record.")


if __name__ == "__main__":
    main()
