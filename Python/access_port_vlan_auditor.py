#!/usr/bin/env python3
"""
Cisco Catalyst Access Port Audit
=================================
- Preflight credential check against all switches
- Finds all access ports in a target VLAN (not trunks)
- Reports interface up/down status
- Collects MAC addresses on up ports
- Resolves MACs to IPs via core switch ARP (sh ip arp [vrf <name>] vlan <N>)
- OUI lookup (local IEEE file preferred, falls back to online API with dedup cache)
- Outputs CSV: switch, port, vlan, status, mac, ip, oui

OUI local file setup (recommended — run once, re-run periodically to refresh):
    curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt

Place oui.txt in the same directory as this script. If not found, the script
falls back to api.macvendors.com — repeated OUIs are cached in memory so each
unique OUI prefix is only looked up once per run.

Usage:
    python3 access_port_vlan_auditor.py switches.txt
"""

import sys
import re
import csv
import time
import getpass
import argparse
import ipaddress
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Global print lock — ensures each switch's output block prints atomically
_print_lock = threading.Lock()

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    print("[ERROR] netmiko is not installed. Run: pip install netmiko --break-system-packages")
    sys.exit(1)

# ---------------------------------------------------------------------------
# OUI handling
# ---------------------------------------------------------------------------

OUI_CACHE: dict[str, str] = {}
OUI_FILE = Path("oui.txt")          # local IEEE OUI flat file if you have it
OUI_URL  = "https://www.ieee.org/netstorage/standards/oui.csv"  # fallback

def _normalise_oui(mac: str) -> str:
    """Return upper-hex 6-char OUI prefix with no delimiters from any MAC format."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    return clean[:6].upper()

def load_local_oui(path: Path) -> bool:
    """Try to load a local IEEE OUI file (oui.txt or oui.csv)."""
    if not path.exists():
        return False
    loaded = 0
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                # IEEE flat file format:  AA-BB-CC   (hex)   Vendor Name
                m = re.match(r"([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)", line)
                if m:
                    oui = m.group(1).replace("-", "").upper()
                    OUI_CACHE[oui] = m.group(2).strip()
                    loaded += 1
                # Also handle CSV format: Registry,Assignment,Organization Name,...
                elif "," in line:
                    parts = line.split(",")
                    if len(parts) >= 3 and re.match(r"[0-9A-Fa-f]{6}", parts[1].strip()):
                        oui = parts[1].strip().upper()
                        OUI_CACHE[oui] = parts[2].strip().strip('"')
                        loaded += 1
    except Exception as e:
        print(f"[WARN] Could not parse local OUI file: {e}")
        return False
    if loaded:
        print(f"[OUI] Loaded {loaded:,} entries from {path}")
        return True
    return False

# Per-session online lookup cache to avoid hammering the API
_online_oui_cache: dict[str, str] = {}

def lookup_oui(mac: str) -> str:
    """Return vendor string for a MAC address, or empty string if unknown."""
    if not mac or mac.lower() in ("", "n/a", "unknown"):
        return ""
    oui = _normalise_oui(mac)
    if oui in OUI_CACHE:
        return OUI_CACHE[oui]
    if oui in _online_oui_cache:
        return _online_oui_cache[oui]
    # Gentle online fallback via macvendors.com (free, no key needed)
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "49ers-net-audit/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            vendor = resp.read().decode().strip()
            _online_oui_cache[oui] = vendor
            time.sleep(0.5)  # be polite to the free API
            return vendor
    except Exception:
        _online_oui_cache[oui] = ""
        return ""

# ---------------------------------------------------------------------------
# Cisco helper parsing
# ---------------------------------------------------------------------------

# Regex for 'show interfaces status' — handles blank/populated Name column
# Groups: (port, status_keyword, vlan_or_trunk)
_INTF_STATUS_RE = re.compile(
    r"^(\S+)\s+"                                                        # port
    r"(?:[\w\-][\w\-. ]*?)?\s*"                                         # optional name
    r"(connected|notconnect\S*|disabled|err-disabled|inactive)\s+"      # status
    r"(trunk|\d+)\s",                                                    # vlan
    re.IGNORECASE,
)

def get_device_conn(host: str, username: str, password: str, enable_secret: str = ""):
    """Return a Netmiko connection dict for a Cisco IOS/IOS-XE device."""
    conn = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
        "session_timeout": 60,
        "fast_cli": False,
    }
    if enable_secret:
        conn["secret"] = enable_secret
    return conn

def parse_vlan_access_ports(show_interfaces_status: str, target_vlan: str) -> tuple[list[str], dict[str, str]]:
    """
    Parse 'show interfaces status' in one pass for a given VLAN.
    Returns:
      ports    – list of port names that are access ports in target_vlan (not trunk)
      statuses – {port: 'up'|'down'} for those ports
    Handles fixed-width output where the Name column may be blank.
    """
    ports: list[str] = []
    statuses: dict[str, str] = {}
    for line in show_interfaces_status.splitlines():
        m = _INTF_STATUS_RE.match(line)
        if not m:
            continue
        port, status_kw, vlan = m.group(1), m.group(2).lower(), m.group(3)
        if vlan.lower() == "trunk" or vlan != target_vlan:
            continue
        if port.lower().startswith("po"):   # skip Port-channels
            continue
        ports.append(port)
        statuses[port] = "up" if "connected" in status_kw else "down"
    return ports, statuses

def parse_mac_address_table(show_mac: str, port: str) -> str:
    """
    Extract first MAC address learned on a given port from
    'show mac address-table interface <port>' output.
    Returns MAC in format aa:bb:cc:dd:ee:ff or empty string.
    """
    for line in show_mac.splitlines():
        # Typical: Vlan  Mac Address        Type    Ports
        #          800   aabb.ccdd.eeff     DYNAMIC GigabitEthernet1/0/5
        m = re.search(r"\b([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b", line, re.IGNORECASE)
        if m:
            cisco_mac = m.group(1)
            # Normalise from Cisco aabb.ccdd.eeff → aa:bb:cc:dd:ee:ff
            raw = cisco_mac.replace(".", "")
            formatted = ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper()
            return formatted
    return ""

def parse_arp_table(show_arp: str) -> dict[str, str]:
    """
    Parse 'sh ip arp vrf Security vlan 800' and return {mac: ip} mapping.
    MAC normalised to upper AA:BB:CC:DD:EE:FF.
    """
    mac_to_ip: dict[str, str] = {}
    for line in show_arp.splitlines():
        # Format: Protocol  Address  Age  Hardware Addr  Type  Interface
        # Internet  10.0.0.1  -   aabb.ccdd.eeff  ARPA  Vlan800
        m = re.match(
            r"\s*Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
            line, re.IGNORECASE
        )
        if m:
            ip = m.group(1)
            raw = m.group(2).replace(".", "")
            mac = ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper()
            mac_to_ip[mac] = ip
    return mac_to_ip

# ---------------------------------------------------------------------------
# Preflight check
# ---------------------------------------------------------------------------

def preflight_check(hosts: list[str], username: str, password: str, enable_secret: str) -> None:
    """
    Validate credentials by trying up to 3 switches from the list.
    Exits immediately on the first successful login.
    Errors out if all attempts fail.
    """
    attempts = min(3, len(hosts))
    print(f"[PREFLIGHT] Validating credentials (trying up to {attempts} switch(es)) ...\n")
    for idx in range(attempts):
        host = hosts[idx]
        print(f"  [{idx+1}/{attempts}] Checking {host} ...", end=" ", flush=True)
        try:
            with ConnectHandler(**get_device_conn(host, username, password, enable_secret)) as conn:
                if enable_secret:
                    conn.enable()
                print("OK")
                print("[PREFLIGHT] Credentials confirmed — proceeding.\n")
                return  # success, carry on
        except NetmikoAuthenticationException:
            print("FAIL (authentication)")
        except NetmikoTimeoutException:
            print("FAIL (timeout/unreachable)")
        except Exception as e:
            print(f"FAIL ({e})")

    print(f"\n[ERROR] Credentials could not be verified against {attempts} switch(es). Aborting.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Per-switch data collection
# ---------------------------------------------------------------------------

def collect_switch_data(
    host: str,
    username: str,
    password: str,
    enable_secret: str,
    target_vlan: str,
) -> list[dict]:
    """
    Connect to a switch, find access ports in target_vlan, get status + MACs.
    Buffers all output and prints it as one atomic block so parallel runs stay readable.
    Returns list of row dicts (mac_to_ip filled in later).
    """
    rows = []
    log: list[str] = []
    skipped_reason = ""

    try:
        with ConnectHandler(**get_device_conn(host, username, password, enable_secret)) as conn:
            if enable_secret:
                conn.enable()

            hostname = host
            prompt = conn.find_prompt()
            m = re.match(r"(.+)[#>]", prompt)
            if m:
                hostname = m.group(1).strip()

            log.append(f"  Pulling interface status ...")
            int_status = conn.send_command("show interfaces status", read_timeout=60)

            access_ports, port_statuses = parse_vlan_access_ports(int_status, target_vlan)
            log.append(f"  Found {len(access_ports)} VLAN {target_vlan} access port(s)")

            for port in access_ports:
                status = port_statuses.get(port, "unknown")
                mac = ""
                if status == "up":
                    mac_out = conn.send_command(
                        f"show mac address-table interface {port}",
                        read_timeout=30,
                    )
                    mac = parse_mac_address_table(mac_out, port)

                rows.append({
                    "switch":    hostname,
                    "port":      port,
                    "vlan":      target_vlan,
                    "status":    status,
                    "mac":       mac,
                    "ip":        "",   # filled in after ARP lookup
                    "oui":       "",   # filled in after OUI lookup
                })

    except NetmikoAuthenticationException:
        skipped_reason = "authentication failed"
        log.append(f"  !! UNREACHABLE — skipped (authentication failed)")
    except NetmikoTimeoutException:
        skipped_reason = "connection timed out"
        log.append(f"  !! UNREACHABLE — skipped (connection timed out)")
    except Exception as e:
        skipped_reason = str(e)
        log.append(f"  !! UNREACHABLE — skipped ({e})")

    # Print the entire block for this switch atomically
    with _print_lock:
        print(f"{hostname}")
        for line in log:
            print(line)
        print()

    return rows, skipped_reason

# ---------------------------------------------------------------------------
# Core switch ARP lookup
# ---------------------------------------------------------------------------

def collect_arp(core_host: str, username: str, password: str, enable_secret: str, target_vlan: str, vrf: str = "") -> dict[str, str]:
    """Run 'sh ip arp [vrf <name>] vlan <N>' on the core switch. Returns {mac: ip}."""
    vrf_clause = f"vrf {vrf} " if vrf else ""
    cmd = f"show ip arp {vrf_clause}vlan {target_vlan}"
    print(f"\n[ARP] Querying core switch {core_host}: {cmd} ...", flush=True)
    try:
        with ConnectHandler(**get_device_conn(core_host, username, password, enable_secret)) as conn:
            if enable_secret:
                conn.enable()
            arp_out = conn.send_command(cmd, read_timeout=60)
            mapping = parse_arp_table(arp_out)
            print(f"[ARP] Got {len(mapping)} ARP entries")
            return mapping
    except Exception as e:
        print(f"[ERROR] ARP collection failed on {core_host}: {e}")
        return {}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cisco VLAN 800 Access Port Audit — 49ers Network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("switch_list", help="Path to text file with one switch IP/hostname per line")
    parser.add_argument("-o", "--output", default="", help="Output CSV filename (default: auto-named with timestamp)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent SSH workers (default: 10, use 1 for sequential)")
    parser.add_argument("--skip-preflight", action="store_true", help="Skip preflight credential checks")
    parser.add_argument("--no-oui", action="store_true", help="Skip OUI lookups (faster)")
    args = parser.parse_args()

    # ---- Read switch list --------------------------------------------------
    switch_file = Path(args.switch_list)
    if not switch_file.exists():
        print(f"[ERROR] Switch list file not found: {switch_file}")
        sys.exit(1)

    switches = [
        line.strip() for line in switch_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not switches:
        print("[ERROR] No switches found in list file.")
        sys.exit(1)

    # ---- VLAN prompt -------------------------------------------------------
    vlan_input = input("Target VLAN number: ").strip()
    if not vlan_input.isdigit():
        print(f"[ERROR] Invalid VLAN: {vlan_input!r}. Must be a number.")
        sys.exit(1)
    target_vlan = vlan_input

    print(f"\n{'='*60}")
    print(f"  Cisco VLAN {target_vlan} Access Port Audit")
    print(f"  Switches: {len(switches)}")
    print(f"{'='*60}\n")

    # ---- Credentials -------------------------------------------------------
    print("Enter switch credentials (used for all devices):")
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password: ")
    enable_pw = getpass.getpass("  Enable secret (press Enter to skip): ")
    print()

    # ---- Core switch for ARP lookup ----------------------------------------
    core_switch = input("Core switch IP or hostname (for ARP lookup): ").strip()
    vrf_input = input("VRF name for ARP lookup (press Enter to skip): ").strip()
    print()

    # ---- Load OUI data -----------------------------------------------------
    if not args.no_oui:
        if not load_local_oui(OUI_FILE):
            print("[OUI] No local oui.txt found — will use online API (rate-limited; may be slow)")
        print()

    # ---- Preflight ---------------------------------------------------------
    if not args.skip_preflight:
        preflight_check(switches, username, password, enable_pw)

    # ---- Per-switch collection ---------------------------------------------
    workers = max(1, args.workers)
    print(f"[COLLECT] Gathering VLAN {target_vlan} data from {len(switches)} switch(es) — {workers} concurrent worker(s) ...\n")

    all_rows: list[dict] = []
    skipped: list[tuple[str, str]] = []   # (host, reason)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                collect_switch_data,
                sw, username, password, enable_pw, target_vlan
            ): sw
            for sw in switches
        }
        for future in as_completed(futures):
            try:
                rows, skip_reason = future.result()
                all_rows.extend(rows)
                if skip_reason:
                    skipped.append((futures[future], skip_reason))
            except Exception as e:
                with _print_lock:
                    print(f"[ERROR] {futures[future]}: {e}\n")

    # ---- ARP lookup on core switch ----------------------------------------
    mac_to_ip = collect_arp(core_switch, username, password, enable_pw, target_vlan, vrf_input)

    # ---- Enrich rows with IP + OUI ----------------------------------------
    print("\n[ENRICH] Resolving MACs → IP and OUI ...", flush=True)
    for row in all_rows:
        mac = row["mac"]
        if mac:
            row["ip"] = mac_to_ip.get(mac, "")
            if not args.no_oui:
                row["oui"] = lookup_oui(mac)

    # ---- Write CSV ---------------------------------------------------------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = args.output or f"vlan{target_vlan}_audit_{timestamp}.csv"

    fieldnames = ["switch", "port", "vlan", "status", "mac", "ip", "oui"]
    with open(out_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)

    # ---- Summary -----------------------------------------------------------
    up_count        = sum(1 for r in all_rows if r["status"] == "up")
    down_count      = sum(1 for r in all_rows if r["status"] == "down")
    mac_count       = sum(1 for r in all_rows if r["mac"])
    ip_count        = sum(1 for r in all_rows if r["ip"])
    reachable_count = len(switches) - len(skipped)

    print(f"\n{'='*60}")
    print(f"  AUDIT COMPLETE")
    print(f"{'='*60}")
    print(f"  Switches in list            : {len(switches)}")
    print(f"  Reachable                   : {reachable_count}")
    print(f"  Unreachable                 : {len(skipped)}")
    if skipped:
        for host, reason in skipped:
            print(f"    !! {host} — {reason}")
    print(f"  Total VLAN {target_vlan} access ports : {len(all_rows)}")
    print(f"  Up                          : {up_count}")
    print(f"  Down                        : {down_count}")
    print(f"  MACs collected              : {mac_count}")
    print(f"  IPs resolved                : {ip_count}")
    print(f"  Output file                 : {out_file}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
