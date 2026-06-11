#!/usr/bin/env python3
"""
PoE Cycler
----------
SSH into Cisco Catalyst switches and cycle PoE power on interfaces that have
locally-learned MAC addresses on the specified VLANs.

Filters to physical interfaces only (Gi, Te, Hu, Fi, Twe) — excludes
PortChannels, SVIs, and any uplink/trunk ports.

Usage:
    python3 poe_cycler.py -f switches.txt
    python3 poe_cycler.py -s 10.40.31.5
    python3 poe_cycler.py -s 10.40.31.5,10.40.31.6
"""

import argparse
from typing import Optional
import csv
import getpass
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

import netmiko
from netmiko import ConnectHandler

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("netmiko").setLevel(logging.CRITICAL)

print_lock = Lock()
DEFAULT_POE_DELAY = 30  # seconds between power inline never → power inline auto

# Physical interface prefixes to act on
PHYSICAL_PREFIXES = (
    "GigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "HundredGigE",
    "FiveGigabitEthernet",
    "Gi",
    "Te",
    "Twe",
    "Hu",
    "Fi",
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_physical(port: str) -> bool:
    """Return True if the port name is a physical interface (not Po, Vlan, etc.)."""
    return any(port.startswith(p) for p in PHYSICAL_PREFIXES)


def expand_interface(short: str) -> str:
    """
    Expand abbreviated interface names to full form for config mode.
    IOS-XE config mode requires full names.
    """
    expansions = {
        "Gi": "GigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Twe": "TwentyFiveGigE",
        "Hu": "HundredGigE",
        "Fi": "FiveGigabitEthernet",
        "Fa": "FastEthernet",
    }
    for abbrev, full in expansions.items():
        if short.startswith(abbrev) and not short.startswith(full):
            return short.replace(abbrev, full, 1)
    return short


def get_hostname(conn) -> str:
    """Pull the hostname from the prompt."""
    try:
        prompt = conn.find_prompt()
        return prompt.strip().rstrip("#>").strip()
    except Exception:
        return "unknown"


def parse_mac_table(output: str, vlans: list[str]) -> dict[str, list[str]]:
    """
    Parse 'show mac address-table vlan <N>' output.
    Returns {interface: [mac, ...]} for locally-learned (DYNAMIC/STATIC) entries
    on physical interfaces only.
    """
    iface_macs: dict[str, list[str]] = {}

    for line in output.splitlines():
        # Match lines like:  261    f8dc.7a82.cba4    DYNAMIC     Gi1/0/3
        m = re.match(
            r'^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+'
            r'(DYNAMIC|STATIC)\s+(\S+)',
            line, re.IGNORECASE
        )
        if not m:
            continue
        vlan_id, mac, _type, port = m.group(1), m.group(2), m.group(3), m.group(4)

        if vlan_id not in vlans:
            continue
        if not is_physical(port):
            continue

        iface_macs.setdefault(port, []).append(mac)

    return iface_macs


def cycle_poe(conn, interfaces: list[str], delay: int) -> list[dict]:
    """
    Power down all interfaces at once, wait delay seconds once, then power all back up.
    Returns a list of result dicts per interface.
    """
    # Down all ports in one config block
    down_cmds = []
    for iface in interfaces:
        down_cmds += [f"interface {expand_interface(iface)}", "power inline never"]
    try:
        conn.send_config_set(down_cmds)
    except Exception as e:
        return [{"interface": iface, "status": "ERROR", "detail": str(e)} for iface in interfaces]

    # Single wait for all devices to power down
    time.sleep(delay)

    # Bring all ports back up
    results = []
    for iface in interfaces:
        full_iface = expand_interface(iface)
        try:
            conn.send_config_set([
                f"interface {full_iface}",
                "power inline auto",
            ])
            results.append({"interface": iface, "status": "CYCLED"})
        except Exception as e:
            results.append({"interface": iface, "status": "ERROR", "detail": str(e)})

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Per-device worker
# ─────────────────────────────────────────────────────────────────────────────

def get_trunk_interfaces(conn) -> set:
    """
    Return a set of interface names currently trunking per 'show interfaces trunk'.
    These are uplinks and must never be PoE cycled.
    """
    output = conn.send_command("show interfaces trunk", read_timeout=30)
    trunks = set()
    for line in output.splitlines():
        # Match lines like: Twe1/1/2    1,52,260-261   ...
        m = re.match(r'^(\S+)\s+\S+\s+\S+\s+\S+', line)
        if m:
            trunks.add(m.group(1))
    return trunks


def process_device(host: str, username: str, password: str,
                   vlans: list[str], delay: int) -> tuple:
    """
    SSH into one switch, find locally-learned physical interfaces for the
    target VLANs, exclude trunk ports, and cycle PoE.
    Returns (host, hostname, results, error).
    """
    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
        "session_log": None,
    }

    try:
        with ConnectHandler(**device) as conn:
            hostname = get_hostname(conn)

            # Pull trunk interfaces first — never touch these
            trunk_ifaces = get_trunk_interfaces(conn)

            all_iface_macs: dict[str, list[str]] = {}

            for vlan in vlans:
                output = conn.send_command(
                    f"show mac address-table vlan {vlan}",
                    read_timeout=30,
                )
                parsed = parse_mac_table(output, vlans)
                for iface, macs in parsed.items():
                    if iface in trunk_ifaces:
                        continue  # skip trunks/uplinks
                    all_iface_macs.setdefault(iface, []).extend(macs)

            if not all_iface_macs:
                return host, hostname, [], None  # nothing to cycle

            interfaces = sorted(all_iface_macs.keys())
            results = cycle_poe(conn, interfaces, delay)
            return host, hostname, results, None

    except netmiko.exceptions.AuthenticationException:
        return host, "unknown", [], "Authentication failed"
    except netmiko.exceptions.NetmikoTimeoutException:
        return host, "unknown", [], "Timeout / unreachable"
    except Exception as e:
        return host, "unknown", [], str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Credential preflight
# ─────────────────────────────────────────────────────────────────────────────

def validate_credentials(hosts: list[str], username: str, password: str) -> bool:
    """Test credentials against up to 5 reachable switches. Exit on auth failure."""
    print("  Verifying credentials (checking up to 5 switches)...")
    tested = 0
    for host in hosts[:5]:
        device = {
            "device_type": "cisco_ios",
            "host": host,
            "username": username,
            "password": password,
            "timeout": 15,
        }
        try:
            with ConnectHandler(**device) as conn:
                conn.find_prompt()
            print(f"  [✓] Credentials OK (verified against {host})\n")
            return True
        except netmiko.exceptions.AuthenticationException:
            print(f"\n  ERROR: Authentication failed on {host}.")
            print("  Please re-run with the correct credentials.\n")
            sys.exit(1)
        except Exception:
            tested += 1
            continue

    print("  WARNING: All preflight targets unreachable — proceeding anyway.\n")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cycle PoE on Cisco Catalyst switches for devices on specified VLANs."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", metavar="FILE",
        help="File with one switch IP per line (e.g. switches.txt)"
    )
    group.add_argument(
        "-s", metavar="HOST[,HOST,...]",
        help="One or more switch IPs, comma-separated"
    )
    args = parser.parse_args()

    print()
    print("  PoE Cycler")
    print("  " + "─" * 50)

    # ── Targets ──────────────────────────────────────────────────────────────
    if args.f:
        try:
            with open(args.f) as fh:
                hosts = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            print(f"\n  ERROR: File not found: {args.f}\n")
            sys.exit(1)
    else:
        hosts = [h.strip() for h in args.s.split(",") if h.strip()]

    if not hosts:
        print("\n  ERROR: No targets found.\n")
        sys.exit(1)

    # ── VLAN prompt ───────────────────────────────────────────────────────────
    vlan_input = input("  VLANs to cycle (comma-separated, e.g. 10,20): ").strip()
    vlans = [v.strip() for v in vlan_input.split(",") if v.strip()]
    if not vlans:
        print("\n  ERROR: No VLANs specified.\n")
        sys.exit(1)

    # ── Credentials ───────────────────────────────────────────────────────────
    print()
    print("  Username: ", end="", flush=True)
    username = input().strip()
    password = getpass.getpass("  Password: ")
    print()

    validate_credentials(hosts, username, password)

    # ── PoE delay ─────────────────────────────────────────────────────────────
    delay_input = input(
        f"  PoE cycle delay (seconds between 'never' → 'auto') [{DEFAULT_POE_DELAY}s default]: "
    ).strip()
    if delay_input:
        try:
            delay = int(delay_input)
        except ValueError:
            print(f"  Invalid value — using default ({DEFAULT_POE_DELAY}s).")
            delay = DEFAULT_POE_DELAY
    else:
        delay = DEFAULT_POE_DELAY

    print()
    print(f"  Targets  : {len(hosts)} switch(es)")
    print(f"  VLANs    : {', '.join(vlans)}")
    print(f"  PoE delay: {delay}s")
    print(f"  Threads  : 10")
    print()

    # ── Run ───────────────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"poe_cycler_{timestamp}.csv"

    all_rows: list[dict] = []
    errors: list[tuple[str, str]] = []
    completed = 0
    total = len(hosts)

    def run_and_report(host: str):
        nonlocal completed
        h, hostname, results, error = process_device(
            host, username, password, vlans, delay
        )
        completed += 1

        with print_lock:
            if error:
                print(f"  [{completed}/{total}] {h}  →  ERROR: {error}")
                errors.append((h, error))
            elif not results:
                print(f"  [{completed}/{total}] {hostname} ({h})  →  No local PoE interfaces found for VLAN(s) {', '.join(vlans)}")
            else:
                cycled = [r for r in results if r["status"] == "CYCLED"]
                erred  = [r for r in results if r["status"] == "ERROR"]
                print(f"  [{completed}/{total}] {hostname} ({h})")
                for r in results:
                    mark = "✓" if r["status"] == "CYCLED" else "✗"
                    print(f"    [{mark}] {r['interface']}")
                all_rows.extend([
                    {"host": h, "hostname": hostname, "interface": r["interface"],
                     "status": r["status"], "detail": r.get("detail", "")}
                    for r in results
                ])

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(run_and_report, h): h for h in hosts}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                with print_lock:
                    print(f"  Thread error: {e}")

    # ── CSV ───────────────────────────────────────────────────────────────────
    print()
    print("  " + "─" * 50)

    with open(csv_path, "w", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=["host", "hostname", "interface", "status", "detail"])
        writer.writeheader()
        writer.writerows(all_rows)

        if errors:
            writer.writerow({})
            writer.writerow({"host": "UNREACHABLE / ERRORS", "hostname": "", "interface": "", "status": "", "detail": ""})
            for h, err in errors:
                writer.writerow({"host": h, "hostname": "", "interface": "", "status": "ERROR", "detail": err})

    cycled_count = sum(1 for r in all_rows if r["status"] == "CYCLED")
    error_count  = sum(1 for r in all_rows if r["status"] == "ERROR") + len(errors)

    print(f"  Interfaces cycled : {cycled_count}")
    print(f"  Errors            : {error_count}")
    print(f"  Report saved to   : {csv_path}")
    print()


if __name__ == "__main__":
    main()
