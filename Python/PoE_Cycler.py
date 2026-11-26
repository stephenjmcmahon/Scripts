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
    python3 poe_cycler.py -s 192.168.1.5
    python3 poe_cycler.py -s 192.168.1.5,192.168.1.6
    python3 poe_cycler.py -f switches.txt --mode off [--save]
    python3 poe_cycler.py --restore poe_recovery_TIMESTAMP.csv [--save]
"""

import argparse
from typing import Optional
import csv
import os
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
    if any(short.startswith(full) for full in expansions.values()):
        return short
    for abbrev, full in sorted(expansions.items(), key=lambda x: -len(x[0])):
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


def config(conn, commands):
    return conn.send_config_set(commands, error_pattern=r"(?im)^\s*%\s*(?:Invalid|Incomplete|Ambiguous|Error|Failed|Authorization|Command rejected)")


def original_poe(conn, iface):
    output = conn.send_command(f"show running-config interface {expand_interface(iface)}")
    if not re.search(r"(?m)^interface\s+", output):
        raise RuntimeError("Cannot read interface configuration")
    lines = [line.strip() for line in output.splitlines() if line.strip().startswith("power inline ")]
    modes = [line for line in lines if re.match(r"power inline (auto|static|never)(?: |$)", line)]
    if any(not re.fullmatch(r"power inline (?:auto|static|never)(?: [a-zA-Z0-9]+)*", line) for line in modes):
        raise RuntimeError("Unsupported PoE mode syntax")
    if len(modes) > 1:
        raise RuntimeError("Ambiguous original PoE mode")
    return modes[0] if modes else "power inline auto"


def apply_poe(conn, interfaces, delay, mode, host, hostname, journal, restore_rows=None):
    results = []
    pending = []
    for iface in interfaces:
        row = {"host": host, "hostname": hostname, "interface": iface,
               "status": "ERROR", "detail": "", "original_poe": ""}
        try:
            if not re.fullmatch(r"(?:Gi(?:gabitEthernet)?|Te(?:nGigabitEthernet)?|Twe(?:ntyFiveGigE)?|Hu(?:ndredGigE)?|Fi(?:veGigabitEthernet)?)[0-9]+(?:/[0-9]+)+", iface):
                raise RuntimeError("Invalid physical interface name")
            full = expand_interface(iface)
            if mode == "restore":
                original = restore_rows[iface]["original_poe"]
                if not re.fullmatch(r"(?:power inline auto|power inline (?:auto|static|never)(?: [a-zA-Z0-9]+)*)", original):
                    raise RuntimeError("Invalid saved PoE command")
                row["original_poe"] = original
                if original_poe(conn, iface) != "power inline never":
                    raise RuntimeError("Current PoE mode is not never; refusing to overwrite")
                config(conn, [f"interface {full}", original])
                row["status"] = "RESTORED"
            else:
                original = original_poe(conn, iface)
                row["original_poe"] = original
                if original == "power inline never":
                    row["status"] = "SKIPPED"
                    row["detail"] = "Already disabled"
                else:
                    # Persist recovery information BEFORE changing the switch.
                    journal(dict(row, status="PENDING"))
                    config(conn, [f"interface {full}", "power inline never"])
                    row["status"] = "POWERED_OFF"
                    if mode == "cycle":
                        pending.append(row)
        except Exception as e:
            row["status"] = "ERROR"
            row["detail"] = str(e)
        results.append(row)
        journal(row)
    if pending:
        time.sleep(delay)
        for row in pending:
            try:
                config(conn, [f"interface {expand_interface(row['interface'])}", row["original_poe"]])
                row["status"] = "CYCLED"
            except Exception as e:
                row["status"] = "ERROR"
                row["detail"] = str(e)
            journal(row)
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
                   vlans: list[str], delay: int, mode, journal, save, restore_rows=None) -> tuple:
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

            if mode == "restore":
                interfaces = [i for i in restore_rows if expand_interface(i) not in {expand_interface(t) for t in trunk_ifaces}]
                results = apply_poe(conn, interfaces, delay, mode, host, hostname, journal, restore_rows)
                if save and any(r["status"] == "RESTORED" for r in results):
                    conn.save_config()
                return host, hostname, results, None

            all_iface_macs: dict[str, list[str]] = {}

            for vlan in vlans:
                output = conn.send_command(
                    f"show mac address-table vlan {vlan}",
                    read_timeout=30,
                )
                parsed = parse_mac_table(output, vlans)
                for iface, macs in parsed.items():
                    if expand_interface(iface) in {expand_interface(t) for t in trunk_ifaces}:
                        continue  # skip trunks/uplinks
                    all_iface_macs.setdefault(iface, []).extend(macs)

            if not all_iface_macs:
                return host, hostname, [], None  # nothing to cycle

            interfaces = sorted(all_iface_macs.keys())
            results = apply_poe(conn, interfaces, delay, mode, host, hostname, journal)
            if save and mode == "off" and any(r["status"] == "POWERED_OFF" for r in results):
                conn.save_config()
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
    group.add_argument("--restore", metavar="CSV", help="Restore original PoE settings from recovery CSV")
    parser.add_argument("--mode", choices=["cycle", "off"], default=None)
    parser.add_argument("--save", action="store_true", help="Save running configuration after off/restore")
    args = parser.parse_args()
    mode = "restore" if args.restore else args.mode
    restore_by_host = {}
    if args.restore:
        with open(args.restore, newline="") as fh:
            latest = {(r["host"], r["interface"]): r for r in csv.DictReader(fh) if r.get("host") and r.get("interface")}
        for (host, iface), r in latest.items():
            if r.get("status") in ("PENDING", "POWERED_OFF", "ERROR") and r.get("original_poe") and r["original_poe"] != "power inline never":
                restore_by_host.setdefault(host, {})[iface] = r
    elif mode is None:
        choice = input("  PoE operation [1] Cycle (default) / [2] Off indefinitely: ").strip()
        if choice not in ("", "1", "2"):
            parser.error("Invalid operation")
        mode = "off" if choice == "2" else "cycle"
    if args.save and mode == "cycle":
        parser.error("--save is only supported for off or restore")

    print()
    print("  PoE Cycler")
    print("  " + "─" * 50)

    # ── Targets ──────────────────────────────────────────────────────────────
    if args.restore:
        hosts = sorted(restore_by_host)
    elif args.f:
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
    vlan_input = "" if mode == "restore" else input("  VLANs to cycle (comma-separated, e.g. 10,20): ").strip()
    vlans = [v.strip() for v in vlan_input.split(",") if v.strip()]
    if not vlans and mode != "restore":
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
    delay_input = "" if mode != "cycle" else input(
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
    print(f"  Mode     : {mode}")
    if mode == "cycle":
        print(f"  PoE delay: {delay}s")
    print(f"  Save config: {args.save}")
    print(f"  Threads  : 10")
    print()

    # ── Run ───────────────────────────────────────────────────────────────────
    if delay < 0:
        parser.error("Delay cannot be negative")
    if args.save and input("  Save ENTIRE running configuration to startup-config? Type SAVE: ").strip() != "SAVE":
        sys.exit("Cancelled")
    if mode == "off" and input("  Type POWER OFF to confirm: ").strip() != "POWER OFF":
        sys.exit("Cancelled")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    csv_path = f"poe_cycler_{timestamp}.csv"

    recovery_path = f"poe_recovery_{timestamp}.csv"
    fields = ["host", "hostname", "interface", "status", "detail", "original_poe"]
    with open(recovery_path, "x", newline="") as fh:
        csv.DictWriter(fh, fieldnames=fields).writeheader()
    def journal(row):
        with print_lock:
            with open(recovery_path, "a", newline="") as fh:
                csv.DictWriter(fh, fieldnames=fields).writerow(row)
                fh.flush()
                os.fsync(fh.fileno())
    print(f"  Recovery journal: {recovery_path}", flush=True)
    all_rows: list[dict] = []
    errors: list[tuple[str, str]] = []
    completed = 0
    total = len(hosts)

    def run_and_report(host: str):
        nonlocal completed
        h, hostname, results, error = process_device(
            host, username, password, vlans, delay, mode, journal, args.save, restore_by_host.get(host)
        )
        with print_lock:
            completed += 1
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
                    mark = "✓" if r["status"] in ("CYCLED", "POWERED_OFF", "RESTORED") else "-" if r["status"] == "SKIPPED" else "✗"
                    print(f"    [{mark}] {r['interface']} — {r['status']} {r.get('detail', '')}")
                all_rows.extend([
                    {"host": h, "hostname": hostname, "interface": r["interface"],
                     "status": r["status"], "detail": r.get("detail", ""), "original_poe": r.get("original_poe", "")}
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
        writer = csv.DictWriter(cf, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_rows)

        if errors:
            writer.writerow({})
            writer.writerow({"host": "UNREACHABLE / ERRORS", "hostname": "", "interface": "", "status": "", "detail": ""})
            for h, err in errors:
                writer.writerow({"host": h, "hostname": "", "interface": "", "status": "ERROR", "detail": err})

    cycled_count = sum(1 for r in all_rows if r["status"] == "CYCLED")
    error_count  = sum(1 for r in all_rows if r["status"] == "ERROR") + len(errors)

    for status in ("CYCLED", "POWERED_OFF", "RESTORED", "SKIPPED"):
        print(f"  {status:18}: {sum(r['status'] == status for r in all_rows)}")
    print(f"  Recovery journal : {recovery_path}")
    print(f"  Errors            : {error_count}")
    print(f"  Report saved to   : {csv_path}")
    print()


if __name__ == "__main__":
    main()% 
