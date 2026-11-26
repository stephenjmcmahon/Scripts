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
    python3 poe_cycler.py -f switches.txt --mode off
    python3 poe_cycler.py --restore poe_recovery_TIMESTAMP.csv
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
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock, Event

import netmiko
from netmiko import ConnectHandler

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("netmiko").setLevel(logging.CRITICAL)

print_lock = Lock()
stop = Event()

def progress(hostname, message):
    with print_lock:
        print(f"  [{hostname}] {message}", flush=True)

def interrupt(signum, frame):
    stop.set()

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
    try:
        return conn.send_config_set(commands, error_pattern=r"(?im)^\s*%\s*(?:Invalid|Incomplete|Ambiguous|Error|Failed|Authorization|Command rejected)")
    finally:
        if conn.check_config_mode():
            conn.exit_config_mode()


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
    progress(hostname, f"Found {len(interfaces)} eligible interfaces: {', '.join(interfaces)}")
    try:
        for iface in interfaces:
            if stop.is_set():
                break
            row = {"host": host, "hostname": hostname, "interface": iface,
                   "status": "ERROR", "detail": "", "original_poe": ""}
            results.append(row)
            try:
                if not re.fullmatch(r"(?:Gi(?:gabitEthernet)?|Te(?:nGigabitEthernet)?|Twe(?:ntyFiveGigE)?|Hu(?:ndredGigE)?|Fi(?:veGigabitEthernet)?)[0-9]+(?:/[0-9]+)+", iface):
                    raise RuntimeError("Invalid physical interface name")
                full = expand_interface(iface)
                current = original_poe(conn, iface)
                if mode == "restore":
                    original = restore_rows[iface]["original_poe"]
                    if original == "no power inline":
                        original = "power inline auto"
                    if not re.fullmatch(r"power inline (?:auto|static)(?: [a-zA-Z0-9]+)*", original):
                        raise RuntimeError("Invalid saved PoE command")
                    row["original_poe"] = original
                    if current == original:
                        row.update(status="SKIPPED", detail="Already restored")
                    elif current != "power inline never":
                        raise RuntimeError("Current PoE mode differs; refusing to overwrite")
                    else:
                        progress(hostname, f"Restoring {iface}")
                        config(conn, [f"interface {full}", original])
                        if original_poe(conn, iface) != original:
                            raise RuntimeError("Restoration verification failed")
                        row["status"] = "RESTORED"
                else:
                    row["original_poe"] = current
                    if current == "power inline never":
                        row.update(status="SKIPPED", detail="Already disabled")
                    else:
                        journal(dict(row, status="PENDING"))
                        if mode == "cycle":
                            pending.append(row)  # even if command outcome is uncertain
                        progress(hostname, f"{iface}: disabling PoE" + (" indefinitely" if mode == "off" else " for timed cycle"))
                        config(conn, [f"interface {full}", "power inline never"])
                        if original_poe(conn, iface) != "power inline never":
                            raise RuntimeError("Shutdown verification failed")
                        row["status"] = "POWERED_OFF"
            except Exception as e:
                row.update(status="ERROR", detail=str(e))
            if mode != "restore":
                journal(row)
        if pending:
            progress(hostname, f"Waiting {delay} seconds before restoring PoE...")
            stop.wait(delay)
    finally:
        if pending:
            progress(hostname, "Interrupt received; restoring PoE..." if stop.is_set() else "Restoring PoE...")
            for row in pending:
                try:
                    iface = row["interface"]
                    current = original_poe(conn, iface)
                    if current == "power inline never":
                        config(conn, [f"interface {expand_interface(iface)}", row["original_poe"]])
                    elif current != row["original_poe"]:
                        raise RuntimeError("Unexpected PoE mode; refusing to overwrite")
                    if original_poe(conn, iface) != row["original_poe"]:
                        raise RuntimeError("Restoration verification failed")
                    if row["status"] == "POWERED_OFF":
                        row.update(status="CYCLED", detail="Restored early after interrupt" if stop.is_set() else "")
                except Exception as e:
                    row.update(status="ERROR", detail=str(e))
                try:
                    journal(row)
                except Exception as e:
                    row.update(status="ERROR", detail=f"Journal update failed: {e}")
    return results


def save_switch(conn, hostname, results):
    progress(hostname, "Saving running configuration to startup-config...")
    try:
        output = conn.save_config()
        if re.search(r"(?im)^\s*%|\b(?:failed|error|denied)\b", output or ""):
            raise RuntimeError(output)
        progress(hostname, "Configuration save command completed")
        return None
    except Exception as e:
        return f"Configuration save failed: {e}"


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

    if stop.is_set():
        return host, "unknown", [], "Interrupted before connection"
    try:
        with ConnectHandler(**device) as conn:
            hostname = get_hostname(conn)

            # Pull trunk interfaces first — never touch these
            trunk_ifaces = get_trunk_interfaces(conn)

            if mode == "restore":
                interfaces = [i for i in restore_rows if expand_interface(i) not in {expand_interface(t) for t in trunk_ifaces}]
                results = apply_poe(conn, interfaces, delay, mode, host, hostname, journal, restore_rows)
                excluded = set(restore_rows) - set(interfaces)
                for iface in sorted(excluded):
                    results.append(dict(restore_rows[iface], status="ERROR", detail="Currently trunking; not restored"))
                error = save_switch(conn, hostname, results) if save and any(r["status"] == "RESTORED" or (r["status"] == "SKIPPED" and r["detail"] == "Already restored") for r in results) else None
                return host, hostname, results, error

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
            error = save_switch(conn, hostname, results) if save and mode == "off" and any(r["status"] == "POWERED_OFF" for r in results) else None
            return host, hostname, results, error

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
    save = mode in ("off", "restore")

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

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        print("\n  ERROR: No targets found.\n")
        sys.exit(1)

    # ── VLAN prompt ───────────────────────────────────────────────────────────
    vlan_input = "" if mode == "restore" else input("  VLANs to cycle (comma-separated, e.g. 10,20): ").strip()
    vlans = [v.strip() for v in vlan_input.split(",") if v.strip()]
    if any(not v.isdecimal() or not 1 <= int(v) <= 4094 for v in vlans):
        parser.error("Invalid VLAN ID")
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
    print(f"  Save config: {save}")
    print(f"  Threads  : 10")
    print()

    # ── Run ───────────────────────────────────────────────────────────────────
    if delay < 0:
        parser.error("Delay cannot be negative")
    if save:
        print("  WARNING: This operation saves the ENTIRE running configuration.")
    if mode == "off" and input("  Type POWER OFF to confirm: ").strip() != "POWER OFF":
        sys.exit("Cancelled")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    csv_path = f"poe_cycler_{timestamp}.csv"

    recovery_path = f"poe_recovery_{timestamp}.csv"
    fields = ["host", "hostname", "interface", "status", "detail", "original_poe"]
    if mode != "restore":
        with open(recovery_path, "x", newline="") as fh:
            csv.DictWriter(fh, fieldnames=fields).writeheader()
            fh.flush()
            os.fsync(fh.fileno())
        directory = os.open(".", os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    def journal(row):
        with print_lock:
            with open(recovery_path, "a", newline="") as fh:
                csv.DictWriter(fh, fieldnames=fields).writerow(row)
                fh.flush()
                os.fsync(fh.fileno())
    if mode != "restore":
        print(f"  Recovery journal: {recovery_path}", flush=True)
    all_rows: list[dict] = []
    errors: list[tuple[str, str]] = []
    completed = 0
    total = len(hosts)

    def run_and_report(host: str):
        nonlocal completed
        h, hostname, results, error = process_device(
            host, username, password, vlans, delay, mode, journal, save, restore_by_host.get(host)
        )
        with print_lock:
            completed += 1
            if error:
                print(f"  [{completed}/{total}] {h}  →  ERROR: {error}")
                errors.append((h, error))
            if not results and not error:
                print(f"  [{completed}/{total}] {hostname} ({h})  →  No local PoE interfaces found for VLAN(s) {', '.join(vlans)}")
            elif results:
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

    stop.clear()
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(run_and_report, h): h for h in hosts}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                with print_lock:
                    print(f"  Thread error: {e}")
                    errors.append((futures[f], str(e)))

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
    if mode == "cycle" and not error_count and not stop.is_set():
        os.unlink(recovery_path)
        print("  Recovery journal : Removed (successful cycle)")
    elif mode != "restore":
        print(f"  Recovery journal : {recovery_path} (retained)")
    else:
        print(f"  Recovery source  : {args.restore} (retained)")
    if stop.is_set():
        print("  Interrupted: review results and recovery journal before exiting.")
    print(f"  Errors            : {error_count}")
    print(f"  Report saved to   : {csv_path}")
    print()
    if error_count or stop.is_set():
        sys.exit(130 if stop.is_set() else 1)


if __name__ == "__main__":
    main()
