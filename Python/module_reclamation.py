#!/usr/bin/env python3
"""
module_reclamation.py
Identifies unused network modules and optics on Cisco Catalyst 9200/9300 switches via SSH.

Usage:
    python module_reclamation.py --file switches.txt
    python module_reclamation.py --host 192.168.1.10 192.168.1.11

switches.txt format — one IP or hostname per line, # for comments:
    192.168.1.10
    192.168.1.11
    # 192.168.1.12  <- skip this one

Requirements:
    pip install netmiko
"""

import csv
import sys
import re
import getpass
import argparse
import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException
except ImportError:
    print("ERROR: netmiko is required.  Run:  pip install netmiko")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Module PID database
# Format: PID -> { "ports": int, "speeds": [abbreviated IOS prefixes], "desc": str }
#
# Multi-rate modules (NM-8X, NM-2Y, etc.) create multiple speed-prefixed
# interface aliases per physical port slot. A slot is only "unused" when
# ALL aliases across ALL ports are down.
# ---------------------------------------------------------------------------
MODULE_DB = {
    # ── Catalyst 9300 / 9300X ─────────────────────────────────────────────
    "C9300-NM-4G":    {"ports": 4,  "speeds": ["Gi"],
                       "desc": "4x 1G SFP"},
    "C9300-NM-8X":    {"ports": 8,  "speeds": ["Gi", "Te", "Fo", "Twe"],
                       "desc": "8x 10G SFP+ (multi-rate: 1/10/25/40G aliases)"},
    "C9300-NM-4M":    {"ports": 4,  "speeds": ["Gi", "Te", "Twe", "Fo"],
                       "desc": "4x mGig RJ-45 (1/2.5/5/10G)"},
    "C9300-NM-2Y":    {"ports": 2,  "speeds": ["Twe", "HuG"],
                       "desc": "2x 25G SFP28"},
    "C9300-NM-2Q":    {"ports": 2,  "speeds": ["Fo", "HuG"],
                       "desc": "2x 40G QSFP+"},
    "C9300X-NM-2C":   {"ports": 2,  "speeds": ["HuG", "Fo"],
                       "desc": "2x 100G QSFP28"},
    "C9300X-NM-4C":   {"ports": 4,  "speeds": ["HuG", "Fo"],
                       "desc": "4x 100G QSFP28"},
    "C9300X-NM-8M":   {"ports": 8,  "speeds": ["Gi", "Te", "Twe", "Fo"],
                       "desc": "8x mGig RJ-45"},
    "C9300X-NM-8Y":   {"ports": 8,  "speeds": ["Twe", "HuG"],
                       "desc": "8x 25G SFP28"},
    "C9300-NM-8X-M":  {"ports": 8,  "speeds": ["Gi", "Te", "Fo", "Twe"],
                       "desc": "8x 10G SFP+ (Meraki-managed)"},
    # Legacy 3850 modules — also run on 9300
    "C3850-NM-4-1G":  {"ports": 4,  "speeds": ["Gi"],
                       "desc": "4x 1G SFP (3850 legacy)"},
    "C3850-NM-2-10G": {"ports": 2,  "speeds": ["Te"],
                       "desc": "2x 10G SFP+ (3850 legacy)"},
    "C3850-NM-4-10G": {"ports": 4,  "speeds": ["Te"],
                       "desc": "4x 10G SFP+ (3850 legacy)"},
    "C3850-NM-8-10G": {"ports": 8,  "speeds": ["Te"],
                       "desc": "8x 10G SFP+ (3850 legacy)"},
    # ── Catalyst 9200 ─────────────────────────────────────────────────────
    "C9200-NM-4G":    {"ports": 4,  "speeds": ["Gi"],
                       "desc": "4x 1G SFP"},
    "C9200-NM-4X":    {"ports": 4,  "speeds": ["Te"],
                       "desc": "4x 10G SFP+"},
    "C9200-NM-2Y":    {"ports": 2,  "speeds": ["Twe", "HuG"],
                       "desc": "2x 25G SFP28"},
    "C9200-NM-2Q":    {"ports": 2,  "speeds": ["Fo", "HuG"],
                       "desc": "2x 40G QSFP+"},
}

# IOS abbreviated speed prefix -> full name (for display)
SPEED_LABEL = {
    "Gi":  "GigabitEthernet",
    "Te":  "TenGigabitEthernet",
    "Twe": "TwentyFiveGigE",
    "Fo":  "FortyGigabitEthernet",
    "HuG": "HundredGigE",
}

# PIDs to skip from inventory — stacking cables, PSUs, fans, blank modules
IGNORE_PID_PREFIXES = (
    "STACK-T", "C9300-STACK", "C9200-STACK",
    "PWR-C", "C9300-FAN", "C9200-FAN", "NM-BLANK",
)

# Switch chassis PIDs that can appear in optic inventory slots (IOS bug)
# Any optic entry with one of these PIDs is a false positive and should be ignored
CHASSIS_PID_PREFIXES = (
    "C9200", "C9300", "C9500", "C9600", "C9400",
    "WS-C", "N9K-", "N3K-", "AIR-",
)

# Interface statuses that mean "not in use"
# "show ip interface brief" status values that mean unused
DOWN_STATUSES = {"down", "administratively down"}

# Regex: inventory block
RE_INV_ITEM = re.compile(
    r'NAME:\s+"([^"]+)".*?PID:\s+(\S+)\s*,\s*VID:\s+(\S+)\s*,\s*SN:\s+([^\s,]+)',
    re.DOTALL
)
# Regex: "Switch 3 FRU Uplink Module 1" -> switch=3, slot=1
RE_MODULE_NAME = re.compile(
    r'Switch\s+(\d+)\s+FRU\s+Uplink\s+Module\s+(\d+)', re.IGNORECASE
)
# Regex: optic inventory name like "Te2/1/1" or "Twe5/1/2"
RE_OPTIC_NAME = re.compile(
    r'^(Gi|Te|Twe|Fo|HuG)(\d+)/(\d+)/(\d+)$'
)
# Regex: interface line from "show ip interface brief"
# Matches both abbreviated (Te, Twe) and full names (TwentyFiveGigE, etc.)
# since IOS uses full names in this command output.
RE_INTF_LINE = re.compile(
    r'^(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet'
    r'|HundredGigE|Gi|Te|Twe|Fo|HuG)(\d+)/(\d+)/(\d+)\s+\S+\s+\S+\s+\S+\s+(\S.*?)\s+\S+\s*$',
    re.MULTILINE
)


def normalize_pid(pid: str) -> str:
    return pid.rstrip("=").upper().strip()


def is_down(status: str) -> bool:
    return (status or "").lower().strip() in DOWN_STATUSES


def should_ignore(pid: str) -> bool:
    return any(pid.startswith(p) for p in IGNORE_PID_PREFIXES)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_inventory(raw: str):
    """
    Parse 'show inventory' output.
    Returns:
        modules — list of dicts for FRU Uplink Module entries
        optics  — list of dicts for transceiver entries (named like Te2/1/1)
    """
    modules, optics = [], []

    for m in RE_INV_ITEM.finditer(raw):
        name = m.group(1).strip()
        pid  = normalize_pid(m.group(2))
        vid  = m.group(3).strip()
        sn   = m.group(4).strip()

        if should_ignore(pid):
            continue

        # FRU Uplink Module entry
        mod_match = RE_MODULE_NAME.search(name)
        if mod_match:
            modules.append({
                "name":   name,
                "pid":    pid,
                "vid":    vid,
                "sn":     sn,
                "switch": int(mod_match.group(1)),
                "slot":   int(mod_match.group(2)),
            })
            continue

        # Optic/transceiver entry — name matches interface pattern
        optic_match = RE_OPTIC_NAME.match(name)
        if optic_match:
            # Skip if PID looks like a switch chassis rather than a transceiver
            if any(pid.startswith(p) for p in CHASSIS_PID_PREFIXES):
                continue
            optics.append({
                "name":        name,
                "pid":         pid,
                "vid":         vid,
                "sn":          sn,
                "speed_pfx":   optic_match.group(1),
                "switch":      int(optic_match.group(2)),
                "uplink_slot": int(optic_match.group(3)),
                "port":        int(optic_match.group(4)),
            })

    return modules, optics


# Map full IOS interface names to abbreviated form used in show inventory
INTF_ABBREV = {
    "GigabitEthernet":      "Gi",
    "TenGigabitEthernet":   "Te",
    "TwentyFiveGigE":       "Twe",
    "FortyGigabitEthernet": "Fo",
    "HundredGigE":          "HuG",
}


def parse_intf_status(raw: str) -> dict:
    """
    Parse 'show ip interface brief' output.
    Full names (TwentyFiveGigE, etc.) are normalized to abbreviated form
    so they match the keys used in check_module and check_optic.
    Returns dict: { "Twe1/1/2": "up", "Te3/1/1": "down", ... }
    """
    status = {}
    for m in RE_INTF_LINE.finditer(raw):
        pfx = INTF_ABBREV.get(m.group(1), m.group(1))
        key = f"{pfx}{m.group(2)}/{m.group(3)}/{m.group(4)}"
        status[key] = m.group(5).lower()
    return status


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def check_module(mod: dict, intf_status: dict) -> dict:
    """
    For a module, check every physical port across every speed alias.
    Returns analysis dict including whether the module is fully unused.
    """
    pid = mod["pid"]
    db  = MODULE_DB.get(pid)

    if not db:
        return {
            "pid":         pid,
            "known":       False,
            "used":        None,
            "port_detail": [],
        }

    sw    = mod["switch"]
    slot  = mod["slot"]
    ports = db["ports"]
    speeds = db["speeds"]

    port_detail = []
    module_used = False

    for p in range(1, ports + 1):
        aliases = {}
        for spd in speeds:
            key = f"{spd}{sw}/{slot}/{p}"
            st  = intf_status.get(key)
            if st is not None:
                aliases[key] = st
                if not is_down(st):
                    module_used = True
        port_detail.append({"port": p, "aliases": aliases})

    return {
        "pid":         pid,
        "known":       True,
        "used":        module_used,
        "port_detail": port_detail,
    }


def check_optic(optic: dict, intf_status: dict) -> dict:
    """
    Check whether the interface an optic is seated in is up or down.
    """
    key    = optic["name"]   # e.g. "Te2/1/1"
    status = intf_status.get(key, "unknown")
    return {
        "interface": key,
        "pid":       optic["pid"],
        "sn":        optic["sn"],
        "status":    status,
        "used":      not is_down(status),
    }


# ---------------------------------------------------------------------------
# SSH data collection
# ---------------------------------------------------------------------------

def collect(host: str, username: str, password: str,
            timeout: int) -> dict:
    """
    SSH to a single device and collect inventory + interface data.
    All status messages are returned in the result dict so the caller
    can print them in order (thread-safe buffered output).
    """
    device = {
        "device_type":          "cisco_ios",
        "host":                 host,
        "username":             username,
        "password":             password,
        "timeout":              timeout,
        "global_delay_factor":  2,
    }
    try:
        with ConnectHandler(**device) as conn:
            hostname   = conn.find_prompt().rstrip("#>").strip()
            raw_inv    = conn.send_command("show inventory",          read_timeout=60)
            raw_status = conn.send_command("show ip interface brief", read_timeout=60)
        return {"host": host, "hostname": hostname,
                "inventory": raw_inv, "intf_status": raw_status,
                "error": None}

    except NetMikoTimeoutException:
        return {"host": host, "error": "Timeout"}
    except NetMikoAuthenticationException:
        return {"host": host, "error": "Authentication failed"}
    except Exception as e:
        return {"host": host, "error": str(e)}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(hostname: str, modules: list, optics: list,
                 intf_status: dict, verbose: bool, unused_only: bool):
    print(f"\n{'='*70}")
    print(f"  {hostname}")
    print(f"{'='*70}")

    # ── Modules ──────────────────────────────────────────────────────────
    print(f"\n  [ NETWORK MODULES ]  ({len(modules)} installed)\n")

    if not modules:
        print("  (none)\n")
    else:
        for mod in modules:
            result = check_module(mod, intf_status)
            db     = MODULE_DB.get(mod["pid"], {})

            if not result["known"]:
                label = "⚠  UNKNOWN PID — manual review"
            elif not result["used"]:
                label = "✖  ALL PORTS DOWN — RECLAIMABLE"
            else:
                label = "✔  IN USE"

            print(f"  Switch {mod['switch']} / Slot {mod['slot']}  |  {mod['pid']}")
            print(f"    S/N   : {mod['sn']}   VID: {mod['vid']}")
            if db:
                print(f"    Type  : {db['desc']}")
            print(f"    Status: {label}")

            if verbose or (result["known"] and not result["used"]):
                for pd in result["port_detail"]:
                    if pd["aliases"]:
                        alias_str = "  ".join(
                            f"{k}={v}" for k, v in pd["aliases"].items()
                        )
                    else:
                        alias_str = "(no interface data)"
                    print(f"      Port {pd['port']:>2}: {alias_str}")
            print()

    # ── Optics ───────────────────────────────────────────────────────────
    print(f"  [ OPTICS ]  ({len(optics)} seated)\n")

    if not optics:
        print("  (none)\n")
    else:
        for op in optics:
            result = check_optic(op, intf_status)
            if unused_only and result["used"]:
                continue
            label = "✖  RECLAIMABLE" if not result["used"] else f"✔  IN USE ({result['status']})"
            print(f"  {op['name']:<14}  {op['pid']:<24}  S/N: {op['sn']}")
            print(f"    Status: {label}\n")


def write_csv(results: list, filepath: str):
    errors = [r for r in results if r.get("error")]
    results = [r for r in results if not r.get("error")]
    rows = []
    for r in results:
        for mod, analysis in r["module_results"]:
            if analysis["known"] and not analysis["used"]:
                db = MODULE_DB.get(mod["pid"], {})
                rows.append({
                    "type":        "MODULE",
                    "hostname":    r["hostname"],
                    "host":        r["host"],
                    "switch":      mod["switch"],
                    "slot":        mod["slot"],
                    "pid":         mod["pid"],
                    "serial":      mod["sn"],
                    "description": db.get("desc", ""),
                    "interface":   "",
                    "status":      "ALL PORTS DOWN",
                })
        for op, analysis in r["optic_results"]:
            if not analysis["used"]:
                rows.append({
                    "type":        "OPTIC",
                    "hostname":    r["hostname"],
                    "host":        r["host"],
                    "switch":      op["switch"],
                    "slot":        op["uplink_slot"],
                    "pid":         op["pid"],
                    "serial":      op["sn"],
                    "description": op["name"],
                    "interface":   op["name"],
                    "status":      analysis["status"],
                })

    # Append ERROR rows for any switches that failed to connect
    for e in errors:
        rows.append({
            "type":        "ERROR",
            "hostname":    e["host"],
            "host":        e["host"],
            "switch":      "",
            "slot":        "",
            "pid":         "",
            "serial":      "",
            "description": e["error"],
            "interface":   "",
            "status":      "SSH FAILED",
        })

    if not rows:
        print("\n  No unused items found — nothing to write to CSV.")
        return

    fields = ["type", "hostname", "host", "switch", "slot",
              "pid", "serial", "description", "interface", "status"]

    # ── Build summary rows ────────────────────────────────────────────
    module_rows = [r for r in rows if r["type"] == "MODULE"]
    optic_rows  = [r for r in rows if r["type"] == "OPTIC"]
    error_rows  = [r for r in rows if r["type"] == "ERROR"]

    # Count reclaimable modules by PID
    from collections import Counter
    mod_counts   = Counter(r["pid"] for r in module_rows)
    optic_counts = Counter(r["pid"] for r in optic_rows)

    empty = {f: "" for f in fields}
    summary_rows = [
        empty,
        empty,
        {**empty, "type": "--- SUMMARY ---"},
        {**empty, "type": "MODULES", "hostname": "Total reclaimable",
         "host": str(len(module_rows))},
    ]
    for pid, count in sorted(mod_counts.items(), key=lambda x: -x[1]):
        db = MODULE_DB.get(pid, {})
        summary_rows.append({
            **empty,
            "type":        "MODULE",
            "pid":         pid,
            "description": db.get("desc", ""),
            "serial":      str(count),
            "status":      f"{count} unit(s)",
        })
    summary_rows.append(
        {**empty, "type": "OPTICS", "hostname": "Total reclaimable",
         "host": str(len(optic_rows))}
    )
    for pid, count in sorted(optic_counts.items(), key=lambda x: -x[1]):
        summary_rows.append({
            **empty,
            "type":        "OPTIC",
            "pid":         pid,
            "serial":      str(count),
            "status":      f"{count} unit(s)",
        })
    if error_rows:
        summary_rows.append(
            {**empty, "type": "ERRORS", "hostname": "SSH failures",
             "host": str(len(error_rows))}
        )

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
        writer.writerows(summary_rows)

    reclaimable = len(module_rows) + len(optic_rows)
    error_count = len(error_rows)
    msg = f"\n  CSV written: {filepath}  ({reclaimable} reclaimable item(s)"
    if error_count:
        msg += f", {error_count} error(s)"
    msg += ")"
    print(msg)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Find unused network modules and optics on Catalyst 9200/9300 switches."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--host", nargs="+", metavar="IP/HOSTNAME",
                     help="One or more switch IPs or hostnames")
    src.add_argument("--file", metavar="FILE",
                     help="Text file with one switch IP/hostname per line")

    parser.add_argument("-u", "--username", default=None)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("--timeout",     type=int, default=30)
    parser.add_argument("--verbose",     action="store_true",
                        help="Show per-port alias detail for every module")
    parser.add_argument("--unused-only", action="store_true",
                        help="Only print unused optics (reduces output noise)")
    parser.add_argument("--out", metavar="FILE", default=None,
                        help="CSV path (default: unused_modules_<timestamp>.csv)")
    parser.add_argument("--list-modules", action="store_true",
                        help="Print known module PID database and exit")
    args = parser.parse_args()

    if args.list_modules:
        print("\nKnown Catalyst 9200/9300 Network Module PIDs:\n")
        for pid, info in sorted(MODULE_DB.items()):
            print(f"  {pid:<24}  {info['ports']} ports  —  {info['desc']}")
        print()
        sys.exit(0)

    # Build host list
    if args.host:
        hosts = args.host
    else:
        with open(args.file) as f:
            hosts = [l.strip() for l in f
                     if l.strip() and not l.strip().startswith("#")]

    username = args.username or input("Username: ")
    password = args.password or getpass.getpass("Password: ")

    csv_path = args.out or \
        f"unused_modules_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    print(f"\n  Targets: {len(hosts)} switch(es)")

    # State shared across nested functions
    all_results = []
    total      = len(hosts)
    counter    = [0]          # list so nested functions can mutate it
    print_lock = threading.Lock()

    import io, contextlib

    def process_raw(raw):
        """Turn a raw collect() result into a (result, output) tuple."""
        if raw["error"]:
            return {"host": raw["host"], "error": raw["error"]},                    f"  [{raw['host']}] ERROR: {raw['error']}\n"
        modules, optics = parse_inventory(raw["inventory"])
        intf_status     = parse_intf_status(raw["intf_status"])
        module_results  = [(m, check_module(m, intf_status)) for m in modules]
        optic_results   = [(o, check_optic(o, intf_status))  for o in optics]
        result = {
            "host":           raw["host"],
            "hostname":       raw["hostname"],
            "module_results": module_results,
            "optic_results":  optic_results,
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(raw["hostname"], modules, optics, intf_status,
                         args.verbose, args.unused_only)
        return result, buf.getvalue()

    def process(host):
        """Collect + process a single host via SSH."""
        return process_raw(collect(host, username, password, args.timeout))

    def handle(result, output, host):
        """Print buffered output and append to all_results (thread-safe)."""
        with print_lock:
            print(f"[{counter[0]}/{total}] {host}", flush=True)
            print(output, end="")
        all_results.append(result)

    # ── Credential check — test first host, reuse result if successful ──
    print(f"  Verifying credentials against {hosts[0]}...", end="", flush=True)
    preflight = collect(hosts[0], username, password, args.timeout)
    if preflight["error"] == "Authentication failed":
        print(f"\n\n  ERROR: Authentication failed on {hosts[0]}."
              "\n  Please re-run with the correct credentials.\n")
        sys.exit(1)
    elif preflight["error"]:
        print(f" WARNING: {preflight['error']} — will still attempt remaining hosts\n")
        remaining = hosts       # retry hosts[0] in the pool
    else:
        print(" OK\n")
        counter[0] += 1
        result, output = process_raw(preflight)
        handle(result, output, hosts[0])
        remaining = hosts[1:]

    # 10 concurrent connections — safe for TACACS/ISE at ~180 switch scale
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process, host): host for host in remaining}
        for future in as_completed(futures):
            host = futures[future]
            counter[0] += 1
            try:
                result, output = future.result()
            except Exception as e:
                with print_lock:
                    print(f"  [{host}] ERROR: {e}")
                all_results.append({"host": host, "error": str(e)})
                continue
            handle(result, output, host)

    # ── Global summary ────────────────────────────────────────────────────
    good = [r for r in all_results if not r.get("error")]
    total_unused_mods   = sum(
        1 for r in good
        for _, a in r["module_results"]
        if a["known"] and not a["used"]
    )
    total_unused_optics = sum(
        1 for r in good
        for _, a in r["optic_results"]
        if not a["used"]
    )
    total_mods   = sum(len(r["module_results"]) for r in good)
    total_optics = sum(len(r["optic_results"])  for r in good)

    print("\n" + "=" * 70)
    print(f"  GLOBAL SUMMARY  —  {len(good)} switch(es) checked  ({len(all_results)-len(good)} error(s))")
    print(f"    Modules  detected    : {total_mods}")
    print(f"    Modules  reclaimable : {total_unused_mods}")
    print(f"    Optics   detected    : {total_optics}")
    print(f"    Optics   reclaimable : {total_unused_optics}")
    print("=" * 70)

    write_csv(all_results, csv_path)


if __name__ == "__main__":
    main()
