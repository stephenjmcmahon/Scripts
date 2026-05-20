#!/usr/bin/env python3
"""
Stack Member Removal Feasibility Assessor
Targets Cisco Catalyst 9200/9300 stacks.
Checks if the last stack member can be safely removed and its ports
absorbed by the switch directly above it in the stack.

Usage:
    python3 stack_feasibility.py -t 10.0.0.1,10.0.0.2
    python3 stack_feasibility.py -f targets.txt
    python3 stack_feasibility.py -t 10.0.0.1 --ssh-port 2222
"""

import argparse
import csv
import getpass
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    print("[ERROR] netmiko not installed. Run: pip install netmiko")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class StackMember:
    switch_num: int
    role: str          # Active / Standby / Member
    model: str
    mac: str
    priority: int
    hw_ver: str
    state: str         # Ready / Provisioned / etc.

@dataclass
class PortStats:
    switch_num: int
    total_ports: int = 0
    active_ports: int = 0       # "connected" in show interfaces status
    free_ports: int = 0
    poe_budget_w: float = 0.0   # Total PoE capacity
    poe_used_w: float = 0.0     # Current PoE draw
    poe_free_w: float = 0.0
    active_vlans: list = field(default_factory=list)
    trunk_count: int = 0
    access_count: int = 0

@dataclass
class FeasibilityResult:
    target_ip: str
    hostname: str
    is_stack: bool
    stack_size: int
    last_member_num: int
    last_member_model: str
    last_member_role: str
    last_member_priority: int
    # Ports on the last member
    last_active_ports: int
    last_total_ports: int
    last_trunk_count: int
    last_access_count: int
    last_active_vlans: str        # comma-separated
    last_poe_used_w: float
    # Receiving switch (second-to-last)
    receiver_switch_num: int
    receiver_model: str
    receiver_free_ports: int
    receiver_poe_free_w: float
    # Feasibility
    port_delta: int               # receiver_free - last_active (positive = OK)
    poe_delta_w: float            # receiver_poe_free - last_poe_used (positive = OK)
    tier: str                     # GREEN / YELLOW / RED
    notes: str
    error: str = ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_show_switch(output: str) -> list[StackMember]:
    """Parse 'show switch' output into a list of StackMember objects."""
    members = []
    # Match lines like:
    #  *1    Active   C9300-48P    xxxx.xxxx.xxxx   1       V06       Ready
    #   2    Member   C9300-24T    xxxx.xxxx.xxxx   1       V06       Ready
    pattern = re.compile(
        r'^[\ \*]*(\d+)\s+(Active|Standby|Member|Ha\s+Active|Ha\s+Standby)\s+'
        r'([0-9a-f.]{14})\s+(\d+)\s+(\S+)\s+(\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    for m in pattern.finditer(output):
        if m:
            members.append(StackMember(
                switch_num=int(m.group(1)),
                role=m.group(2).strip(),
                model="",
                mac=m.group(3),
                priority=int(m.group(4)),
                hw_ver=m.group(5),
                state=m.group(6),
            ))
    return members


def parse_interfaces_status(output: str, switch_num: int) -> PortStats:
    """
    Parse 'show interfaces status' to count active/free ports for a specific
    switch number. Filters by GiX/Y or TeX/Y where X == switch_num.
    Excludes AppGig and management interfaces.
    """
    stats = PortStats(switch_num=switch_num)
    vlans_seen = set()
    trunk_count = 0
    access_count = 0
    active_count = 0
    total_count = 0

    # Port line: Gi1/0/1   connected    1       a-full  a-1000  ...
    port_pattern = re.compile(
        r'^(Gi|Te|Tw|Fo|Fi|Hu|Twe)' + str(switch_num) + r'/\d+/\d+\s+\S*\s+(connected|notconnect|disabled|err-disabled)\s+(\S+)',
        re.IGNORECASE | re.MULTILINE
    )

    for m in port_pattern.finditer(output):
        total_count += 1
        status = m.group(2).lower()
        vlan_field = m.group(3)

        if status == 'connected':
            active_count += 1
            if vlan_field.lower() == 'trunk':
                trunk_count += 1
            else:
                access_count += 1
                if vlan_field.isdigit():
                    vlans_seen.add(int(vlan_field))

    stats.total_ports = total_count
    stats.active_ports = active_count
    stats.free_ports = total_count - active_count
    stats.active_vlans = sorted(vlans_seen)
    stats.trunk_count = trunk_count
    stats.access_count = access_count
    return stats


def parse_show_version_models(output: str) -> dict[int, str]:
    """
    Parse 'show version' switch table to get model per switch number.
    Matches lines like:
         1 65    C9300-48P     17.12.04 ...
    *    2 65    C9300-48UN    17.12.04 ...
    """
    models = {}
    pattern = re.compile(
        r'^[\ \*]*(\d+)\s+\d+\s+(C9\d{3}-\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    for m in pattern.finditer(output):
        models[int(m.group(1))] = m.group(2)
    return models

def parse_poe_inline(output: str, switch_num: int) -> tuple[float, float]:
    """
    Parse 'show power inline' to get total budget and used watts for a switch.
    Returns (budget_w, used_w). Returns (0.0, 0.0) if PoE not supported.
    """
    budget = 0.0
    used = 0.0

    # Summary line per switch:
    # Switch Available(W) Used(W) Remaining(W)
    # 1      1440.0       312.5   1127.5
    summary_pattern = re.compile(
        r'^\s*' + str(switch_num) + r'\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
        re.MULTILINE
    )
    m = summary_pattern.search(output)
    if m:
        budget = float(m.group(1))
        used = float(m.group(2))
        return budget, used

    # Fallback: per-module lines like "Module   Available(W) Used(W) ..."
    # Some IOS-XE versions use "GigabitEthernetX/0/1" format in summary
    module_pattern = re.compile(
        r'Gi' + str(switch_num) + r'/\S+\s+\S+\s+[\d.]+\s+([\d.]+)',
        re.IGNORECASE
    )
    for m in module_pattern.finditer(output):
        used += float(m.group(1))

    return budget, used


# ---------------------------------------------------------------------------
# Device interrogation
# ---------------------------------------------------------------------------

def interrogate_device(ip: str, username: str, password: str,
                        ssh_port: int = 22) -> FeasibilityResult:
    """SSH into a device, collect data, return a FeasibilityResult."""

    result = FeasibilityResult(
        target_ip=ip,
        hostname="",
        is_stack=False,
        stack_size=0,
        last_member_num=0,
        last_member_model="",
        last_member_role="",
        last_member_priority=0,
        last_active_ports=0,
        last_total_ports=0,
        last_trunk_count=0,
        last_access_count=0,
        last_active_vlans="",
        last_poe_used_w=0.0,
        receiver_switch_num=0,
        receiver_model="",
        receiver_free_ports=0,
        receiver_poe_free_w=0.0,
        port_delta=0,
        poe_delta_w=0.0,
        tier="",
        notes="",
    )

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "port": ssh_port,
        "timeout": 30,
        "session_timeout": 60,
        "fast_cli": False,
    }

    try:
        print(f"  [→] Connecting to {ip}...")
        with ConnectHandler(**device) as conn:
            # Hostname
            prompt = conn.find_prompt()
            hostname = prompt.strip("#>").strip()
            result.hostname = hostname
            print(f"  [✓] Connected — {hostname}")

            # Stack topology
            sw_output = conn.send_command("show switch", read_timeout=30)
            members = parse_show_switch(sw_output)

            if len(members) < 2:
                result.is_stack = False
                result.stack_size = len(members)
                result.tier = "N/A"
                result.notes = "Standalone switch or single-member stack — no member to remove."
                print(f"  [!] {hostname}: standalone/single-member, skipping.")
                return result

            result.is_stack = True
            result.stack_size = len(members)

            # Sort by switch number to reliably find last/second-to-last
            members.sort(key=lambda x: x.switch_num)
            last = members[-1]
            receiver = members[-2]

            ver_output = conn.send_command("show version", read_timeout=30)
            version_models = parse_show_version_models(ver_output)

            result.last_member_model = version_models.get(last.switch_num, "unknown")
            result.last_member_role = last.role
            result.last_member_priority = last.priority
            result.receiver_switch_num = receiver.switch_num
            result.receiver_model = version_models.get(receiver.switch_num, "unknown")
            result.last_member_num = last.switch_num
            result.last_member_role = last.role
            result.last_member_priority = last.priority

            print(f"  [i] Stack size: {len(members)} | Last: Sw{last.switch_num} ({last.model}) | Receiver: Sw{receiver.switch_num} ({receiver.model})")

            # Interface status for both switches (one command, parse by switch num)
            print(f"  [→] Fetching interface status...")
            intf_output = conn.send_command("show interfaces status", read_timeout=60)

            last_ports = parse_interfaces_status(intf_output, last.switch_num)
            recv_ports = parse_interfaces_status(intf_output, receiver.switch_num)

            result.last_active_ports = last_ports.active_ports
            result.last_total_ports = last_ports.total_ports
            result.last_trunk_count = last_ports.trunk_count
            result.last_access_count = last_ports.access_count
            result.last_active_vlans = ",".join(str(v) for v in last_ports.active_vlans)
            result.receiver_free_ports = recv_ports.free_ports

            # PoE
            print(f"  [→] Fetching PoE data...")
            poe_output = conn.send_command("show power inline", read_timeout=30)

            last_budget, last_used = parse_poe_inline(poe_output, last.switch_num)
            recv_budget, recv_used = parse_poe_inline(poe_output, receiver.switch_num)

            result.last_poe_used_w = last_used
            result.receiver_poe_free_w = round(recv_budget - recv_used, 1)

            # Deltas
            result.port_delta = recv_ports.free_ports - last_ports.active_ports
            result.poe_delta_w = round((recv_budget - recv_used) - last_used, 1)

    except NetmikoAuthenticationException:
        result.error = "Authentication failed"
        result.tier = "ERROR"
        print(f"  [✗] {ip}: auth failure")
        return result
    except NetmikoTimeoutException:
        result.error = "Connection timed out"
        result.tier = "ERROR"
        print(f"  [✗] {ip}: timeout")
        return result
    except Exception as e:
        result.error = str(e)
        result.tier = "ERROR"
        print(f"  [✗] {ip}: {e}")
        return result

    # -------------------------------------------------------------------
    # Feasibility scoring
    # -------------------------------------------------------------------
    notes = []
    issues = []
    warnings = []

    # Port check
    if result.port_delta >= 0:
        buffer_pct = (result.port_delta / max(result.last_active_ports, 1)) * 100
        if buffer_pct >= 20:
            notes.append(f"Port buffer: +{result.port_delta} free ({buffer_pct:.0f}% headroom)")
        else:
            warnings.append(f"Tight port fit: only +{result.port_delta} spare ports ({buffer_pct:.0f}% buffer)")
    else:
        issues.append(f"PORT DEFICIT: receiver needs {abs(result.port_delta)} more free ports")

    # PoE check
    poe_present = last_used > 0 or recv_budget > 0
    if poe_present:
        if result.poe_delta_w >= 100:
            notes.append(f"PoE headroom: +{result.poe_delta_w}W free after absorption")
        elif result.poe_delta_w >= 0:
            warnings.append(f"PoE tight: only {result.poe_delta_w}W remaining after absorption")
        else:
            issues.append(f"POE OVERSUBSCRIPTION: {abs(result.poe_delta_w)}W short on receiver")
    else:
        notes.append("No PoE detected on last member")

    # VLAN complexity
    vlan_count = len(last_ports.active_vlans)
    if last_ports.trunk_count > 0:
        warnings.append(f"Trunk ports present: {last_ports.trunk_count} trunk(s) — verify config before recabling")
    if vlan_count > 4:
        warnings.append(f"High VLAN diversity: {vlan_count} VLANs across active ports")
    elif vlan_count > 1:
        notes.append(f"Multi-VLAN: {vlan_count} VLANs on active ports")

    # Priority check — warn if last member has elevated priority
    if last.priority >= max(m.priority for m in members[:-1]):
        warnings.append(f"Switch {last.switch_num} has stack priority {last.priority} — higher than or equal to other members, verify master election won't be affected")

    # Role check
    if last.role.lower() in ("active", "ha active"):
        issues.append(f"LAST MEMBER IS ACTIVE MASTER — do NOT remove without failover")

    # Tier assignment
    if issues:
        result.tier = "RED"
    elif warnings:
        result.tier = "YELLOW"
    else:
        result.tier = "GREEN"

    result.notes = " | ".join(issues + warnings + notes)

    print(f"  [✓] {hostname}: {result.tier} — delta ports={result.port_delta}, PoE={result.poe_delta_w}W")
    return result


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

TIER_LABEL = {
    "GREEN":  "✅ GREEN  — Low effort, safe to proceed",
    "YELLOW": "⚠️  YELLOW — Proceed with caution, review notes",
    "RED":    "🔴 RED    — Do NOT proceed without resolving issues",
    "N/A":    "➖ N/A    — Standalone, not applicable",
    "ERROR":  "❌ ERROR  — Could not assess",
}

def print_summary(results: list[FeasibilityResult]):
    sep = "─" * 78
    print(f"\n{'═'*78}")
    print(f"  STACK MEMBER REMOVAL FEASIBILITY REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*78}\n")

    for r in results:
        print(sep)
        print(f"  HOST:     {r.target_ip}  ({r.hostname})")
        if r.error:
            print(f"  STATUS:   ❌ ERROR — {r.error}")
            print()
            continue
        if not r.is_stack:
            print(f"  STATUS:   {TIER_LABEL.get(r.tier, r.tier)}")
            print()
            continue

        print(f"  TIER:     {TIER_LABEL.get(r.tier, r.tier)}")
        print(f"  Stack:    {r.stack_size} members")
        print()
        print(f"  CANDIDATE FOR REMOVAL — Switch {r.last_member_num}")
        print(f"    Model:          {r.last_member_model}")
        print(f"    Role:           {r.last_member_role}  (Priority: {r.last_member_priority})")
        print(f"    Active ports:   {r.last_active_ports} / {r.last_total_ports} total")
        if r.last_trunk_count:
            print(f"    Trunk ports:    {r.last_trunk_count}")
        print(f"    Access ports:   {r.last_access_count}")
        if r.last_active_vlans:
            print(f"    VLANs in use:   {r.last_active_vlans}")
        if r.last_poe_used_w > 0:
            print(f"    PoE draw:       {r.last_poe_used_w}W")
        print()
        print(f"  RECEIVING SWITCH — Switch {r.receiver_switch_num}")
        print(f"    Model:          {r.receiver_model}")
        print(f"    Free ports:     {r.receiver_free_ports}")
        if r.receiver_poe_free_w > 0:
            print(f"    PoE headroom:   {r.receiver_poe_free_w}W available")
        print()
        print(f"  ANALYSIS")
        delta_str = f"+{r.port_delta}" if r.port_delta >= 0 else str(r.port_delta)
        print(f"    Port delta:     {delta_str} (receiver free minus ports to absorb)")
        if r.last_poe_used_w > 0 or r.receiver_poe_free_w > 0:
            poe_str = f"+{r.poe_delta_w}W" if r.poe_delta_w >= 0 else f"{r.poe_delta_w}W"
            print(f"    PoE delta:      {poe_str}")

        if r.notes:
            print(f"\n  NOTES")
            for note in r.notes.split(" | "):
                print(f"    • {note}")
        print()

    print(f"{'═'*78}\n")

    # Quick summary table
    print("  QUICK REFERENCE")
    print(f"  {'IP':<18} {'Hostname':<22} {'Candidate':<10} {'Ports Δ':<10} {'PoE Δ (W)':<12} {'Tier'}")
    print(f"  {'-'*18} {'-'*22} {'-'*10} {'-'*10} {'-'*12} {'-'*10}")
    for r in results:
        if r.error:
            print(f"  {r.target_ip:<18} {r.hostname:<22} {'—':<10} {'—':<10} {'—':<12} ❌ ERROR")
        elif not r.is_stack:
            print(f"  {r.target_ip:<18} {r.hostname:<22} {'—':<10} {'—':<10} {'—':<12} ➖ N/A")
        else:
            delta_str = f"+{r.port_delta}" if r.port_delta >= 0 else str(r.port_delta)
            poe_str = f"+{r.poe_delta_w}" if r.poe_delta_w >= 0 else str(r.poe_delta_w)
            tier_icon = {"GREEN": "✅", "YELLOW": "⚠️ ", "RED": "🔴"}.get(r.tier, r.tier)
            cand = f"Sw{r.last_member_num} ({r.last_member_model.split('-')[1] if '-' in r.last_member_model else r.last_member_model})"
            print(f"  {r.target_ip:<18} {r.hostname:<22} {cand:<10} {delta_str:<10} {poe_str:<12} {tier_icon} {r.tier}")
    print()


def write_csv(results: list[FeasibilityResult], path: str):
    fieldnames = [
        "target_ip", "hostname", "is_stack", "stack_size",
        "last_member_num", "last_member_model", "last_member_role", "last_member_priority",
        "last_active_ports", "last_total_ports", "last_trunk_count", "last_access_count",
        "last_active_vlans", "last_poe_used_w",
        "receiver_switch_num", "receiver_model", "receiver_free_ports", "receiver_poe_free_w",
        "port_delta", "poe_delta_w", "tier", "notes", "error"
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print(f"[✓] CSV saved: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cisco 9200/9300 Stack Member Removal Feasibility Assessor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--targets", help="Comma-separated list of IPs")
    group.add_argument("-f", "--file", help="File with one IP per line")
    parser.add_argument("-u", "--username", help="SSH username (prompted if omitted)")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-o", "--output", default="stack_feasibility_report.csv",
                        help="CSV output path (default: stack_feasibility_report.csv)")
    parser.add_argument("--concurrency", type=int, default=1,
                        help="Parallel threads (default: 1, increase carefully)")
    args = parser.parse_args()

    # Build target list
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        print("[ERROR] No targets provided.")
        sys.exit(1)

    # Credentials
    username = args.username or input("SSH Username: ").strip()
    password = getpass.getpass("SSH Password: ")

    print(f"\n[→] Assessing {len(targets)} device(s)...\n")

    results = []

    if args.concurrency > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {
                executor.submit(interrogate_device, ip, username, password, args.port): ip
                for ip in targets
            }
            for future in as_completed(futures):
                results.append(future.result())
    else:
        for ip in targets:
            results.append(interrogate_device(ip, username, password, args.port))

    # Sort results by tier severity for report readability
    tier_order = {"RED": 0, "YELLOW": 1, "GREEN": 2, "N/A": 3, "ERROR": 4, "": 5}
    results.sort(key=lambda r: tier_order.get(r.tier, 5))

    print_summary(results)
    write_csv(results, args.output)


if __name__ == "__main__":
    main()
