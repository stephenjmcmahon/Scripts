#!/usr/bin/env python3
"""
Stack Member Removal Feasibility Assessor
Targets Cisco Catalyst 9200/9300 stacks.
Checks if the last stack member can be safely removed and its ports
absorbed by the switch directly above it (N-1) in the stack.

Usage:
    python3 stack_reclamation.py -t 192.168.1.1,192.168.1.2
    python3 stack_reclamation.py -f switches.txt
    python3 stack_reclamation.py -t 192.168.1.1 --ssh-port 2222
"""

import argparse
import csv
import getpass
import re
import sys
import threading
from dataclasses import dataclass, asdict
from datetime import datetime

_print_lock = threading.Lock()

import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

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
    role: str
    model: str
    mac: str
    priority: int
    hw_ver: str
    state: str

@dataclass
class PortStats:
    switch_num: int
    total_ports: int = 0
    active_ports: int = 0
    free_ports: int = 0

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
    last_active_ports: int
    last_total_ports: int
    last_poe_used_w: float
    receiver_switch_num: int
    receiver_model: str
    receiver_free_ports: int
    receiver_poe_free_w: float
    port_delta: int
    poe_delta_w: float
    tier: str
    notes: str
    error: str = ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_show_switch(output: str) -> list[StackMember]:
    """Parse 'show switch' output. Handles format without model column (9200/9300)."""
    members = []
    pattern = re.compile(
        r'^[\ \*]*(\d+)\s+(Active|Standby|Member|Ha\s+Active|Ha\s+Standby)\s+'
        r'([0-9a-f.]{14})\s+(\d+)\s+(\S+)\s+(\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    for m in pattern.finditer(output):
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


def parse_show_version_models(output: str) -> dict[int, str]:
    """Parse 'show version' switch table to get model per switch number."""
    models = {}
    pattern = re.compile(
        r'^[\ \*]*(\d+)\s+\d+\s+(C9\d{3}-\S+)',
        re.IGNORECASE | re.MULTILINE
    )
    for m in pattern.finditer(output):
        models[int(m.group(1))] = m.group(2)
    return models


def parse_interfaces_status(output: str, switch_num: int) -> PortStats:
    """
    Count active/free ports for a specific switch number.
    Handles description field between port name and status.
    Supports Gi, Te, Tw, Fo, Fi (FiveGig), Hu, Twe port types.
    """
    stats = PortStats(switch_num=switch_num)
    active_count = 0
    total_count = 0

    port_pattern = re.compile(
        r'^(Gi|Te|Tw|Fo|Fi|Hu|Twe)' + str(switch_num) +
        r'/\d+/\d+\s+\S*\s+(connected|notconnect|disabled|err-disabled)\s+(\S+)',
        re.IGNORECASE | re.MULTILINE
    )

    for m in port_pattern.finditer(output):
        total_count += 1
        if m.group(2).lower() == 'connected':
            active_count += 1

    stats.total_ports = total_count
    stats.active_ports = active_count
    stats.free_ports = total_count - active_count
    return stats


def parse_poe_inline(output: str, switch_num: int) -> tuple[float, float]:
    """
    Parse 'show power inline' summary to get budget and used watts per switch.
    Returns (budget_w, used_w). Returns (0.0, 0.0) if PoE not supported.
    """
    budget = 0.0
    used = 0.0

    summary_pattern = re.compile(
        r'^\s*' + str(switch_num) + r'\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
        re.MULTILINE
    )
    m = summary_pattern.search(output)
    if m:
        budget = float(m.group(1))
        used = float(m.group(2))
        return budget, used

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
    log = []
    def lprint(msg): log.append(msg)
    def flush_log():
        with _print_lock:
            for line in log:
                print(line)

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
        lprint(f"  [→] Connecting to {ip}...")
        with ConnectHandler(**device) as conn:
            prompt = conn.find_prompt()
            hostname = prompt.strip("#>").strip()
            result.hostname = hostname
            lprint(f"  [✓] Connected — {hostname}")

            sw_output = conn.send_command("show switch", read_timeout=30)
            members = parse_show_switch(sw_output)

            if len(members) < 2:
                result.is_stack = False
                result.stack_size = len(members)
                result.tier = "N/A"
                result.notes = "Standalone switch or single-member stack — no member to remove."
                lprint(f"  [!] {hostname}: standalone/single-member, skipping.")
                flush_log()
                return result

            result.is_stack = True
            result.stack_size = len(members)

            members.sort(key=lambda x: x.switch_num)
            last = members[-1]
            receiver = members[-2]

            ver_output = conn.send_command("show version", read_timeout=30)
            version_models = parse_show_version_models(ver_output)

            result.last_member_num = last.switch_num
            result.last_member_model = version_models.get(last.switch_num, "unknown")
            result.last_member_role = last.role
            result.last_member_priority = last.priority
            result.receiver_switch_num = receiver.switch_num
            result.receiver_model = version_models.get(receiver.switch_num, "unknown")

            lprint(f"  [i] Stack size: {len(members)} | Last: Sw{last.switch_num} ({result.last_member_model}) | Receiver: Sw{receiver.switch_num} ({result.receiver_model})")

            lprint(f"  [→] Fetching interface status...")
            intf_output = conn.send_command("show interfaces status", read_timeout=60)

            last_ports = parse_interfaces_status(intf_output, last.switch_num)
            recv_ports = parse_interfaces_status(intf_output, receiver.switch_num)

            result.last_active_ports = last_ports.active_ports
            result.last_total_ports = last_ports.total_ports
            result.receiver_free_ports = recv_ports.free_ports

            lprint(f"  [→] Fetching PoE data...")
            poe_output = conn.send_command("show power inline", read_timeout=30)

            last_budget, last_used = parse_poe_inline(poe_output, last.switch_num)
            recv_budget, recv_used = parse_poe_inline(poe_output, receiver.switch_num)

            result.last_poe_used_w = last_used
            result.receiver_poe_free_w = round(recv_budget - recv_used, 1)
            result.port_delta = recv_ports.free_ports - last_ports.active_ports
            result.poe_delta_w = round((recv_budget - recv_used) - last_used, 1)

    except NetmikoAuthenticationException:
        result.error = "Authentication failed"
        result.tier = "ERROR"
        lprint(f"  [✗] {ip}: auth failure")
        flush_log()
        return result
    except NetmikoTimeoutException:
        result.error = "Connection timed out"
        result.tier = "ERROR"
        lprint(f"  [✗] {ip}: timeout")
        flush_log()
        return result
    except Exception as e:
        result.error = str(e)
        result.tier = "ERROR"
        lprint(f"  [✗] {ip}: {e}")
        flush_log()
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

    # Priority check
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

    lprint(f"  [✓] {hostname}: {result.tier} — delta ports={result.port_delta}, PoE={result.poe_delta_w}W")
    flush_log()
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

    print("  QUICK REFERENCE")
    print(f"  {'IP':<18} {'Hostname':<22} {'Candidate':<14} {'Ports Δ':<10} {'PoE Δ (W)':<12} {'Tier'}")
    print(f"  {'-'*18} {'-'*22} {'-'*14} {'-'*10} {'-'*12} {'-'*10}")
    for r in results:
        if r.error:
            print(f"  {r.target_ip:<18} {r.hostname:<22} {'—':<14} {'—':<10} {'—':<12} ❌ ERROR")
        elif not r.is_stack:
            print(f"  {r.target_ip:<18} {r.hostname:<22} {'—':<14} {'—':<10} {'—':<12} ➖ N/A")
        else:
            delta_str = f"+{r.port_delta}" if r.port_delta >= 0 else str(r.port_delta)
            poe_str = f"+{r.poe_delta_w}" if r.poe_delta_w >= 0 else str(r.poe_delta_w)
            tier_icon = {"GREEN": "✅", "YELLOW": "⚠️ ", "RED": "🔴"}.get(r.tier, r.tier)
            cand = f"Sw{r.last_member_num} ({r.last_member_model})"
            print(f"  {r.target_ip:<18} {r.hostname:<22} {cand:<14} {delta_str:<10} {poe_str:<12} {tier_icon} {r.tier}")
    print()


def write_csv(results: list[FeasibilityResult], path: str):
    fieldnames = [
        "target_ip", "hostname", "is_stack", "stack_size",
        "last_member_num", "last_member_model", "last_member_role", "last_member_priority",
        "last_active_ports", "last_total_ports", "last_poe_used_w",
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
    group.add_argument("-f", "--file", help="File with one IP per line (# for comments)")
    parser.add_argument("-u", "--username", help="SSH username (prompted if omitted)")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parser.add_argument("-o", "--output", default=f"stack_feasibility_report_{timestamp}.csv",
                        help="CSV output path (default: stack_feasibility_report_<timestamp>.csv)")
    parser.add_argument("--concurrency", type=int, default=10,
                        help="Parallel threads (default: 10)")
    args = parser.parse_args()

    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        print("[ERROR] No targets provided.")
        sys.exit(1)

    username = args.username or input("SSH Username: ").strip()
    password = getpass.getpass("SSH Password: ")

    # Validate credentials — try first 5 targets until one responds
    print(f"\n[→] Validating credentials...")
    auth_checked = False
    for check_ip in targets[:5]:
        print(f"  [→] Trying {check_ip}...")
        try:
            test_conn = ConnectHandler(
                device_type="cisco_ios", host=check_ip,
                username=username, password=password, timeout=15
            )
            test_conn.disconnect()
            print(f"[✓] Auth OK (verified against {check_ip})\n")
            auth_checked = True
            break
        except NetmikoAuthenticationException:
            print(f"[✗] Authentication failed — check credentials and try again.")
            sys.exit(1)
        except Exception as e:
            err = str(e).lower()
            if "authentication" in err or "auth" in err or "permission denied" in err:
                print(f"[✗] Authentication failed — check credentials and try again.")
                sys.exit(1)
            # Banner errors, timeouts, connection resets = unreachable, try next
            continue

    if not auth_checked:
        print(f"[!] No targets reachable for auth check, proceeding anyway...\n")

    print(f"[→] Assessing {len(targets)} device(s)...\n")

    results = []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {
            executor.submit(interrogate_device, ip, username, password, args.port): ip
            for ip in targets
        }
        for future in as_completed(futures):
            results.append(future.result())

    tier_order = {"RED": 0, "YELLOW": 1, "GREEN": 2, "N/A": 3, "ERROR": 4, "": 5}
    results.sort(key=lambda r: tier_order.get(r.tier, 5))

    print_summary(results)
    write_csv(results, args.output)


if __name__ == "__main__":
    main()
