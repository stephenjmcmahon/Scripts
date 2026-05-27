#!/usr/bin/env python3
"""
psu_investigator.py — PSU Power Investigator
Checks Cisco Catalyst switches for:
  1. Current power oversubscription (draw > capacity)
  2. N-1 PSU failure risk (would losing one PSU cause oversubscription?)
  3. Full UPS side loss risk (A-side and B-side failure scenarios)
  4. Mismatched PSUs within the same switch member

For any findings, provides remediation guidance including specific PSU PIDs,
slot-level upgrade recommendations, and notes on what can and can't be resolved
through hardware alone.

Usage:
    python3 psu_investigator.py -f switches.txt
    python3 psu_investigator.py -f switches.txt -o report.csv
    python3 psu_investigator.py -s 192.168.1.1
    python3 psu_investigator.py -s 192.168.1.1,192.168.1.2,192.168.1.3
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Suppress paramiko's internal error logging — exceptions are caught and handled
# cleanly in check_device; without this, paramiko prints raw tracebacks to stderr
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_THREADS   = 10
AUTH_CHECK_LIMIT  = 5      # Try up to this many switches to validate creds
SSH_TIMEOUT       = 20

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
print_lock = threading.Lock()

def safe_print(msg: str) -> None:
    with print_lock:
        print(msg, flush=True)


def load_targets(path: str) -> list[str]:
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    if not targets:
        print(f"[!] No targets found in {path}")
        sys.exit(1)
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────
def parse_hostname(output: str) -> str:
    """Extract hostname from 'show version' output."""
    m = re.search(r"^(\S+)\s+uptime", output, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else "unknown"


def parse_model(output: str) -> str:
    """Extract switch model from 'show version' output."""
    m = re.search(r"Model Number\s*[:\-]\s*(\S+)", output, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    # WS-C3560CX style
    m = re.search(r"cisco\s+(WS-C\S+)\s+", output, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    # C9500 / C9300 style
    m = re.search(r"cisco\s+(C9[0-9A-Z\-]+)\s+", output, re.IGNORECASE)
    return m.group(1).upper() if m else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# PSU upgrade matrix
# ─────────────────────────────────────────────────────────────────────────────
# Maps platform family → ordered list of (watts, PID) upgrade tiers.
# The script walks this list to find the current PSU size and suggest next tier.
#
# C9300 / C9300L / C9300X — PWR-C1 family
C9300_PSU_TIERS = [
    (350,  "PWR-C1-350WAC-P"),
    (715,  "PWR-C1-715WAC-P"),
    (1100, "PWR-C1-1100WAC-P"),
    (1900, "PWR-C1-1900WAC-P"),
]
# C9200 (modular) — PWR-C5/C6 family, locked per model (both slots must match)
C9200_PSU_TIERS = [
    (125,  "PWR-C5-125WAC / PWR-C6-125WAC"),
    (600,  "PWR-C5-600WAC / PWR-C6-600WAC"),
    (1000, "PWR-C5-1KWAC  / PWR-C6-1KWAC"),
]
# C9200L — PWR-C5 only (C6 not supported)
C9200L_PSU_TIERS = [
    (125,  "PWR-C5-125WAC"),
    (600,  "PWR-C5-600WAC"),
    (1000, "PWR-C5-1KWAC"),
]
# C9500 — C9K-PWR family
C9500_PSU_TIERS = [
    (1600, "C9K-PWR-1600WAC-R"),
    (2400, "C9K-PWR-2400WAC-R"),
]
# C9606R — C9600-PWR family
C9600_PSU_TIERS = [
    (1050, "C9600-PWR-2KWAC"),   # 2KW rated, 1050W active in Combined mode
    (3000, "C9600-PWR-3KWAC"),
]


def _platform_tiers(model: str) -> list:
    """Return the correct PSU tier list for a given model string."""
    m = model.upper()
    if "C9200L" in m or "C9200CX" in m:
        return C9200L_PSU_TIERS
    if "C9200" in m:
        return C9200_PSU_TIERS
    if "C9606" in m or "C9600" in m:
        return C9600_PSU_TIERS
    if "C9500" in m:
        return C9500_PSU_TIERS
    if "C9300" in m:   # covers C9300, C9300L, C9300X
        return C9300_PSU_TIERS
    return []


def get_remediation(model: str, psus: list, severity: str,
                    scenario_severity: dict, non_redundant: bool,
                    drawn_w: float = 0.0) -> str:
    """
    Return per-member PSU upgrade recommendations based on severity findings.
    For stacked platforms: identifies which members need upgrading with specific
    slot names and PIDs. For side-loss scenarios: notes that feed-level redundancy
    should be verified, since StackPower pool recalculation after an upgrade
    cannot be accurately predicted without running 'show power detail' post-swap.
    Returns empty string if severity is OK.
    """
    from collections import defaultdict

    if severity == "OK":
        return ""

    tiers = _platform_tiers(model)
    rem   = []

    # C9200CX — built-in PSU, no upgrade path
    if "C9200CX" in model.upper() or non_redundant:
        rem.append(
            "Built-in PSU — no upgrade path. "
            "For redundancy, replace with a C9200 or C9300 model that supports dual PSUs."
        )
        return " | ".join(rem)

    if not tiers:
        rem.append("Platform not in PSU matrix — check Cisco datasheet manually.")
        return " | ".join(rem)

    # C9200 note — both slots must be same wattage
    c9200_note = ""
    if "C9200" in model.upper() and "C9200L" not in model.upper():
        c9200_note = " (C9200: both slots must use identical wattage)"

    sev_order = {"CRITICAL": 0, "HIGH": 1, "DEGRADED": 1, "MEDIUM": 2, "LOW": 3, "BUILT-IN PSU": 4, "OK": 5}
    worst_scenario = min(
        scenario_severity.values(),
        key=lambda s: sev_order.get(s, 99),
        default=severity,
    ) if scenario_severity else severity

    # ── Group PSUs by member ──────────────────────────────────────────────────
    by_member: dict = defaultdict(list)
    for p in psus:
        slot = str(p["slot"])
        m    = re.match(r"^(\d+)", slot)
        member = m.group(1) if m else "1"
        by_member[member].append(dict(p))  # copy so we can mutate for simulation

    member_list = sorted(by_member.keys())
    is_stack    = len(member_list) > 1

    # ── Handle missing slot B (add PSU first) ─────────────────────────────────
    slot_actions = []
    for member, member_psus in sorted(by_member.items()):
        op_psus = [p for p in member_psus if p["ok"]]
        a_psus  = [p for p in op_psus if str(p["slot"]).endswith("A")]
        b_psus  = [p for p in op_psus if str(p["slot"]).endswith("B")]
        if a_psus and not b_psus:
            a_w      = a_psus[0]["capacity_w"]
            tier_idx = next((i for i, (w, _) in enumerate(tiers) if w == int(a_w)), None)
            pid      = tiers[tier_idx][1] if tier_idx is not None else "matching PSU"
            slot_actions.append(f"SW{member}: add {pid} to slot {member}B{c9200_note}")

    if slot_actions:
        rem.extend(slot_actions)

    # ── Mismatch fix (same member) ────────────────────────────────────────────
    for member, member_psus in sorted(by_member.items()):
        op_psus   = [p for p in member_psus if p["ok"]]
        watts_set = set(p["capacity_w"] for p in op_psus)
        if len(watts_set) > 1:
            max_w    = max(watts_set)
            tier_idx = next((i for i, (w, _) in enumerate(tiers) if w == int(max_w)), None)
            pid      = tiers[tier_idx][1] if tier_idx is not None else "matching PSU"
            low_slots = [str(p["slot"]) for p in op_psus if p["capacity_w"] < max_w]
            rem.append(f"SW{member}: replace {', '.join(low_slots)} with {pid} to match slot wattage")

    # ── Upgrade recommendations ───────────────────────────────────────────────
    # Remediate when:
    #   1. Single PSU failure would cause oversubscription (HIGH/CRITICAL)
    #   2. A or B side loss would cause oversubscription — check if upgrading
    #      the surviving side's PSUs in any combination would cover draw

    single_psu_sev  = scenario_severity.get("single_psu", "")
    a_side_sev      = scenario_severity.get("a_side_loss", "")
    b_side_sev      = scenario_severity.get("b_side_loss", "")
    single_needs_hw = single_psu_sev in ("CRITICAL", "HIGH")
    a_loss_high     = a_side_sev in ("HIGH", "MEDIUM")
    b_loss_high     = b_side_sev in ("HIGH", "MEDIUM")

    # Helper: next-tier wattage for a member's PSUs
    def next_tier_w(current_w: float):
        idx = next((i for i, (w, _) in enumerate(tiers) if w == int(current_w)), None)
        if idx is not None and idx < len(tiers) - 1:
            return tiers[idx + 1]   # (watts, pid)
        return None

    # Helper: simulate surviving-side capacity after upgrading a subset of members
    def surviving_capacity(side: str, upgrade_members: set, drawn: float):
        """
        After losing `side` (A or B), remaining capacity = sum of surviving side PSUs.
        Uses explicit p["side"] field when present (C9606R), otherwise slot suffix.
        """
        surviving_side = "B" if side == "A" else "A"
        total = 0.0
        for mem, mem_psus in by_member.items():
            for p in mem_psus:
                if not p["ok"]:
                    continue
                # Use explicit side field if present (C9606R), else slot suffix
                psu_side = p.get("side", "").upper() or (
                    str(p["slot"])[-1].upper() if str(p["slot"])[-1].upper() in ("A","B") else ""
                )
                if psu_side != surviving_side:
                    continue
                w = p["capacity_w"]
                if mem in upgrade_members:
                    upgraded = next_tier_w(w)
                    w = float(upgraded[0]) if upgraded else w
                total += w
        return total - drawn

    # ── Single PSU failure fix ────────────────────────────────────────────────
    if single_needs_hw:
        all_op    = [p for ml in by_member.values() for p in ml if p["ok"]]
        max_psu_w = max((p["capacity_w"] for p in all_op), default=0)

        if is_stack:
            for member, member_psus in sorted(by_member.items()):
                op_psus = [p for p in member_psus if p["ok"]]
                max_w   = max(p["capacity_w"] for p in op_psus)
                if max_w < max_psu_w:
                    continue
                nt = next_tier_w(max_w)
                if nt:
                    slots_str = " + ".join(str(p["slot"]) for p in op_psus)
                    rem.append(f"SW{member}: upgrade {slots_str} → {nt[1]} ({nt[0]}W)")
                else:
                    slots_str = " + ".join(str(p["slot"]) for p in op_psus)
                    rem.append(f"SW{member}: {slots_str} already at max tier — reduce load on this member")
        else:
            for member, member_psus in sorted(by_member.items()):
                op_psus = [p for p in member_psus if p["ok"]]
                max_w   = max(p["capacity_w"] for p in op_psus)
                nt = next_tier_w(max_w)
                if nt:
                    slots_str = " + ".join(str(p["slot"]) for p in op_psus)
                    rem.append(f"SW{member}: upgrade {slots_str} → {nt[1]} ({nt[0]}W){c9200_note}")
                else:
                    slots_str = " + ".join(str(p["slot"]) for p in op_psus)
                    rem.append(f"SW{member}: {slots_str} already at max tier — reduce load on this switch")

    # ── Side loss fix — check if upgrading surviving side covers draw ─────────
    from itertools import combinations as _combos

    # Build a mismatch-corrected view of by_member — the side-loss solver should
    # account for PSUs that are already being replaced as part of mismatch fixes,
    # so it doesn't recommend additional upgrades that those swaps already cover.
    by_member_corrected: dict = defaultdict(list)
    for mem, mem_psus in by_member.items():
        corrected = []
        op_psus   = [p for p in mem_psus if p["ok"]]
        watts_set = set(p["capacity_w"] for p in op_psus)
        if len(watts_set) > 1:
            # This member has a mismatch — simulate replacing low PSUs with max wattage
            max_w = max(watts_set)
            for p in mem_psus:
                cp = dict(p)
                if cp["ok"] and cp["capacity_w"] < max_w:
                    cp["capacity_w"] = max_w  # post-replacement wattage
                corrected.append(cp)
        else:
            corrected = [dict(p) for p in mem_psus]
        by_member_corrected[mem] = corrected

    def surviving_capacity_corrected(side: str, upgrade_members: set, drawn: float):
        surviving_side = "B" if side == "A" else "A"
        total = 0.0
        for mem, mem_psus in by_member_corrected.items():
            for p in mem_psus:
                if not p["ok"]:
                    continue
                psu_side = p.get("side", "").upper() or (
                    str(p["slot"])[-1].upper() if str(p["slot"])[-1].upper() in ("A","B") else ""
                )
                if psu_side != surviving_side:
                    continue
                w = p["capacity_w"]
                if mem in upgrade_members:
                    upgraded = next_tier_w(w)
                    w = float(upgraded[0]) if upgraded else w
                total += w
        return total - drawn

    def _psu_side(p: dict) -> str:
        """Return the A/B side for a PSU using explicit field or slot suffix."""
        s = p.get("side", "").upper()
        if s in ("A", "B"):
            return s
        last = str(p["slot"])[-1].upper()
        return last if last in ("A", "B") else ""

    for side, side_high in (("A", a_loss_high), ("B", b_loss_high)):
        if not side_high:
            continue

        surviving = "B" if side == "A" else "A"
        upgradeable = [
            m for m, ml in by_member_corrected.items()
            if any(_psu_side(p) == surviving and p["ok"] and next_tier_w(p["capacity_w"])
                   for p in ml)
        ]

        # Current surviving-side headroom after mismatch fixes applied
        current_headroom = surviving_capacity_corrected(side, set(), drawn_w)

        # Require at least 10% of draw as minimum safe headroom
        min_safe = drawn_w * 0.10
        if current_headroom >= min_safe:
            # Already has sufficient headroom after mismatch fixes — skip
            continue

        solution_found = False
        for size in range(1, len(upgradeable) + 1):
            for combo in _combos(upgradeable, size):
                h = surviving_capacity_corrected(side, set(combo), drawn_w)
                if h >= min_safe:
                    for mem in sorted(combo):
                        sur_psus = [
                            p for p in by_member_corrected[mem]
                            if p["ok"] and _psu_side(p) == surviving
                        ]
                        if not sur_psus:
                            continue
                        max_w = max(p["capacity_w"] for p in sur_psus)
                        nt    = next_tier_w(max_w)
                        if nt:
                            slots_str = " + ".join(str(p["slot"]) for p in sur_psus)
                            rem.append(
                                f"[{side}-side loss fix] SW{mem}: upgrade {slots_str} → {nt[1]} ({nt[0]}W)"
                            )
                    no_change = [m for m in member_list if m not in combo]
                    if no_change:
                        rem.append(
                            f"[{side}-side loss fix] SW{', '.join(no_change)}: no change needed"
                        )
                    solution_found = True
                    break
            if solution_found:
                break

        if not solution_found:
            rem.append(
                f"[{side}-side loss] No PSU upgrade combination can cover draw — "
                "review A/B power source resilience accordingly"
            )

    if worst_scenario in ("LOW",) and not rem:
        pass  # mismatch/slot B actions already handled above

    return " | ".join(rem) if rem else ""


def parse_power_supply(detail_out: str, env_out: str = "", inline_out: str = "") -> dict:
    """
    Parse PSU capacity and draw across platform types.

    Priority order:
      1. "show power detail" — stacked Cat9300/9500 (StackPower)
         Uses the per-PSU table for individual PSU data and the
         'Power Summary' block for system-level capacity/draw.
      2. "show environment power" Built-In line — C9200CX fixed platform
         Draw comes from "show power inline" module summary.
      3. Legacy "Power Supply N : Normal XXXW" format.
    """
    result = {
        "psus": [],
        "total_capacity_w": 0.0,
        "drawn_w": 0.0,
        "remaining_w": 0.0,
        "psu_count": 0,
        "operational_psu_count": 0,
        "non_redundant": False,
        "fiber_switch": False,
    }

    # ── Pattern A: C9300 per-PSU table ────────────────────────────────────────
    # e.g.   1A  PWR-C1-1100WAC-P   DCC123...   OK   Good  Good  1100
    psu_table_re = re.compile(
        r"^\s*(\d+)([A-Z])\s+\S+\s+\S+\s+(OK|Good|Normal|Failed|Not Present|Absent)\s+\w+\s+\w+\s+([\d.]+)",
        re.MULTILINE | re.IGNORECASE,
    )

    # ── Pattern A2: C9500 / C9606R Switch:N / PSx format ─────────────────────
    # C9500:  PS0/PS1  + no draw data
    # C9606R: PS1-PS4  + draw from Power Summary
    #
    # C9500:   PS0     C9K-PWR-1600WAC-R     AC    1600 W    ok    ...
    # C9606R:  PS1     C9600-PWR-2KWAC       ac    1050 W    active  ...
    c9500_switch_re = re.compile(r"^Switch:(\d+)", re.MULTILINE)
    c9500_psu_re    = re.compile(
        r"^\s*(PS\d+)\s+\S+\s+\S+\s+([\d.]+)\s*W\s+(ok|good|active|failed|not present|absent)",
        re.MULTILINE | re.IGNORECASE,
    )
    # C9606R Power Summary: System Power   2690    4020
    c9600_summary_re = re.compile(
        r"^System Power\s+([\d.]+)\s+([\d.]+)\s*$",
        re.MULTILINE | re.IGNORECASE,
    )

    # ── Pattern B: Power Summary block (C9300 stacked) ────────────────────────
    power_summary_re = re.compile(
        r"^System Power\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
        re.MULTILINE | re.IGNORECASE,
    )

    # ── Pattern C: C9200CX Built-In line ──────────────────────────────────────
    builtin_re = re.compile(r"Built-In\s+.*?([\d.]+)\s*\(w\)", re.IGNORECASE)

    # ── Pattern D: Legacy "Power Supply N" ────────────────────────────────────
    legacy_psu_re = re.compile(
        r"Power Supply\s+(\d+)\s*[:\-]\s*(\S+).*?([\d.]+)\s*W",
        re.IGNORECASE | re.MULTILINE,
    )

    # ── Fallback summary patterns ─────────────────────────────────────────────
    total_re     = re.compile(r"Total\s+(?:Available\s+)?Power\s*[:\-]\s*([\d.]+)", re.IGNORECASE)
    used_re      = re.compile(r"(?:Used|Consumed|Draw(?:n)?)\s+Power\s*[:\-]\s*([\d.]+)", re.IGNORECASE)
    remaining_re = re.compile(r"Remaining\s+Power\s*[:\-]\s*([\d.]+)", re.IGNORECASE)

    # ── show power inline header (3560CX / C9200CX) ───────────────────────────
    # e.g.  Available:240.0(w)  Used:106.2(w)  Remaining:133.8(w)
    inline_summary_re = re.compile(
        r"Available\s*:\s*([\d.]+)\s*\(w\).*?Used\s*:\s*([\d.]+)\s*\(w\).*?Remaining\s*:\s*([\d.]+)\s*\(w\)",
        re.IGNORECASE,
    )

    # ── show power inline module summary (stacked C9300) ─────────────────────
    # e.g.   1    240.0    61.6    178.4
    inline_module_re = re.compile(
        r"^\s*\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$", re.MULTILINE
    )

    # ── Step 1: Try C9500/C9606R Switch:N/PSx format ─────────────────────────
    c9500_switches = c9500_switch_re.findall(detail_out or "")
    if not c9500_switches:
        c9500_switches = c9500_switch_re.findall(env_out or "")
    c9500_src = detail_out if c9500_switch_re.search(detail_out or "") else env_out

    if c9500_switches and c9500_src:
        blocks  = re.split(r"^Switch:\d+", c9500_src, flags=re.MULTILINE)
        sw_nums = c9500_switches

        # Detect platform by PSU label style:
        # C9606R uses PS1-PS4 + C9600-PWR model, C9500 uses PS0/PS1
        is_c9606r = bool(re.search(r"^\s*PS[1-4]\s+C9600-PWR", c9500_src,
                                    re.MULTILINE | re.IGNORECASE))

        # C9606R: each Switch: block is an independent chassis — parse separately
        # Note: show power detail on C9606R emits Switch:N twice per chassis
        # (once for PSU table, once for module table). Use unique switch numbers
        # and find the block containing PSU data (has PS1/PS2/PS3/PS4 lines).
        if is_c9606r:
            result["chassis"] = []
            seen_sw = set()
            all_blocks = re.split(r"(?=^Switch:\d+)", c9500_src, flags=re.MULTILINE)
            for block in all_blocks:
                sw_m = re.match(r"^Switch:(\d+)", block)
                if not sw_m:
                    continue
                sw_num = sw_m.group(1)
                # Only process the block that has PSU entries (skip module-only blocks)
                if not c9500_psu_re.search(block):
                    continue
                if sw_num in seen_sw:
                    continue
                seen_sw.add(sw_num)
                chassis_psus = []
                for psu_m in c9500_psu_re.finditer(block):
                    ps_label = psu_m.group(1).upper()
                    watts    = float(psu_m.group(2))
                    status   = psu_m.group(3)
                    ok       = status.lower() in ("ok", "good", "active")
                    ps_num   = int(re.search(r'\d+', ps_label).group())
                    side     = "A" if ps_num <= 2 else "B"
                    chassis_psus.append({
                        "slot": f"{sw_num}{ps_label}",
                        "capacity_w": watts,
                        "status": status,
                        "ok": ok,
                        "side": side,
                    })
                m_sum        = c9600_summary_re.search(block)
                chassis_draw = float(m_sum.group(1)) if m_sum else 0.0
                result["chassis"].append({
                    "sw_num":           sw_num,
                    "psus":             chassis_psus,
                    "drawn_w":          chassis_draw,
                    "total_capacity_w": sum(p["capacity_w"] for p in chassis_psus if p["ok"]),
                })
            # Populate top-level result from first chassis for compatibility
            if result["chassis"]:
                first = result["chassis"][0]
                result["psus"]          = first["psus"]
                result["drawn_w"]       = first["drawn_w"]
                result["fiber_switch"]  = False
                result["multi_chassis"] = True
        else:
            for sw_num, block in zip(sw_nums, blocks[1:]):
                for psu_m in c9500_psu_re.finditer(block):
                    ps_label = psu_m.group(1).upper()
                    watts    = float(psu_m.group(2))
                    status   = psu_m.group(3)
                    ok       = status.lower() in ("ok", "good", "active")
                    side     = "A" if ps_label == "PS0" else "B"
                    result["psus"].append({
                        "slot": f"{sw_num}{side}",
                        "capacity_w": watts,
                        "status": status,
                        "ok": ok,
                        "side": side,
                    })
            result["fiber_switch"] = True
            result["drawn_w"]      = 0.0

    # ── Step 1b: Try C9300 per-PSU table ─────────────────────────────────────
    if not result["psus"]:
        found_psus = psu_table_re.findall(detail_out)
        if found_psus:
            for sw, slot, status, watts in found_psus:
                ok = status.lower() in ("ok", "good", "normal")
                result["psus"].append({
                    "slot": f"{sw}{slot}",
                    "capacity_w": float(watts),
                    "status": status,
                    "ok": ok,
                })

    # ── Step 2: Get draw from Power Summary ───────────────────────────────────
    # Use the Total row (System + PoE combined) for the most accurate draw figure.
    #
    # Stacked format has 3 data cols:   Total   <Allocated>  <Consumed>  <Available>
    # Standalone format has 2 data cols: Total   <Used/Budget>  <Available>
    #
    # We detect stacked by checking if "System Power" has 3 numeric columns.
    # Standalone "Used" column is budget allocation not actual draw — skip it.

    # Stacked: System Power   1145   352   1510  (3 cols = Allocated/Consumed/Available)
    stacked_system_re = re.compile(
        r"^System Power\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", re.MULTILINE | re.IGNORECASE
    )
    # Stacked: Total   2685   942   5830
    stacked_total_re = re.compile(
        r"^Total\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", re.MULTILINE | re.IGNORECASE
    )
    # Standalone: Total   2267   6215  (2 cols = Used/Available) — but Used = budget+PoE
    # We'll parse this too since it's more reliable than module instantaneous
    standalone_total_re = re.compile(
        r"^Total\s+([\d.]+)\s+([\d.]+)\s*$", re.MULTILINE | re.IGNORECASE
    )

    m_stacked_sys   = stacked_system_re.search(detail_out)
    m_stacked_total = stacked_total_re.search(detail_out)
    m_standalone    = standalone_total_re.search(detail_out)

    if m_stacked_total:
        # Stacked: use Total Consumed (col 2) — system + PoE combined
        result["drawn_w"] = float(m_stacked_total.group(2))
    elif m_standalone:
        # Standalone SP-PS: Total Used col includes system + PoE allocation
        # This is budget not actual, but it's the best available on this platform
        result["drawn_w"] = float(m_standalone.group(1))

    # ── Step 2b: Parse per-module instantaneous (stored per-PSU, not used for draw)
    # Module instantaneous is unreliable — known Cisco bug causes rollover values
    # like 4294938W. We still store it per-PSU for reference but cap at 2000W/module.
    module_re = re.compile(
        r"^\s*(\d+)\s+\S+\s+\d+\s+\S+\s+([\d.]+)\s+([\d.]+)",
        re.MULTILINE,
    )
    module_instant_total = 0.0
    found_modules        = False
    for m in module_re.finditer(detail_out):
        mod_num   = int(m.group(1))
        budget_w  = float(m.group(2))
        instant_w = float(m.group(3))
        # Cap at 2000W to filter known Cisco counter rollover bug
        if instant_w <= 2000:
            module_instant_total += instant_w
            found_modules = True
        for p in result["psus"]:
            slot_m = re.match(r"^(\d+)", str(p["slot"]))
            if slot_m and int(slot_m.group(1)) == mod_num:
                p["module_budget_w"]  = budget_w
                p["module_instant_w"] = instant_w if instant_w <= 2000 else None

    # If no Power Summary found (e.g. very old IOS-XE) fall back to module sum
    if not result["drawn_w"] and found_modules:
        result["drawn_w"] = module_instant_total

    # ── Step 3: If no PSU table found, try env_out / inline ───────────────────
    if not result["psus"]:
        m_builtin = builtin_re.search(env_out)
        if m_builtin:
            watts = float(m_builtin.group(1))
            result["psus"].append({"slot": "Built-In", "capacity_w": watts, "status": "Built-In", "ok": True})
            result["non_redundant"] = True
        else:
            # 3560CX and similar — inline-only, capacity from Available line
            m_inline_sum = inline_summary_re.search(inline_out or "")
            if m_inline_sum:
                avail_w = float(m_inline_sum.group(1))
                used_w  = float(m_inline_sum.group(2))
                result["psus"].append({"slot": "Built-In", "capacity_w": avail_w, "status": "Built-In", "ok": True})
                result["non_redundant"] = True
                result["drawn_w"]       = used_w
                result["remaining_w"]   = avail_w - used_w
            else:
                found_legacy = legacy_psu_re.findall(env_out)
                for slot, status, watts in found_legacy:
                    ok = status.lower() in ("normal", "ok", "good", "present")
                    result["psus"].append({"slot": str(slot), "capacity_w": float(watts), "status": status, "ok": ok})

    # ── Step 4: Capacity = raw sum of operational PSU watts (no StackPower pool)
    if result["psus"]:
        result["total_capacity_w"] = sum(p["capacity_w"] for p in result["psus"] if p["ok"])

    # ── Step 5: Fill draw if still missing ────────────────────────────────────
    if not result["drawn_w"]:
        for src in (detail_out, env_out):
            m_used = used_re.search(src)
            if m_used:
                result["drawn_w"] = float(m_used.group(1))
                break
        if not result["drawn_w"] and inline_out:
            modules = inline_module_re.findall(inline_out)
            if modules:
                result["drawn_w"] = sum(float(m[1]) for m in modules)

    # ── Step 6: Remaining = raw capacity minus draw ───────────────────────────
    if result["total_capacity_w"] and result["drawn_w"] is not None:
        result["remaining_w"] = result["total_capacity_w"] - result["drawn_w"]

    result["psu_count"]             = len(result["psus"])
    result["operational_psu_count"] = sum(1 for p in result["psus"] if p["ok"])

    return result


def _severity_rank(label: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "DEGRADED": 1, "MEDIUM": 2, "LOW": 3, "BUILT-IN PSU": 4, "OK": 5, "UNKNOWN": 6}.get(label, 99)


def _headroom_severity(headroom_w: float, total_w: float) -> str:
    """Translate post-failure headroom into a severity label."""
    if headroom_w < 0:
        return "CRITICAL"
    if total_w > 0 and headroom_w < (total_w * 0.10):
        return "MEDIUM"
    return "OK"


def evaluate_psu(data: dict) -> dict:
    """
    Produces a three-scenario power analysis:

      Scenario 1 — Single PSU failure (worst case across all members)
      Scenario 2 — Full A-side UPS loss (all xA PSUs fail simultaneously)
      Scenario 3 — Full B-side UPS loss (all xB PSUs fail simultaneously)

    Overall severity is the worst across all three scenarios.
    Each scenario gets its own note line for easy identification.

    Severity scale:
      CRITICAL — currently oversubscribed OR scenario results in immediate oversubscription
      HIGH     — a failure scenario would cause oversubscription
      MEDIUM   — headroom after failure is under 10% of total capacity
      LOW      — no redundancy (single PSU) or same-member PSU mismatch
      OK       — all scenarios pass with healthy headroom
    """
    from collections import defaultdict

    r = {
        "currently_over":    False,
        "n1_would_be_over":  False,
        "n1_headroom_w":     None,
        "status_label":      "UNKNOWN",
        "scenario_severity": {},   # {"single_psu": "MEDIUM", "a_side": "OK", "b_side": "HIGH"}
        "notes":             [],
    }

    total         = data["total_capacity_w"]
    drawn         = data["drawn_w"]
    psus          = data["psus"]
    op_count      = data["operational_psu_count"]
    non_redundant = data.get("non_redundant", False)
    fiber_switch  = data.get("fiber_switch", False)

    # ── Fiber switch (C9500 no-PoE) — report PSU health only, skip draw checks ─
    if fiber_switch:
        failed_psus = [p for p in psus if not p["ok"]]
        if failed_psus:
            slots = ", ".join(str(p["slot"]) for p in failed_psus)
            r["notes"].append(f"OFFLINE PSU: {slots} — status reported as failed/not present")
            r["status_label"] = "DEGRADED"
        else:
            r["notes"].append(
                f"Fiber switch — {op_count}/{len(psus)} PSUs operational, "
                f"no PoE draw data available on this platform"
            )
            r["status_label"] = "OK"
        return r

    if total <= 0:
        r["notes"].append("Could not parse PSU capacity — manual review needed")
        return r

    # drawn_w can legitimately be zero (no PoE devices connected)

    # ── Current state ─────────────────────────────────────────────────────────
    if drawn > total:
        r["currently_over"] = True
        r["notes"].append(
            f"CURRENTLY OVERSUBSCRIBED: drawing {drawn:.0f}W vs {total:.0f}W capacity"
        )

    # ── Non-redundant platform (single built-in PSU) ──────────────────────────
    if non_redundant or op_count <= 1:
        r["notes"].append(
            f"Non-redundant platform (single PSU) — any failure is total loss | "
            f"headroom: {total - drawn:.0f}W"
        )
        r["status_label"] = "CRITICAL" if r["currently_over"] else "BUILT-IN PSU"
        return r

    # ── Group PSUs by member number and side (A/B) ────────────────────────────
    # C9300 slots: "1A", "2B" — side from second char
    # C9606R slots: "1PS1", "1PS2" etc — side from explicit p["side"] field
    by_member: dict = defaultdict(list)
    a_side_psus: list = []
    b_side_psus: list = []

    for p in psus:
        if not p["ok"]:
            continue
        slot = str(p["slot"])
        # Use explicit side field if present (C9606R), otherwise parse from slot
        if "side" in p:
            member = re.match(r"^(\d+)", slot).group(1) if re.match(r"^(\d+)", slot) else "1"
            side   = p["side"].upper()
        else:
            m = re.match(r"^(\d+)([A-Za-z])", slot)
            if not m:
                continue
            member = m.group(1)
            side   = m.group(2).upper()
        by_member[member].append(p)
        if side == "A":
            a_side_psus.append(p)
        elif side == "B":
            b_side_psus.append(p)

    scenario_severities = []

    def _fmt_headroom(headroom: float, capacity: float) -> str:
        """Format headroom string with context on severity."""
        if headroom < 0:
            deficit = abs(int(headroom))
            if deficit <= 50:
                return f"OVER by {deficit}W (PoE shedding likely — switch stays up)"
            return f"OVER by {deficit}W"
        if headroom == 0:
            return "exactly at capacity — surviving but no buffer"
        pct = (headroom / capacity * 100) if capacity > 0 else 0
        if pct < 10:
            return f"{int(headroom)}W headroom ({pct:.0f}% — within 10% threshold)"
        return f"{int(headroom)}W headroom"

    # ── Scenario 1: Single PSU failure (worst case) ───────────────────────────
    # Remaining capacity = total raw PSU watts minus the failed PSU's watts
    worst_single_headroom = None
    worst_single_note     = ""
    for psu in psus:
        if not psu["ok"]:
            continue
        cap_after = total - psu["capacity_w"]
        headroom  = cap_after - drawn
        if worst_single_headroom is None or headroom < worst_single_headroom:
            worst_single_headroom = headroom
            worst_single_note = (
                f"Losing {psu['slot']} ({psu['capacity_w']:.0f}W) → "
                f"{cap_after:.0f}W remaining vs {drawn:.0f}W draw → "
                f"{_fmt_headroom(headroom, cap_after)}"
            )

    if worst_single_headroom is not None:
        r["n1_headroom_w"] = worst_single_headroom
        sev = "HIGH" if worst_single_headroom < 0 else _headroom_severity(worst_single_headroom, total)
        if sev in ("HIGH", "CRITICAL"):
            r["n1_would_be_over"] = True
        r["scenario_severity"]["single_psu"] = sev
        scenario_severities.append(sev)
        r["notes"].append(f"[Single PSU failure — {sev}] {worst_single_note}")

    # ── Scenario 2: Full A-side loss ──────────────────────────────────────────
    # Remaining capacity = sum of B-side PSU watts only
    if a_side_psus:
        b_raw     = sum(p["capacity_w"] for p in b_side_psus)
        headroom  = b_raw - drawn
        sev = "HIGH" if headroom < 0 else _headroom_severity(headroom, total)
        r["scenario_severity"]["a_side_loss"] = sev
        scenario_severities.append(sev)
        r["notes"].append(
            f"[A-side loss ({len(a_side_psus)} PSUs) — {sev}] "
            f"B-side raw capacity {b_raw:.0f}W vs {drawn:.0f}W draw → "
            f"{_fmt_headroom(headroom, b_raw)}"
        )
    else:
        r["notes"].append("[A-side loss] No A-side PSUs identified — skipped")

    # ── Scenario 3: Full B-side loss ──────────────────────────────────────────
    # Remaining capacity = sum of A-side PSU watts only
    if b_side_psus:
        a_raw     = sum(p["capacity_w"] for p in a_side_psus)
        headroom  = a_raw - drawn
        sev = "HIGH" if headroom < 0 else _headroom_severity(headroom, total)
        r["scenario_severity"]["b_side_loss"] = sev
        scenario_severities.append(sev)
        r["notes"].append(
            f"[B-side loss ({len(b_side_psus)} PSUs) — {sev}] "
            f"A-side raw capacity {a_raw:.0f}W vs {drawn:.0f}W draw → "
            f"{_fmt_headroom(headroom, a_raw)}"
        )
    else:
        r["notes"].append("[B-side loss] No B-side PSUs identified — skipped")

    # ── PSU mismatch detection (same-member only) ─────────────────────────────
    has_mismatch = False
    mismatch_notes = []
    for member, member_psus in sorted(by_member.items()):
        if len(member_psus) < 2:
            continue
        watts_set = set(p["capacity_w"] for p in member_psus)
        if len(watts_set) > 1:
            detail = ", ".join(f"{p['slot']}={p['capacity_w']:.0f}W" for p in member_psus)
            mismatch_notes.append(f"SW{member} ({detail})")
            has_mismatch = True
    if has_mismatch:
        r["notes"].append("PSU MISMATCH: " + " | ".join(mismatch_notes))

    # ── Offline PSU detection ─────────────────────────────────────────────────
    has_offline = False
    offline_slots = [
        str(p["slot"]) for p in psus
        if not p["ok"] and p.get("status", "").lower() not in ("", "built-in")
    ]
    if offline_slots:
        has_offline = True
        r["notes"].append(
            f"OFFLINE PSU: {', '.join(offline_slots)} — "
            f"status reported as failed/not present"
        )

    # ── Overall severity — worst across all scenarios ─────────────────────────
    if r["currently_over"]:
        r["status_label"] = "CRITICAL"
    elif has_offline:
        r["status_label"] = "DEGRADED"
    elif scenario_severities:
        worst = sorted(scenario_severities, key=_severity_rank)[0]
        r["status_label"] = worst if worst != "OK" else ("LOW" if has_mismatch else "OK")
    elif has_mismatch:
        r["status_label"] = "LOW"
    else:
        r["status_label"] = "UNKNOWN"

    return r


# ─────────────────────────────────────────────────────────────────────────────
# Per-device worker
# ─────────────────────────────────────────────────────────────────────────────
def _make_base(host: str) -> dict:
    return {
        "host":                 host,
        "hostname":             "",
        "model":                "",
        "severity":             "",
        "status_label":         "ERROR",
        "currently_over":       False,
        "n1_would_be_over":     False,
        "total_capacity_w":     "",
        "drawn_w":              "",
        "remaining_w":          "",
        "n1_headroom_w":        "",
        "psu_count":            "",
        "operational_psu_count":"",
        "psu_mismatch":         False,
        "scenario_single_psu":  "",
        "scenario_a_side":      "",
        "scenario_b_side":      "",
        "remediation":          "",
        "notes":                "",
        "error":                "",
    }


def _build_result(base: dict, hostname: str, model: str, psu_data: dict,
                  analysis: dict, remediation: str) -> dict:
    base.update({
        "hostname":              hostname,
        "model":                 model,
        "severity":              analysis["status_label"],
        "status_label":          analysis["status_label"],
        "currently_over":        analysis["currently_over"],
        "n1_would_be_over":      analysis["n1_would_be_over"],
        "total_capacity_w":      psu_data["total_capacity_w"],
        "drawn_w":               psu_data["drawn_w"],
        "remaining_w":           psu_data["remaining_w"],
        "n1_headroom_w":         analysis["n1_headroom_w"] if analysis["n1_headroom_w"] is not None else "",
        "psu_count":             psu_data["psu_count"],
        "operational_psu_count": psu_data["operational_psu_count"],
        "psu_mismatch":          any("PSU MISMATCH" in n for n in analysis["notes"]),
        "scenario_single_psu":   analysis["scenario_severity"].get("single_psu", ""),
        "scenario_a_side":       analysis["scenario_severity"].get("a_side_loss", ""),
        "scenario_b_side":       analysis["scenario_severity"].get("b_side_loss", ""),
        "remediation":           remediation,
        "notes":                 " | ".join(analysis["notes"]),
        "error":                 "",
    })
    return base


def check_device(host: str, username: str, password: str) -> list:
    """Returns a list of result dicts — usually one, two for multi-chassis C9606R."""
    base = _make_base(host)
    try:
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=host,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
        )
        conn.enable()

        ver_out    = conn.send_command("show version",           read_timeout=30)
        detail_out = conn.send_command("show power detail",      read_timeout=60)
        env_out    = conn.send_command("show environment power",  read_timeout=30)
        inline_out = conn.send_command("show power inline",       read_timeout=30)

        conn.disconnect()

        hostname = parse_hostname(ver_out)
        model    = parse_model(ver_out)
        psu_data = parse_power_supply(detail_out, env_out, inline_out)

        # ── Multi-chassis C9606R: each Switch: block is independent ───────────
        if psu_data.get("multi_chassis") and psu_data.get("chassis"):
            results = []
            for chassis in psu_data["chassis"]:
                sw_num  = chassis["sw_num"]
                ch_base = _make_base(host)
                ch_data = {
                    "psus":                  chassis["psus"],
                    "total_capacity_w":      chassis["total_capacity_w"],
                    "drawn_w":               chassis["drawn_w"],
                    "remaining_w":           chassis["total_capacity_w"] - chassis["drawn_w"],
                    "psu_count":             len(chassis["psus"]),
                    "operational_psu_count": sum(1 for p in chassis["psus"] if p["ok"]),
                    "non_redundant":         False,
                    "fiber_switch":          False,
                }
                analysis    = evaluate_psu(ch_data)
                remediation = get_remediation(
                    model, ch_data["psus"], analysis["status_label"],
                    analysis["scenario_severity"], False,
                    drawn_w=ch_data["drawn_w"],
                )
                ch_base["hostname"] = f"{hostname} SW{sw_num}"
                results.append(_build_result(ch_base, f"{hostname} SW{sw_num}", model,
                                             ch_data, analysis, remediation))
            return results

        # ── Single device (normal path) ────────────────────────────────────────
        analysis    = evaluate_psu(psu_data)
        remediation = get_remediation(
            model, psu_data["psus"], analysis["status_label"],
            analysis["scenario_severity"], psu_data.get("non_redundant", False),
            drawn_w=psu_data["drawn_w"],
        )
        return [_build_result(base, hostname, model, psu_data, analysis, remediation)]

    except NetmikoAuthenticationException:
        base["error"] = "auth failure"
    except NetmikoTimeoutException:
        base["error"] = "timeout / unreachable"
    except Exception as e:
        err_str = str(e).strip()
        if "banner" in err_str.lower() or "eof" in err_str.lower():
            base["error"] = "SSH banner error — device may be overloaded or rejecting connections"
        else:
            base["error"] = err_str

    return [base]


# ─────────────────────────────────────────────────────────────────────────────
# Terminal output helpers
# ─────────────────────────────────────────────────────────────────────────────
STATUS_COLOUR = {
    "CRITICAL":       "\033[91m",   # red
    "HIGH":           "\033[91m",   # red
    "DEGRADED":       "\033[91m",   # red
    "MEDIUM":         "\033[93m",   # yellow
    "LOW":            "\033[94m",   # blue
    "BUILT-IN PSU":   "\033[95m",   # magenta
    "OK":             "\033[92m",   # green
    "UNKNOWN":        "\033[90m",   # grey
    "ERROR":          "\033[91m",   # red
}
RESET = "\033[0m"


def format_result(r: dict, index: int, total: int) -> str:
    host     = r["host"]
    hostname = r["hostname"] or host
    label    = r["status_label"]
    colour   = STATUS_COLOUR.get(label, "")

    lines = [f"[{index}/{total}] {hostname} ({host})"]

    if r["error"]:
        lines.append(f"  {colour}[{label}]{RESET}  {r['error']}")
        return "\n".join(lines)

    cap  = f"{r['total_capacity_w']:.0f}W" if r["total_capacity_w"] else "?"
    draw = f"{r['drawn_w']:.0f}W"          if r["drawn_w"]          else "?"
    rem  = f"{r['remaining_w']:.0f}W"      if r["remaining_w"]      else "?"

    lines.append(
        f"  {colour}[{label}]{RESET}  "
        f"Capacity: {cap}  |  Draw: {draw}  |  Remaining: {rem}  |  "
        f"PSUs: {r['operational_psu_count']}/{r['psu_count']} operational"
    )
    if r["notes"]:
        for note in r["notes"].split(" | "):
            lines.append(f"    → {note}")
    if r.get("remediation"):
        lines.append(f"    \033[96m[REMEDIATION]\033[0m {r['remediation']}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────────────────────
CSV_FIELDS = [
    "host", "hostname", "model", "severity", "status_label",
    "currently_over", "n1_would_be_over",
    "total_capacity_w", "drawn_w", "remaining_w", "n1_headroom_w",
    "psu_count", "operational_psu_count", "psu_mismatch",
    "scenario_single_psu", "scenario_a_side", "scenario_b_side",
    "remediation", "notes", "error",
]


def build_summary(results: list[dict]) -> dict:
    """Compute summary stats across all results."""
    total         = len(results)
    crit_count    = sum(1 for r in results if r["status_label"] == "CRITICAL")
    high_count    = sum(1 for r in results if r["status_label"] == "HIGH")
    deg_count     = sum(1 for r in results if r["status_label"] == "DEGRADED")
    med_count     = sum(1 for r in results if r["status_label"] == "MEDIUM")
    low_count     = sum(1 for r in results if r["status_label"] == "LOW")
    builtin_count = sum(1 for r in results if r["status_label"] == "BUILT-IN PSU")
    ok_count      = sum(1 for r in results if r["status_label"] == "OK")
    err_count     = sum(1 for r in results if r.get("error"))
    offline_count = sum(1 for r in results if r.get("notes") and "OFFLINE PSU" in r["notes"])
    mismatch_count= sum(1 for r in results if r.get("psu_mismatch"))
    any_finding   = sum(1 for r in results if r["status_label"] not in ("OK", "BUILT-IN PSU", "ERROR", "UNKNOWN"))
    unreachable   = [
        {"host": r["host"], "hostname": r.get("hostname") or r["host"], "error": r.get("error", "")}
        for r in results if r.get("error")
    ]
    return {
        "total": total, "critical": crit_count, "high": high_count,
        "degraded": deg_count, "medium": med_count, "low": low_count,
        "builtin": builtin_count, "ok": ok_count, "errors": err_count,
        "offline_psus": offline_count, "psu_mismatches": mismatch_count,
        "any_finding": any_finding, "unreachable": unreachable,
    }


def write_csv(results: list[dict], path: str) -> None:
    s = build_summary(results)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

        # Blank separator then summary counts
        f.write("\n")
        f.write("SUMMARY\n")
        f.write(f"Total Switches Checked,{s['total']}\n")
        f.write(f"CRITICAL (oversubscribed now),{s['critical']}\n")
        f.write(f"HIGH (failure = oversubscribe),{s['high']}\n")
        f.write(f"DEGRADED (PSU offline / failed),{s['degraded']}\n")
        f.write(f"MEDIUM (headroom <10%),{s['medium']}\n")
        f.write(f"LOW (mismatch / missing slot B),{s['low']}\n")
        f.write(f"BUILT-IN PSU (no upgrade path),{s['builtin']}\n")
        f.write(f"OK,{s['ok']}\n")
        f.write(f"Errors / Unreachable,{s['errors']}\n")
        f.write(f"Switches with offline PSUs,{s['offline_psus']}\n")
        f.write(f"Switches with PSU mismatches,{s['psu_mismatches']}\n")
        f.write(f"Switches with any finding,{s['any_finding']}\n")
        f.write(f"Clean switches (OK),{s['ok']}\n")

        # Unreachable device list
        if s["unreachable"]:
            f.write("\n")
            f.write("UNREACHABLE / SSH ERRORS\n")
            f.write("Host,Hostname,Error\n")
            for u in s["unreachable"]:
                f.write(f"{u['host']},{u['hostname']},{u['error']}\n")

    print(f"\n[→] Report saved to {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Credential validation
# ─────────────────────────────────────────────────────────────────────────────
def validate_credentials(targets: list[str], username: str, password: str) -> None:
    """
    Try up to AUTH_CHECK_LIMIT targets in order.
    - First successful auth → continue.
    - Auth failure on any reachable switch → exit immediately.
    - All attempted targets unreachable → warn and continue.
    """
    print(f"\n  Verifying credentials (checking up to {AUTH_CHECK_LIMIT} switches)...")
    attempted = 0
    for host in targets[:AUTH_CHECK_LIMIT]:
        attempted += 1
        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=host,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
            )
            conn.disconnect()
            print(f"  [✓] Credentials OK (verified against {host})\n")
            return
        except NetmikoAuthenticationException:
            print(f"  [✗] Authentication failed against {host} — bad username/password.")
            sys.exit(1)
        except Exception:
            print(f"  [!] {host} unreachable, trying next...")
            continue

    print(f"  [!] None of the first {attempted} switches responded — proceeding anyway.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="PSU Power Investigator — checks Cisco Catalyst switches for oversubscription, N-1 PSU failure risk, and mismatched PSUs."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file",   help="File with one switch IP per line")
    group.add_argument("-s", "--switch", metavar="IP[,IP,...]",
                       help="One or more switch IPs, comma-separated (e.g. -s 192.168.1.1,192.168.1.2,192.168.1.3)")
    parser.add_argument("-o", "--output", default=None,
                        help="CSV output path (default: auto-named)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Concurrent threads (default: {DEFAULT_THREADS})")
    args = parser.parse_args()

    if args.file:
        targets = load_targets(args.file)
    else:
        targets = [ip.strip() for ip in args.switch.split(",") if ip.strip()]
        if not targets:
            print("[!] No valid IPs provided to -s")
            sys.exit(1)

    print(f"\n  PSU Investigator")
    print(f"  Targets : {len(targets)} switch(es)")
    print(f"  Threads : {args.threads}")

    username = input("\n  Username: ").strip()
    password = getpass.getpass("  Password: ")

    # Always validate credentials against the first reachable switch before
    # launching the thread pool — regardless of whether -f or -s was used.
    validate_credentials(targets, username, password)

    all_results: list[dict] = []
    counter     = [0]
    total       = len(targets)

    print(f"[→] Checking {total} device(s)...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {
            executor.submit(check_device, host, username, password): host
            for host in targets
        }
        for future in as_completed(future_map):
            results = future.result()
            counter[0] += 1
            for result in results:
                output_str = format_result(result, counter[0], total)
                safe_print(output_str)
            all_results.extend(results)

    order = {"CRITICAL": 0, "HIGH": 1, "DEGRADED": 1, "MEDIUM": 2, "LOW": 3, "BUILT-IN PSU": 4, "OK": 5, "UNKNOWN": 6, "ERROR": 7}
    all_results.sort(key=lambda r: order.get(r["status_label"], 99))

    s = build_summary(all_results)

    print("\n" + "─" * 60)
    print(f"  Summary  ({s['total']} switches checked)")
    print(f"  {'CRITICAL  (oversubscribed now)':<34} {s['critical']}")
    print(f"  {'HIGH      (failure = oversubscribe)':<34} {s['high']}")
    print(f"  {'DEGRADED  (PSU offline / failed)':<34} {s['degraded']}")
    print(f"  {'MEDIUM    (headroom <10%)':<34} {s['medium']}")
    print(f"  {'LOW       (mismatch / missing slot B)':<34} {s['low']}")
    print(f"  {'BUILT-IN PSU  (no upgrade path)':<34} {s['builtin']}")
    print(f"  {'OK':<34} {s['ok']}")
    print(f"  {'Errors / Unreachable':<34} {s['errors']}")
    print(f"  {'─' * 36}")
    print(f"  {'Switches with offline PSUs':<34} {s['offline_psus']}")
    print(f"  {'Switches with PSU mismatches':<34} {s['psu_mismatches']}")
    print(f"  {'Switches with any finding':<34} {s['any_finding']}")
    print(f"  {'Clean switches (OK)':<34} {s['ok']}")
    if s["unreachable"]:
        print(f"\n  Unreachable / SSH errors:")
        for u in s["unreachable"]:
            print(f"    {u['host']:<20} {u['error']}")
    print("─" * 60)

    # Skip CSV if every result was an auth failure — nothing useful to save
    all_auth_failures = all(r.get("error") == "auth failure" for r in all_results)
    if all_auth_failures:
        print("\n[!] All connections failed with auth errors — no report saved.")
        sys.exit(1)

    # CSV output
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = args.output or f"psu_investigator_{ts}.csv"
    write_csv(all_results, outfile)


if __name__ == "__main__":
    main()
