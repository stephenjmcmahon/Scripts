#!/usr/bin/env python3
"""
NMC2 Management Tool
Menu-driven hardening and configuration for APC NMC2 devices.

Usage:
    python3 nmc2.py [-f targets.txt] [-s 192.168.1.1] [--dry-run]
"""

import argparse
import csv
import getpass
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

try:
    import paramiko
    from paramiko import RSAKey
    paramiko.Transport._key_info["ssh-rsa"] = RSAKey
    paramiko.Transport._key_info[b"ssh-rsa"] = RSAKey
except ImportError:
    print("ERROR: paramiko not installed. Run: pip install paramiko")
    sys.exit(1)

THREADS  = 20
SSH_PORT = 22


# ── Helpers ───────────────────────────────────────────────────────────────────
def sanitize(text):
    text = re.sub(r'(-a\d?\s+|--auth\s+)\S+',  r'\1[REDACTED]', text or "")
    text = re.sub(r'(-c\d?\s+|--crypt\s+)\S+',  r'\1[REDACTED]', text or "")
    text = re.sub(r'(-pw\s+|--password\s+)\S+', r'\1[REDACTED]', text or "")
    text = re.sub(r'(-cp\s+)\S+',                r'\1[REDACTED]', text or "")
    text = re.sub(r'(-s1\s+)\S+',                r'\1[REDACTED]', text or "")
    text = re.sub(r'(-w\s+)\S+',                 r'\1[REDACTED]', text or "")
    return text


def preview_cmds(cmds):
    """Print the exact commands that will be sent to each device."""
    print("\n  Commands to be run:")
    for cmd, description in cmds:
        # Clean up sentinel commands for display
        if cmd.startswith("__user_create__"):
            display = f"user -n <username> -pw [REDACTED] -pe Administrator -e enable"
        elif cmd.startswith("__hostname_from__"):
            domain = cmd.replace("__hostname_from__", "")
            display = f"smtp -f <hostname>@{domain}"
        elif cmd == "reboot__confirm":
            display = "reboot → YES (sent as single transmission)"
        else:
            display = sanitize(cmd)
        print(f"    {description:50s}  ->  {display}")
    print()


def send_cmd(shell, cmd, wait=3.0):
    # Only chunk user commands — they're long and hit the paste buffer limit
    # Other commands send as-is to avoid special character issues
    CHUNK = 60
    if cmd.startswith("user ") and len(cmd) > CHUNK:
        for i in range(0, len(cmd), CHUNK):
            shell.send(cmd[i:i+CHUNK])
            time.sleep(0.15)
        shell.send("\n")
    else:
        shell.send(cmd + "\n")

    output = ""
    deadline = time.time() + wait + 6
    while time.time() < deadline:
        time.sleep(0.5)
        while shell.recv_ready():
            output += shell.recv(4096).decode("utf-8", errors="replace")
        # Look for E-codes only on their own line (not inside echoed command text)
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(("E000", "E001", "E100", "E101", "E102")):
                return output
        # apc> on its own line = prompt returned = command completed
        if "\napc>" in output or "\r\napc>" in output:
            break
    return output


def make_transport(ip):
    transport = paramiko.Transport((ip, SSH_PORT))
    transport.banner_timeout = 20
    transport.handshake_timeout = 10
    transport._preferred_keys    = ["ecdsa-sha2-nistp256", "ssh-rsa"]
    transport._verify_key        = lambda host_key, sig: None
    transport._preferred_ciphers = ["aes256-ctr", "aes128-ctr", "aes256-cbc", "3des-cbc"]
    transport._preferred_kex     = [
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
    ]
    transport._preferred_macs    = [
        "hmac-sha2-256",
        "hmac-sha1",
        "hmac-md5",
    ]
    return transport


def connect(ip, username, password):
    import socket
    sock = socket.create_connection((ip, SSH_PORT), timeout=15)
    transport = paramiko.Transport(sock)
    transport.banner_timeout = 20
    transport.handshake_timeout = 10
    transport._preferred_keys    = ["ecdsa-sha2-nistp256", "ssh-rsa"]
    transport._verify_key        = lambda host_key, sig: None
    transport._preferred_ciphers = ["aes256-ctr", "aes128-ctr", "aes256-cbc", "3des-cbc"]
    transport._preferred_kex     = [
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
    ]
    transport._preferred_macs    = [
        "hmac-sha2-256",
        "hmac-sha1",
        "hmac-md5",
    ]
    transport.connect(hostkey=None, username=username, password=password)
    client = paramiko.SSHClient()
    client._transport = transport
    shell = client.invoke_shell()
    time.sleep(2)
    while shell.recv_ready():
        shell.recv(4096)
    return client, shell


def preflight(ip, username, password):
    print(f"\n[PREFLIGHT] Testing SSH to {ip}...")
    try:
        transport = make_transport(ip)
        transport.connect(hostkey=None, username=username, password=password)
        transport.close()
        print(f"[PREFLIGHT] SSH OK — credentials accepted by {ip}")
        return True
    except paramiko.AuthenticationException:
        print(f"[PREFLIGHT] FAILED — credentials rejected by {ip}")
        return False
    except Exception as e:
        print(f"[PREFLIGHT] FAILED — {e}")
        return False


# ── State reader ──────────────────────────────────────────────────────────────
def read_state(shell, cmd, wait=12):
    """
    Run a read-only state command and fully drain output including prompt.
    Waits for apc> prompt AFTER E000 to ensure full output is captured.
    """
    # Drain any stale buffer first
    time.sleep(0.2)
    while shell.recv_ready():
        shell.recv(4096)

    shell.send(cmd + "\n")
    output = ""
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.3)
        while shell.recv_ready():
            output += shell.recv(4096).decode("utf-8", errors="replace")
        # Wait for apc> prompt to appear AFTER the E000 line
        # This ensures the full response body has been received
        if "E000" in output and output.rstrip().endswith("apc>"):
            break
        if "E001" in output or "E102" in output:
            break

    # Drain again after
    time.sleep(0.3)
    while shell.recv_ready():
        shell.recv(4096)

    return output.lower()


def kv(output, key):
    """Extract value for a key from NMC read output. Returns lowercase string or None."""
    for line in output.splitlines():
        if key.lower() in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                # strip whitespace including tabs
                return parts[1].strip().strip("\t").strip().lower()
    return None


# ── Idempotent command filtering ──────────────────────────────────────────────
def filter_web(shell, desired_cmds):
    """Skip web/cipher commands already matching desired state."""
    state     = read_state(shell, "web")
    cipher_st = read_state(shell, "cipher")
    skip = []

    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "web -h disable"   and kv(state, "http:")     == "disabled": already_set = True
        elif cmd == "web -h enable"    and kv(state, "http:")      == "enabled":  already_set = True
        elif cmd == "web -s disable"   and kv(state, "https:")     == "disabled": already_set = True
        elif cmd == "web -s enable"    and kv(state, "https:")     == "enabled":  already_set = True
        elif cmd == "web -hs enable"   and kv(state, "hsts:")      == "enabled":  already_set = True
        elif cmd == "web -hs disable"  and kv(state, "hsts:")      == "disabled": already_set = True
        elif "web -mp" in cmd:
            cur = kv(state, "minimum protocol:")
            desired = cmd.split()[-1].lower()
            if cur and cur == desired: already_set = True
        elif cmd == "cipher -dh disable"    and "dh                   disabled" in cipher_st: already_set = True
        elif cmd == "cipher -rsaau disable" and "rsa authentication   disabled" in cipher_st: already_set = True
        elif cmd == "cipher -aes enable"    and "aes                  enabled" in cipher_st:  already_set = True
        elif cmd == "cipher -ecdhe enable"  and "ecdhe                enabled" in cipher_st:  already_set = True
        elif cmd == "cipher -sha1 enable"   and "sha                  enabled" in cipher_st:  already_set = True
        elif cmd == "cipher -sha2 enable"   and "sha256               enabled" in cipher_st:  already_set = True

        if already_set:
            skip.append((cmd, desc))

    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_console(shell, desired_cmds):
    state = read_state(shell, "console").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "console -t disable" and kv(state, "telnet:") == "disabled": already_set = True
        elif cmd == "console -t enable"  and kv(state, "telnet:") == "enabled":  already_set = True
        elif cmd == "console -s disable" and kv(state, "ssh:")    == "disabled": already_set = True
        elif cmd == "console -s enable"  and kv(state, "ssh:")    == "enabled":  already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_ftp(shell, desired_cmds):
    state = read_state(shell, "ftp").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "ftp -S disable" and kv(state, "service:") == "disabled": already_set = True
        elif cmd == "ftp -S enable"  and kv(state, "service:") == "enabled":  already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_snmpv1(shell, desired_cmds):
    state = read_state(shell, "snmp").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "snmp -S disable" and "snmpv1:     disabled" in state: already_set = True
        elif cmd == "snmp -S enable"  and "snmpv1:     enabled"  in state: already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_snmpv3(shell, desired_cmds):
    state = read_state(shell, "snmpv3").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        import re as _re2
        snmpv3_status = _re2.search(r"snmpv3:\s+(enabled|disabled)", state)
        snmpv3_val = snmpv3_status.group(1) if snmpv3_status else ""
        if   cmd == "snmpv3 -S disable" and snmpv3_val == "disabled": already_set = True
        elif cmd == "snmpv3 -S enable"  and snmpv3_val == "enabled":  already_set = True
        elif cmd == "snmpv3 -ac2 disable" and "index:                2" in state:
            # Check if profile 2 access is already disabled
            idx = state.find("index:                2")
            chunk = state[idx:idx+200]
            if "access:               disabled" in chunk: already_set = True
        elif cmd == "snmpv3 -ac3 disable" and "index:                3" in state:
            idx = state.find("index:                3")
            chunk = state[idx:idx+200]
            if "access:               disabled" in chunk: already_set = True
        elif cmd == "snmpv3 -ac4 disable" and "index:                4" in state:
            idx = state.find("index:                4")
            chunk = state[idx:idx+200]
            if "access:               disabled" in chunk: already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_radius(shell, desired_cmds):
    state = read_state(shell, "radius").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "radius -a local"       and "local only"          in state: already_set = True
        elif cmd == "radius -a radiusLocal" and "radius, local"       in state: already_set = True
        elif cmd == "radius -a radius"      and "radius only"         in state: already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_ipv6(shell, desired_cmds):
    state = read_state(shell, "tcpip6").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "tcpip6 -S disable" and kv(state, "ipv6:") == "disabled": already_set = True
        elif cmd == "tcpip6 -S enable"  and kv(state, "ipv6:") == "enabled":  already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_ntp(shell, desired_cmds):
    state = read_state(shell, "ntp").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if   cmd == "ntp -e enable"  and "ntp status: enabled"  in state: already_set = True
        elif cmd == "ntp -e disable" and "ntp status: disabled" in state: already_set = True
        elif cmd.startswith("ntp -p"):
            desired_ip = cmd.split()[-1]
            cur = kv(state, "primary ntp server:")
            if cur and cur == desired_ip.lower(): already_set = True
        elif cmd.startswith("ntp -s"):
            desired_ip = cmd.split()[-1]
            cur = kv(state, "secondary ntp server:")
            if cur and cur == desired_ip.lower(): already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


def filter_smtp(shell, desired_cmds):
    state = read_state(shell, "smtp").replace("	", " ")
    skip = []
    for cmd, desc in desired_cmds:
        already_set = False
        if cmd == "smtp -s 0.0.0.0":
            cur = kv(state, "server:")
            if cur and cur.strip() == "0.0.0.0": already_set = True
        elif cmd.startswith("smtp -s"):
            desired = cmd.split()[-1].strip().lower()
            cur = kv(state, "server:")
            if cur and cur.strip().lower() == desired: already_set = True
        elif cmd.startswith("smtp -p"):
            desired = cmd.split()[-1]
            cur = kv(state, "port:")
            if cur and cur.strip() == desired: already_set = True
        elif cmd.startswith("smtp -f"):
            desired = cmd.split(None, 2)[-1].lower()
            cur = kv(state, "from:")
            if cur and cur.strip().lower() == desired: already_set = True
        elif cmd.startswith("__hostname_from__"):
            # Can't pre-check hostname-based from — always let it through
            pass
        elif cmd.startswith("smtp -e"):
            desired = cmd.split()[-1].lower()
            cur = kv(state, "encryption:")
            if cur and cur.strip().lower() == desired: already_set = True
        elif cmd == "smtp -a enable"  and kv(state, "auth:") == "enabled":  already_set = True
        elif cmd == "smtp -a disable" and kv(state, "auth:") == "disabled": already_set = True
        if already_set:
            skip.append((cmd, desc))
    filtered = [(c, d) for c, d in desired_cmds if (c, d) not in skip]
    skipped  = [(c, d) for c, d in desired_cmds if (c, d) in skip]
    return filtered, skipped


# Maps action label prefix to filter function
STATE_FILTERS = {
    "web":      filter_web,
    "console":  filter_console,
    "ftp":      filter_ftp,
    "snmpv1":   filter_snmpv1,
    "snmpv3":   filter_snmpv3,
    "radius":   filter_radius,
    "ipv6":     filter_ipv6,
    "ntp":      filter_ntp,
    "smtp":     filter_smtp,
}


# ── Command builders ──────────────────────────────────────────────────────────
def build_snmpv3_configure(cfg):
    """Configure a specific SNMPv3 profile (1-4)."""
    n = cfg['profile']
    return [
        ("snmpv3 -S enable",
         "Enable SNMPv3 globally"),
        (f"snmpv3 -u{n} {cfg['snmp_user']} -ap{n} sha -pp{n} aes "
         f"-a{n} {cfg['snmp_auth']} -c{n} {cfg['snmp_priv']} "
         f"-ac{n} enable -n{n} {cfg['nms_ip']}",
         f"Configure profile {n} (SHA auth, AES priv, lock to NMS IP)"),
    ]


def build_snmpv3_rotate(cfg):
    """Rotate passphrases on a specific SNMPv3 profile."""
    n = cfg['profile']
    return [
        (f"snmpv3 -a{n} {cfg['snmp_auth']} -c{n} {cfg['snmp_priv']}",
         f"Rotate SNMPv3 auth + priv passphrases (profile {n})"),
    ]


def build_snmpv3_disable_profile(cfg):
    """Disable access on a specific SNMPv3 profile."""
    n = cfg['profile']
    return [
        (f"snmpv3 -ac{n} disable", f"Disable SNMPv3 profile {n}"),
    ]


def build_ntp(cfg):
    return [
        ("ntp -e enable",                  "Enable NTP"),
        (f"ntp -p {cfg['ntp_primary']}",   "Set primary NTP server"),
        (f"ntp -s {cfg['ntp_secondary']}", "Set secondary NTP server"),
        ("ntp -u",                         "Force NTP sync now"),
    ]


def build_user_superuser(cfg):
    return [
        (f"user -n apc -cp {cfg['current_pass']} -pw {cfg['superuser_pass_new']}",
         "Rotate Super User (apc) password"),
    ]


def build_user_timeout(cfg):
    return [
        (f"user -n {cfg['nmc_user']} -st {cfg['session_timeout']}",
         f"Set session timeout to {cfg['session_timeout']} min for '{cfg['nmc_user']}'"),
    ]


def build_user_lockout(cfg):
    return [
        (f"userdflt -la {cfg['lockout_attempts']}",
         f"Lock account after {cfg['lockout_attempts']} failed attempts"),
        (f"userdflt -lp {cfg['lockout_duration']}",
         f"Lockout duration: {cfg['lockout_duration']} min"),
    ]


def build_user_subaccounts(cfg):
    return [
        (f"user -n {acct} -e {cfg['subaccount_action']}",
         f"{cfg['subaccount_action'].capitalize()} account '{acct}'")
        for acct in cfg['subaccounts']
    ]


def build_dns(cfg):
    cmds = []
    if cfg.get('dns_primary'):
        cmds.append((f"dns -p {cfg['dns_primary']}", "Set primary DNS server"))
    if cfg.get('dns_secondary'):
        cmds.append((f"dns -s {cfg['dns_secondary']}", "Set secondary DNS server"))
    if cfg.get('dns_domain'):
        cmds.append((f"dns -d {cfg['dns_domain']}", "Set domain name"))
    return cmds


# ── Execution engine ──────────────────────────────────────────────────────────
def run_commands(ip, username, password, cmds, action_label, dry_run):
    result = {
        "ip":           ip,
        "status":       "UNKNOWN",
        "detail":       "",
        "actions_ok":   0,
        "actions_fail": 0,
        "skipped":      0,
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if dry_run:
        result["status"]     = "DRY_RUN"
        result["detail"]     = f"Would run {len(cmds)} commands"
        result["actions_ok"] = len(cmds)
        return result

    try:
        client, shell = connect(ip, username, password)

        # NMC version check
        about_out = read_state(shell, "about", wait=15)
        if not about_out:
            client.close()
            result["status"] = "NO_RESPONSE"
            result["detail"] = "Device connected but returned no output — may be mid-reboot"
            return result
        # NMC2 runs sumx (Smart-UPS) or Symmetra APP as the application module
        about_lower = about_out.lower()
        # NMC2 app module is sumx (Smart-UPS) or sy (Symmetra)
        # Both always appear alongside aos in the about output
        is_nmc2 = ("sumx" in about_lower or "\tsy\n" in about_lower or "\tsy\r" in about_lower or "\tsu\n" in about_lower or "\tsu\r" in about_lower) and "aos" in about_lower
        if not is_nmc2:
            client.close()
            result["status"] = "SKIPPED_NMC1"
            result["detail"] = "Device identified as NMC1 — not supported"
            return result
        is_nmc3 = ("\tsu\n" in about_lower or "\tsu\r" in about_lower)

        # Idempotency — filter commands already matching desired state
        filter_key = action_label.split("_")[0]
        if filter_key in STATE_FILTERS:
            cmds, skipped = STATE_FILTERS[filter_key](shell, cmds)
            result["skipped"] = len(skipped)
            if skipped:
                skipped_names = ", ".join(d for _, d in skipped)
        else:
            skipped = []

        if not cmds:
            client.close()
            result["status"] = "ALREADY_SET"
            result["detail"] = "All settings already match desired state — no changes made"
            return result

        failures     = []
        reboot_cmds  = []

        # For NMC3 devices, replace cipher commands with web -cs equivalent
        if is_nmc3:
            swapped = []
            has_cipher_cmds = any(c.startswith("cipher") for c, d in cmds)
            for cmd, desc in cmds:
                if cmd.startswith("cipher"):
                    continue
                swapped.append((cmd, desc))
            if has_cipher_cmds:
                swapped.append(("web -cs 4", "Set cipher suite to maximum security level (NMC3)"))
            cmds = swapped

        # Resolve special sentinel commands before executing
        resolved_cmds = []
        for cmd, description in cmds:
            if cmd.startswith("__user_create__"):
                # Parse sentinel
                parts        = cmd.replace("__user_create__", "").split("||")
                new_user     = parts[0]
                new_pass     = parts[1]
                enable_mode  = parts[2] if len(parts) > 2 else "1"

                # Read current user list
                user_out = read_state(shell, "user -l")
                user_exists  = new_user.lower() in user_out
                user_enabled = False
                if user_exists:
                    # Find the line with this username and check status
                    for line in user_out.splitlines():
                        if new_user.lower() in line.lower():
                            user_enabled = "enabled" in line.lower()
                            break

                if user_exists and user_enabled:
                    # Already exists and enabled — skip
                    result["skipped"] += 1
                    result["detail"] = f"Account '{new_user}' already exists and is enabled"
                elif user_exists and not user_enabled and enable_mode == "1":
                    # Exists but disabled — just enable it
                    resolved_cmds.append((
                        f"user -n {new_user} -e enable",
                        f"Enabled existing account '{new_user}' (was disabled)"
                    ))
                else:
                    # Create fresh
                    resolved_cmds.append((
                        f"user -n {new_user} -pw {new_pass} -pe Administrator -e enable",
                        f"Created new Administrator account '{new_user}'"
                    ))

            elif cmd.startswith("__hostname_from__"):
                domain = cmd.replace("__hostname_from__", "")
                sys_out = send_cmd(shell, "system", wait=3)
                hostname = None
                for line in sys_out.splitlines():
                    if "name" in line.lower() and ":" in line:
                        hostname = line.split(":", 1)[1].strip()
                        break
                if hostname:
                    from_addr = f"{hostname}@{domain}"
                    resolved_cmds.append((f"smtp -f {from_addr}", f"Set from address to {from_addr}"))
                else:
                    failures.append(f"{description}: could not read hostname from device")
                    result["actions_fail"] += 1
            else:
                resolved_cmds.append((cmd, description))
        cmds = resolved_cmds

        for cmd, description in cmds:
            if cmd == "reboot__confirm":
                # Send reboot + YES as single transmission before connection drops
                try:
                    shell.send("reboot\n")
                    time.sleep(1)
                    shell.send("YES\n")
                    time.sleep(2)
                    result["actions_ok"] += 1
                except Exception:
                    result["actions_ok"] += 1  # Connection drop is expected
                continue
            if cmd.startswith("user"):
                wait = 15
            elif cmd.startswith("smtp"):
                wait = 10
            else:
                wait = 3
            out = send_cmd(shell, cmd, wait=wait)
            if "E000" in out or ("apc>" in out and "E0" not in out):
                result["actions_ok"] += 1
            elif "E002" in out:
                result["actions_ok"] += 1
                reboot_cmds.append(description)
            elif "E101" in out:
                pass  # Command not found — firmware variation, skip
            else:
                result["actions_fail"] += 1
                # Extract error code from output if present
                err_code = ""
                for token in out.split():
                    if token.startswith("E") and token[1:].isdigit():
                        err_code = f" ({token})"
                        break
                failures.append(f"{description}{err_code}: {sanitize(out.strip()[:120])}")

        client.close()

        reboot_note = f" | REBOOT REQUIRED for: {', '.join(reboot_cmds)}" if reboot_cmds else ""
        total_cmds  = result['actions_ok'] + result['actions_fail'] + result['skipped']

        if result["actions_fail"] == 0:
            result["status"] = "SUCCESS_REBOOT" if reboot_cmds else "SUCCESS"
            # Preserve detail set by resolver (e.g. user create action description)
            if not result["detail"]:
                if total_cmds == 1:
                    result["detail"] = f"Success{reboot_note}"
                elif result['skipped'] == 0:
                    result["detail"] = f"{result['actions_ok']} applied{reboot_note}"
                else:
                    result["detail"] = f"{result['actions_ok']} applied, {result['skipped']} already set{reboot_note}"
            elif reboot_note:
                result["detail"] += reboot_note
        else:
            result["status"] = "PARTIAL"
            if total_cmds == 1:
                err = failures[0] if failures else "unknown error"
                result["detail"] = f"Failed: {err}"
            else:
                result["detail"] = (
                    f"{result['actions_ok']} ok, {result['actions_fail']} failed: "
                    f"{'; '.join(failures[:2])}{reboot_note}"
                )

    except paramiko.AuthenticationException:
        result["status"] = "AUTH_FAILED"
        result["detail"] = "SSH authentication failed"
    except paramiko.ssh_exception.NoValidConnectionsError:
        result["status"] = "CONN_REFUSED"
        result["detail"] = "SSH connection refused"
    except paramiko.ssh_exception.IncompatiblePeer as e:
        result["status"] = "SSH_INCOMPATIBLE"
        result["detail"] = f"SSH algorithm mismatch: {e}"
    except TimeoutError:
        result["status"] = "TIMEOUT"
        result["detail"] = "SSH connection timed out"
    except Exception as e:
        result["status"] = "ERROR"
        result["detail"] = str(e)[:150]

    return result


def _reboot_nmc(ip, username, password, retries=3, retry_delay=10):
    """
    Send reboot + YES to a single device with retry logic.
    Returns (success: bool, detail: str)
    """
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            client, shell = connect(ip, username, password)
            send_cmd(shell, "reboot", wait=3)
            send_cmd(shell, "YES", wait=5)
            client.close()
            return True, f"Reboot sent (attempt {attempt})"
        except paramiko.AuthenticationException:
            return False, "AUTH_FAILED — wrong credentials"
        except paramiko.ssh_exception.NoValidConnectionsError:
            last_error = "CONN_REFUSED — SSH not accepting connections"
        except paramiko.ssh_exception.IncompatiblePeer as e:
            return False, f"SSH_INCOMPATIBLE — {e}"
        except TimeoutError:
            last_error = "TIMEOUT — SSH connection timed out"
        except EOFError:
            # Device may have already started rebooting — treat as success
            return True, f"Reboot likely sent — connection dropped immediately (attempt {attempt})"
        except Exception as e:
            last_error = f"ERROR — {str(e)[:80]}"

        if attempt < retries:
            time.sleep(retry_delay)

    return False, f"FAILED after {retries} attempts — {last_error}"


def _wait_for_device(ip, username, password, timeout=180):
    """
    Poll device via SSH until it responds or timeout expires.
    SSH_INCOMPATIBLE = device is up but uses legacy kex — treat as online.
    Returns (True, elapsed_seconds) on success, (False, timeout) on failure.
    """
    import socket as _socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            # Step 1: quick TCP check with short timeout
            sock = _socket.create_connection((ip, SSH_PORT), timeout=5)
            # Step 2: reuse socket for paramiko with short banner timeout
            transport = paramiko.Transport(sock)
            transport.banner_timeout  = 8
            transport.handshake_timeout = 8
            transport._preferred_keys    = ["ecdsa-sha2-nistp256", "ssh-rsa"]
            transport._verify_key        = lambda host_key, sig: None
            transport._preferred_ciphers = ["aes256-ctr", "aes128-ctr", "aes256-cbc", "3des-cbc"]
            transport._preferred_kex     = [
                "ecdh-sha2-nistp256",
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group-exchange-sha1",
                "diffie-hellman-group14-sha1",
            ]
            transport._preferred_macs = ["hmac-sha2-256", "hmac-sha1", "hmac-md5"]
            transport.connect(hostkey=None, username=username, password=password)
            transport.close()
            return True, int(time.time() - start)
        except paramiko.AuthenticationException:
            return True, int(time.time() - start)
        except paramiko.ssh_exception.IncompatiblePeer:
            return True, int(time.time() - start)
        except _socket.timeout:
            time.sleep(3)
        except ConnectionRefusedError:
            time.sleep(3)
        except Exception:
            time.sleep(3)
    return False, timeout


def _verify_config(ip, username, password, action_label):
    """
    Re-read relevant config after reboot and verify key settings.
    Returns (verified: bool, detail: str)
    """
    try:
        client, shell = connect(ip, username, password)
        verified = False
        detail   = "No verification rule for this action"

        label = action_label.lower()

        if "ftp" in label:
            out = read_state(shell, "ftp")
            svc = kv(out, "service:")
            if "enable" in label and svc == "enabled":
                verified, detail = True, "FTP confirmed enabled"
            elif "disable" in label and svc == "disabled":
                verified, detail = True, "FTP confirmed disabled"
            else:
                verified, detail = False, f"FTP service={svc} (unexpected)"

        elif "web" in label:
            out  = read_state(shell, "web")
            http = kv(out, "http:")
            https = kv(out, "https:")
            tls   = kv(out, "minimum protocol:")
            if "harden" in label:
                if http == "disabled" and https == "enabled" and tls == "tls1.2":
                    verified, detail = True, f"HTTP={http}, HTTPS={https}, TLS={tls}"
                else:
                    verified, detail = False, f"HTTP={http}, HTTPS={https}, TLS={tls}"
            else:
                verified, detail = True, f"HTTP={http}, HTTPS={https}, TLS={tls}"

        elif "console" in label:
            out     = read_state(shell, "console")
            telnet  = kv(out, "telnet:")
            ssh     = kv(out, "ssh:")
            if "harden" in label:
                if telnet == "disabled" and ssh == "enabled":
                    verified, detail = True, f"Telnet={telnet}, SSH={ssh}"
                else:
                    verified, detail = False, f"Telnet={telnet}, SSH={ssh}"
            else:
                verified, detail = True, f"Telnet={telnet}, SSH={ssh}"

        elif "radius" in label:
            out    = read_state(shell, "radius")
            access = kv(out, "access:")
            verified, detail = True, f"RADIUS access={access}"

        elif "snmpv1" in label:
            out  = read_state(shell, "snmp")
            v1   = "enabled" if "snmpv1:     enabled" in out else "disabled"
            verified, detail = True, f"SNMPv1={v1}"

        elif "ipv6" in label:
            out  = read_state(shell, "tcpip6")
            ipv6 = kv(out, "ipv6:")
            if "disable" in label and ipv6 == "disabled":
                verified, detail = True, "IPv6 confirmed disabled"
            elif "enable" in label and ipv6 == "enabled":
                verified, detail = True, "IPv6 confirmed enabled"
            else:
                verified, detail = False, f"IPv6={ipv6} (unexpected)"

        elif "ntp" in label:
            out    = read_state(shell, "ntp")
            status = "enabled" if "ntp status: enabled" in out else "disabled"
            verified, detail = True, f"NTP={status}"

        elif "snmpv3" in label:
            out = read_state(shell, "snmpv3")
            if "snmpv3:       enabled" in out:
                verified, detail = True, "SNMPv3 enabled"
            elif "snmpv3:       disabled" in out:
                verified, detail = False, "SNMPv3 still disabled"
            else:
                verified, detail = True, "SNMPv3 state read"

        elif "snmpv1" in label:
            out = read_state(shell, "snmp")
            v1  = "enabled" if "snmpv1:     enabled" in out else "disabled"
            verified, detail = True, f"SNMPv1={v1}"

        client.close()
        return verified, detail

    except Exception as e:
        return False, f"Verify connect failed: {str(e)[:80]}"


def _reboot_and_verify_fleet(reboot_ips, username, password, action_label, results):
    """
    Reboot all devices in reboot_ips, wait for them to come back,
    verify config, and update results in place.
    """
    print(f"\n  Rebooting {len(reboot_ips)} device(s)...")

    # Send reboot to all in parallel
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_reboot_nmc, ip, username, password): ip for ip in reboot_ips}
        for future in as_completed(futures):
            ip      = futures[future]
            ok, msg = future.result()
            tag     = "[REBOOT]  " if ok else "[REBOOT!] "
            print(f"  {tag}{ip:20s}  {msg}")

    # Poll until responsive + verify config — no flat wait, poll handles timing
    print("\n  Polling devices and verifying configuration...\n")
    result_map = {r["ip"]: r for r in results}

    verified_count = timeout_count = failed_count = 0

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(_wait_and_verify, ip, username, password, action_label, 120): ip
            for ip in reboot_ips
        }
        for future in as_completed(futures):
            ip              = futures[future]
            came_back, elapsed, verified, detail = future.result()
            r               = result_map[ip]

            if not came_back:
                r["status"] = "REBOOT_TIMEOUT"
                r["detail"] += " | REBOOT TIMEOUT — device did not respond"
                print(f"  [TIMEOUT] {ip:20s}  Did not respond within timeout")
                timeout_count += 1
            elif verified:
                r["status"] = "SUCCESS"
                r["detail"] += f" | Reboot verified: {detail}"
                print(f"  [VERIFIED]{ip:20s}  {detail}")
                verified_count += 1
            else:
                r["status"] = "VERIFY_FAILED"
                r["detail"] += f" | Reboot verify failed: {detail}"
                print(f"  [VERIFY!] {ip:20s}  Verify failed: {detail}")
                failed_count += 1

    print(f"\n  Verification complete — {verified_count} verified, {failed_count} failed, {timeout_count} timed out")


def _wait_and_verify(ip, username, password, action_label, timeout=60):
    """Wait for device to come back then verify config. Returns (came_back, elapsed, verified, detail)."""
    came_back, elapsed = _wait_for_device(ip, username, password, timeout=timeout)
    if not came_back:
        return False, elapsed, False, ""
    verified, detail = _verify_config(ip, username, password, action_label)
    return True, elapsed, verified, detail


def execute_fleet(targets, username, password, cmds, action_label, dry_run):
    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path   = os.path.join(script_dir, f"nmc2_{action_label}_{ts}.csv")

    results          = []
    success = partial = fail = 0

    print(f"[INFO] Targets : {len(targets)} device(s)")
    print(f"[INFO] Threads : {THREADS}")
    print(f"[INFO] Action  : {action_label}")
    if dry_run:
        print("[INFO] Mode    : DRY RUN — no changes will be made")
    print(f"[INFO] Output  : {csv_path}\n")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(run_commands, ip, username, password, cmds, action_label, dry_run): ip
            for ip in targets
        }
        for future in as_completed(futures):
            r      = future.result()
            status = r["status"]
            detail = sanitize(r["detail"])
            results.append(r)
            if status in ("SUCCESS", "DRY_RUN", "ALREADY_SET"):
                success += 1
                print(f"  [OK]      {r['ip']:20s}  {detail}")
            elif status == "SUCCESS_REBOOT":
                success += 1
                print(f"  [OK*]     {r['ip']:20s}  {detail}")
            elif status == "PARTIAL":
                partial += 1
                print(f"  [PARTIAL] {r['ip']:20s}  {detail}")
            elif status in ("SKIPPED_NMC1", "NO_RESPONSE"):
                print(f"  [SKIP]    {r['ip']:20s}  {detail}")
            else:
                fail += 1
                print(f"  [FAIL]    {r['ip']:20s}  {status}: {detail}")

    reboot_devices = [r["ip"] for r in results if r["status"] == "SUCCESS_REBOOT"]

    # Retry PARTIAL devices once — skip for reboot actions (drop is expected behavior)
    partial_devices = [r["ip"] for r in results if r["status"] == "PARTIAL"]
    if partial_devices and not dry_run and "reboot" not in action_label:
        print(f"\n  Retrying {len(partial_devices)} partial device(s) in 5s...")
        time.sleep(5)
        result_map = {r["ip"]: r for r in results}
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(run_commands, ip, username, password, cmds, action_label, dry_run): ip
                for ip in partial_devices
            }
            for future in as_completed(futures):
                r      = future.result()
                old_r  = result_map[r["ip"]]
                detail = sanitize(r["detail"])
                if r["status"] in ("SUCCESS", "ALREADY_SET"):
                    old_r["status"] = r["status"]
                    old_r["detail"] = r["detail"]
                    print(f"  [RETRY OK] {r['ip']:20s}  {detail}")
                elif r["status"] == "PARTIAL":
                    print(f"  [RETRY FAIL] {r['ip']:18s}  {detail}")
                else:
                    old_r["status"] = r["status"]
                    old_r["detail"] = r["detail"]
                    print(f"  [RETRY FAIL] {r['ip']:18s}  {r['status']}: {detail}")

    # Offer reboot + verify for devices that need it
    if reboot_devices and not dry_run:
        print(f"\n{'─' * 60}")
        print(f"  {len(reboot_devices)} device(s) require an NMC card reboot for changes to take effect.")
        print(f"  NOTE: Reboots the NMC management card only —")
        print(f"        UPS stays online, outlets stay live throughout.")
        print(f"  After reboot, script will verify the config was applied.")
        confirm = input(f"\n  Reboot and verify now? [y/N]: ").strip().lower()
        if confirm == "y":
            _reboot_and_verify_fleet(reboot_devices, username, password, action_label, results)
        else:
            print("  Skipped — reboot manually via menu option 10 (System > Reboot NMC card)")

    # Recalculate counters after potential status updates
    success = sum(1 for r in results if r["status"] in ("SUCCESS", "DRY_RUN", "ALREADY_SET"))
    partial = sum(1 for r in results if r["status"] == "PARTIAL")
    skipped = sum(1 for r in results if r["status"] in ("SKIPPED_NMC1", "NO_RESPONSE"))
    fail    = sum(1 for r in results if r["status"] not in (
        "SUCCESS", "DRY_RUN", "ALREADY_SET", "PARTIAL", "SKIPPED_NMC1", "NO_RESPONSE", "SUCCESS_REBOOT"
    ))

    for r in results:
        r["detail"] = sanitize(r["detail"])

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["ip", "status", "actions_ok", "actions_fail", "skipped", "detail", "timestamp"]
        )
        writer.writeheader()
        writer.writerows(sorted(results, key=lambda x: x["ip"]))

    print(f"\n{'=' * 60}")
    print(f"  Complete : {success} success, {partial} partial, {fail} failed, {skipped} skipped")
    print(f"  CSV      : {csv_path}")
    print(f"{'=' * 60}")


def _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run):
    if len(targets) > 1 and not dry_run:
        if not preflight(targets[0], nmc_user, nmc_pass):
            print("\n  Preflight failed. Check credentials and SSH access.")
            return
        confirm = input(f"\n  Preflight passed. Apply to all {len(targets)} devices? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Aborted.")
            return
    execute_fleet(targets, nmc_user, nmc_pass, cmds, label, dry_run)


# ── Menu action functions ─────────────────────────────────────────────────────
def action_web(targets, nmc_user, nmc_pass, dry_run):
    print("\n  HTTP / HTTPS Options:")
    print("    1) Disable HTTP             (blocks unencrypted web access)")
    print("    2) Enable HTTP              (allows unencrypted web access)")
    print("    3) Enable HTTPS             (allows encrypted web access)")
    print("    4) Disable HTTPS            (blocks encrypted web access)")
    print("    5) TLS & Cipher hardening   (set min TLS version, disable/enable ciphers)")
    print("    6) Harden all — safe        (disable HTTP, enable HTTPS, TLS 1.2 minimum,")
    print("                                 disable DH, enable AES/ECDHE/SHA1/SHA256)")
    print("                                 Web access preserved — see option 5 for full")
    print("                                 cipher hardening with RSA-AU warning)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        cmds  = [("web -h disable", "Disable HTTP (unencrypted web access off)")]
        label = "web_http_disable"
    elif choice == "2":
        cmds  = [("web -h enable", "Enable HTTP (unencrypted web access on)")]
        label = "web_http_enable"
    elif choice == "3":
        cmds  = [("web -s enable", "Enable HTTPS (encrypted web access on)")]
        label = "web_https_enable"
    elif choice == "4":
        cmds  = [("web -s disable", "Disable HTTPS (encrypted web access off)")]
        label = "web_https_disable"
    elif choice == "5":
        print("\n  TLS & Cipher Options:")
        print("    1) Set minimum TLS version  (valid: SSL3.0 | TLS1.0 | TLS1.1 | TLS1.2)")
        print("    2) Cipher hardening — safe  (disable DH, enable AES/ECDHE/SHA1/SHA256)")
        print("                                 Safe for all firmware — web access preserved)")
        print("    3) Cipher hardening — full  (safe set + disable RSA authentication)")
        print("                                 WARNING: breaks HTTPS web access on devices")
        print("                                 using default RSA cert — firmware v6.8.0")
        print("                                 has no SSL CLI, cannot generate ECDSA cert)")
        print("    r) Return")
        sub = input("\n  Select: ").strip()
        if sub == "1":
            tls = input("  Minimum TLS version [SSL3.0 / TLS1.0 / TLS1.1 / TLS1.2]: ").strip()
            if tls not in ("SSL3.0", "TLS1.0", "TLS1.1", "TLS1.2"):
                print("  Invalid TLS version.")
                return
            cmds  = [(f"web -mp {tls}", f"Set minimum TLS version to {tls}")]
            label = f"web_tls_min_{tls.lower().replace('.','')}"
        elif sub == "2":
            cmds = [
                ("cipher -dh disable",    "Disable DH key exchange"),
                ("cipher -aes enable",    "Enable AES cipher"),
                ("cipher -ecdhe enable",  "Enable ECDHE key exchange"),
                ("cipher -sha1 enable",   "Enable SHA1"),
                ("cipher -sha2 enable",   "Enable SHA256"),
            ]
            label = "web_ciphers_safe_harden"
        elif sub == "3":
            print()
            print("  !! WARNING !!")
            print("  Disabling RSA authentication will break HTTPS web access on any device")
            print("  using the default RSA self-signed certificate (all NMC2 out of the box).")
            print("  Firmware v6.8.0 has no SSL CLI — ECDSA cert generation not possible.")
            print("  Device will still be manageable via SSH only after this change.")
            print("  Only proceed if you have confirmed ECDSA cert is installed, or if")
            print("  SSH-only management is acceptable for these devices.")
            print()
            confirm = input("  Type YES to confirm you understand and want to proceed: ").strip()
            if confirm != "YES":
                print("  Aborted.")
                return
            cmds = [
                ("cipher -dh disable",    "Disable DH key exchange"),
                ("cipher -rsaau disable", "Disable RSA authentication (web access will break)"),
                ("cipher -aes enable",    "Enable AES cipher"),
                ("cipher -ecdhe enable",  "Enable ECDHE key exchange"),
                ("cipher -sha1 enable",   "Enable SHA1"),
                ("cipher -sha2 enable",   "Enable SHA256"),
            ]
            label = "web_ciphers_full_harden_BREAKS_HTTPS"
        elif sub in ("r", "R"):
            return
        else:
            print("  Invalid selection.")
            return
    elif choice == "6":
        cmds = [
            ("web -h disable",       "Disable HTTP (unencrypted web access off)"),
            ("web -s enable",        "Enable HTTPS (encrypted web access on)"),
            ("web -mp TLS1.2",       "Set minimum TLS version to TLS1.2"),
            ("cipher -dh disable",   "Disable DH key exchange"),
            ("cipher -aes enable",   "Enable AES cipher"),
            ("cipher -ecdhe enable", "Enable ECDHE key exchange"),
            ("cipher -sha1 enable",  "Enable SHA1"),
            ("cipher -sha2 enable",  "Enable SHA256"),
        ]
        label = "web_harden_all_safe"
    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_ftp(targets, nmc_user, nmc_pass, dry_run):
    print("\n  FTP Options:")
    print("    1) Disable FTP   (recommended — no file transfer access)")
    print("    2) Enable FTP    (allows unencrypted file transfer access)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("ftp -S disable", "Disable FTP")], "ftp_disable"
    elif choice == "2": cmds, label = [("ftp -S enable",  "Enable FTP")],  "ftp_enable"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_console(targets, nmc_user, nmc_pass, dry_run):
    print("\n  Telnet / SSH Options:")
    print("    1) Disable Telnet   (blocks unencrypted CLI access)")
    print("    2) Enable Telnet    (allows unencrypted CLI access)")
    print("    3) Enable SSH       (allows encrypted CLI access)")
    print("    4) Disable SSH      (blocks encrypted CLI access — use with caution)")
    print("    5) Harden all       (disable Telnet, enable SSH)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("console -t disable", "Disable Telnet")], "console_telnet_disable"
    elif choice == "2": cmds, label = [("console -t enable",  "Enable Telnet")],  "console_telnet_enable"
    elif choice == "3": cmds, label = [("console -s enable",  "Enable SSH")],     "console_ssh_enable"
    elif choice == "4": cmds, label = [("console -s disable", "Disable SSH")],    "console_ssh_disable"
    elif choice == "5":
        cmds  = [("console -t disable", "Disable Telnet"), ("console -s enable", "Enable SSH")]
        label = "console_harden_all"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_radius(targets, nmc_user, nmc_pass, dry_run):
    print("\n  RADIUS Options:")
    print("    1) Disable RADIUS         (local auth only)")
    print("    2) RADIUS + local fallback (try RADIUS first, fall back to local if unreachable)")
    print("    3) RADIUS only            (local auth disabled — RADIUS must be reachable)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("radius -a local",      "Set auth: local only")],                "radius_disable"
    elif choice == "2": cmds, label = [("radius -a radiusLocal", "Set auth: RADIUS + local fallback")],  "radius_local_fallback"
    elif choice == "3": cmds, label = [("radius -a radius",      "Set auth: RADIUS only")],              "radius_only"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_snmpv1(targets, nmc_user, nmc_pass, dry_run):
    print("\n  SNMPv1 Options:")
    print("    1) Disable SNMPv1   (recommended — use SNMPv3 for polling)")
    print("    2) Enable SNMPv1    (allows unauthenticated SNMP polling)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("snmp -S disable", "Disable SNMPv1")], "snmpv1_disable"
    elif choice == "2": cmds, label = [("snmp -S enable",  "Enable SNMPv1")],  "snmpv1_enable"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def _get_profile():
    """Prompt for a valid profile number (1-4). Returns int or None."""
    raw = input("  Profile number [1-4]: ").strip()
    if raw in ("1", "2", "3", "4"):
        return int(raw)
    print("  Invalid profile number. Must be 1, 2, 3, or 4.")
    return None


def action_snmpv3(targets, nmc_user, nmc_pass, dry_run):
    print("\n  SNMPv3 Options:")
    print("    1) Enable SNMPv3 globally")
    print("    2) Disable SNMPv3 globally")
    print("    3) Configure a profile     (set user, SHA auth, AES priv, NMS IP for profile 1-4)")
    print("    4) Disable a profile       (revoke access on a specific profile)")
    print("    5) Rotate passphrases      (update auth + priv on a specific profile)")
    print("    6) Clear a profile         (reset to factory defaults + disable access)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        cmds  = [("snmpv3 -S enable", "Enable SNMPv3 globally")]
        label = "snmpv3_enable"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "2":
        cmds  = [("snmpv3 -S disable", "Disable SNMPv3 globally")]
        label = "snmpv3_disable"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "3":
        profile = _get_profile()
        if profile is None:
            return
        nms_ip    = input("  NMS IP (SNMP polling host): ").strip()
        snmp_user = input("  SNMPv3 username: ").strip()
        snmp_auth = getpass.getpass("  SNMPv3 auth passphrase (min 8 chars): ")
        snmp_priv = getpass.getpass("  SNMPv3 priv passphrase (min 8 chars): ")
        if len(snmp_auth) < 8 or len(snmp_priv) < 8:
            print("  ERROR: Passphrases must be at least 8 characters.")
            return
        cfg   = {"profile": profile, "nms_ip": nms_ip, "snmp_user": snmp_user,
                 "snmp_auth": snmp_auth, "snmp_priv": snmp_priv}
        cmds  = build_snmpv3_configure(cfg)
        label = f"snmpv3_configure_profile{profile}"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "4":
        profile = _get_profile()
        if profile is None:
            return
        cfg   = {"profile": profile}
        cmds  = build_snmpv3_disable_profile(cfg)
        label = f"snmpv3_disable_profile{profile}"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "5":
        profile = _get_profile()
        if profile is None:
            return
        snmp_auth = getpass.getpass("  New auth passphrase (min 8 chars): ")
        snmp_priv = getpass.getpass("  New priv passphrase (min 8 chars): ")
        if len(snmp_auth) < 8 or len(snmp_priv) < 8:
            print("  ERROR: Passphrases must be at least 8 characters.")
            return
        cfg   = {"profile": profile, "snmp_auth": snmp_auth, "snmp_priv": snmp_priv}
        cmds  = build_snmpv3_rotate(cfg)
        label = f"snmpv3_rotate_profile{profile}"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "6":
        profile = _get_profile()
        if profile is None:
            return
        n = profile
        cmds = [
            (f"snmpv3 -u{n} profile{n} -ap{n} none -pp{n} none -ac{n} disable -n{n} 0.0.0.0",
             f"Clear profile {n} (reset username, disable auth/priv, revoke access)"),
        ]
        label = f"snmpv3_clear_profile{profile}"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")


def action_users(targets, nmc_user, nmc_pass, dry_run):
    print("\n  User Management:")
    print("    1) Rotate Super User password     (update password for built-in 'apc' account)")
    print("    2) Manage Administrator account   (create new named account, delete old one)")
    print("    3) Set session timeout            (auto-logout after N minutes of inactivity)")
    print("    4) Set lockout policy             (lock account after N failed login attempts)")
    print("    5) Manage sub-accounts            (enable or disable device / readonly accounts)")
    print("    6) Disable Super User account     (disables built-in 'apc' account — requires")
    print("                                       confirmed working admin account as fallback)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        print("  Note: Super User (apc) has a separate password from your login account.")
        apc_current = getpass.getpass("  Current Super User (apc) password: ")
        new_pass    = getpass.getpass("  New Super User (apc) password: ")
        cfg   = {"current_pass": apc_current, "superuser_pass_new": new_pass}
        cmds  = build_user_superuser(cfg)
        label = "user_superuser_rotate"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "2":
        print("\n  Administrator Account Options:")
        print("    1) Create new Administrator account")
        print("    2) Delete an account")
        print("    3) Create new + delete old   (rename workflow)")
        print("    4) Rotate Administrator password   (update password for named account)")
        print("    r) Return")
        sub = input("\n  Select: ").strip()

        if sub == "1":
            new_admin_user = input("  New Administrator username: ").strip()
            new_admin_pass = getpass.getpass("  New Administrator password: ")
            print()
            print("  Account status options if account already exists:")
            print("    1) Enable if disabled, skip if already enabled (recommended)")
            print("    2) Always create/overwrite")
            enable_choice = input("\n  Select [1]: ").strip() or "1"
            # Store config in a sentinel command — resolved per-device in run_commands
            sentinel = f"__user_create__{new_admin_user}||{new_admin_pass}||{enable_choice}"
            cmds  = [(sentinel, f"Create/enable Administrator account '{new_admin_user}'")]
            label = "user_admin_create"
            preview_cmds(cmds)
            _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

        elif sub == "2":
            del_user = input("  Username to delete: ").strip()
            cmds     = [(f"user -del {del_user}", f"Delete account '{del_user}'")]
            label    = "user_admin_delete"
            preview_cmds(cmds)
            print(f"  WARNING: '{del_user}' will be permanently deleted.")
            print("  Verify you have another admin account or Super User (apc) access first.")
            confirm = input("  Proceed? [y/N]: ").strip().lower()
            if confirm != "y":
                print("  Aborted.")
                return
            execute_fleet(targets, nmc_user, nmc_pass, cmds, label, dry_run)

        elif sub == "3":
            print(f"\n  Current admin username: {nmc_user}")
            new_admin_user = input("  New Administrator username: ").strip()
            new_admin_pass = getpass.getpass("  New Administrator password: ")
            cmds = [
                (f"user -n {new_admin_user} -pw {new_admin_pass} -pe Administrator -e enable",
                 f"Create Administrator account '{new_admin_user}'"),
                (f"user -del {nmc_user}", f"Delete old account '{nmc_user}'"),
            ]
            label = "user_admin_rename"
            preview_cmds(cmds)
            print(f"  WARNING: This will create '{new_admin_user}' and permanently delete '{nmc_user}'.")
            print("  Verify Super User (apc) SSH access works as fallback before proceeding.")
            confirm = input("  Proceed? [y/N]: ").strip().lower()
            if confirm != "y":
                print("  Aborted.")
                return
            execute_fleet(targets, nmc_user, nmc_pass, cmds, label, dry_run)

        elif sub == "4":
            target_user = input("  Administrator username to rotate: ").strip()
            new_pass    = getpass.getpass("  New password: ")
            cmds  = [(f"user -n {target_user} -pw {new_pass}",
                      f"Rotate password for '{target_user}'")]
            label = f"user_admin_rotate_pw"
            preview_cmds(cmds)
            _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

        elif sub in ("r", "R"):
            return
        else:
            print("  Invalid selection.")

    elif choice == "3":
        timeout = input("  Session timeout in minutes [30]: ").strip() or "30"
        cfg   = {"nmc_user": nmc_user, "session_timeout": timeout}
        cmds  = build_user_timeout(cfg)
        label = f"user_session_timeout_{timeout}min"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "4":
        attempts = input("  Failed attempts before lockout [3]: ").strip() or "3"
        duration = input("  Lockout duration in minutes [5]: ").strip() or "5"
        cfg   = {"lockout_attempts": attempts, "lockout_duration": duration}
        cmds  = build_user_lockout(cfg)
        label = f"user_lockout_{attempts}attempts_{duration}min"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "5":
        print("\n  Sub-accounts:")
        print("    1) device    (limited device control access)")
        print("    2) readonly  (read-only monitoring access)")
        print("    3) both")
        print("    r) Return")
        acct_choice = input("\n  Select: ").strip()
        acct_map = {"1": ["device"], "2": ["readonly"], "3": ["device", "readonly"]}
        if acct_choice in ("r", "R"):
            return
        if acct_choice not in acct_map:
            print("  Invalid selection.")
            return
        print("\n  Action:")
        print("    1) Disable   (revoke access — account still exists)")
        print("    2) Enable    (restore access)")
        print("    r) Return")
        act_choice = input("\n  Select: ").strip()
        if   act_choice == "1": action = "disable"
        elif act_choice == "2": action = "enable"
        elif act_choice in ("r", "R"): return
        else:
            print("  Invalid selection.")
            return
        cfg   = {"subaccounts": acct_map[acct_choice], "subaccount_action": action}
        cmds  = build_user_subaccounts(cfg)
        label = f"user_subaccounts_{action}"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "6":
        print()
        print("  WARNING: Disabling the Super User ('apc') account is a significant action.")
        print("  If your named admin account loses access, recovery requires physical console")
        print("  or factory reset. Verify your admin account works before proceeding.")
        print()
        apc_current = getpass.getpass("  Current Super User (apc) password (required to disable): ")
        confirm = input("  Type YES to confirm disable of Super User account: ").strip()
        if confirm != "YES":
            print("  Aborted.")
            return
        cmds  = [(f"user -n apc -cp {apc_current} -e disable -y",
                  "Disable Super User (apc) account")]
        label = "user_superuser_disable"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")


def action_ntp(targets, nmc_user, nmc_pass, dry_run):
    print("\n  NTP Options:")
    print("    1) Enable NTP + set servers   (enable time sync, set primary + secondary)")
    print("    2) Disable NTP               (turn off time sync)")
    print("    3) Sync now                  (force immediate NTP sync, no config changes)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        ntp_primary   = input("  NTP Primary server: ").strip()
        ntp_secondary = input("  NTP Secondary server: ").strip()
        cmds  = build_ntp({"ntp_primary": ntp_primary, "ntp_secondary": ntp_secondary})
        label = "ntp_enable_set_servers"
    elif choice == "2":
        cmds, label = [("ntp -e disable", "Disable NTP")], "ntp_disable"
    elif choice == "3":
        cmds, label = [("ntp -u", "Force NTP sync now")], "ntp_sync_now"
    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_ipv6(targets, nmc_user, nmc_pass, dry_run):
    print("\n  IPv6 Options:")
    print("    1) Disable IPv6   (recommended if IPv6 not in use — reduces attack surface)")
    print("    2) Enable IPv6    (allow IPv6 connectivity)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("tcpip6 -S disable", "Disable IPv6")], "ipv6_disable"
    elif choice == "2": cmds, label = [("tcpip6 -S enable",  "Enable IPv6")],  "ipv6_enable"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_system(targets, nmc_user, nmc_pass, dry_run):
    print("\n  System Options:")
    print("    1) Set system contact        (admin contact info, visible in SNMP)")
    print("    2) Set login banner          (message displayed at SSH/web login)")
    print("    3) Reboot NMC card           (reboots management card only —")
    print("                                  UPS stays online, outlets stay live,")
    print("                                  mgmt access unavailable for ~60 seconds)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        contact = input("  System contact: ").strip()
        cmds    = [(f"system -c {contact}", f"Set system contact to '{contact}'")]
        label   = "system_contact"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "2":
        message = input("  Login banner message (single line): ").strip()
        cmds    = [(f'system -m "{message}"', "Set login banner")]
        label   = "system_login_banner"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice == "3":
        cmds  = [("reboot__confirm", "Reboot NMC card (UPS stays online, outlets stay live, ~60s mgmt unavailable)")]
        label = "system_reboot_nmc"
        preview_cmds(cmds)
        _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)

    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")


def action_dns(targets, nmc_user, nmc_pass, dry_run):
    print("\n  DNS Options:")
    print("    1) Set DNS servers + domain   (primary, secondary, domain name)")
    print("    2) Set primary DNS only")
    print("    3) Set secondary DNS only")
    print("    4) Set domain name only")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    cfg = {}
    if choice == "1":
        cfg['dns_primary']   = input("  Primary DNS server: ").strip()
        cfg['dns_secondary'] = input("  Secondary DNS server: ").strip()
        cfg['dns_domain']    = input("  Domain name (e.g. example.com): ").strip()
        label = "dns_set_all"
    elif choice == "2":
        cfg['dns_primary'] = input("  Primary DNS server: ").strip()
        label = "dns_set_primary"
    elif choice == "3":
        cfg['dns_secondary'] = input("  Secondary DNS server: ").strip()
        label = "dns_set_secondary"
    elif choice == "4":
        cfg['dns_domain'] = input("  Domain name (e.g. example.com): ").strip()
        label = "dns_set_domain"
    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")
        return

    cmds = build_dns(cfg)
    if not cmds:
        print("  Nothing to run.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_boot(targets, nmc_user, nmc_pass, dry_run):
    print("\n  Boot / IP Mode Options:")
    print("    1) Set boot mode to DHCP    (device gets IP from DHCP server)")
    print("    2) Set boot mode to BOOTP   (device gets IP from BOOTP server)")
    print("    3) Set boot mode to manual  (locks to current IP, stops DHCP on reboot)")
    print("    4) Require DHCPv4 cookie    (only accept DHCP offers with vendor cookie)")
    print("    5) Disable DHCPv4 cookie    (accept any DHCP offer)")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if   choice == "1": cmds, label = [("boot -b dhcp",   "Set boot mode to DHCP")],              "boot_mode_dhcp"
    elif choice == "2": cmds, label = [("boot -b bootp",  "Set boot mode to BOOTP")],             "boot_mode_bootp"
    elif choice == "3": cmds, label = [("boot -b manual", "Set boot mode to manual (static IP)")], "boot_mode_manual"
    elif choice == "4": cmds, label = [("boot -c enable",  "Require DHCPv4 cookie")],             "boot_dhcp_cookie_enable"
    elif choice == "5": cmds, label = [("boot -c disable", "Disable DHCPv4 cookie requirement")], "boot_dhcp_cookie_disable"
    elif choice in ("r", "R"): return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_smtp(targets, nmc_user, nmc_pass, dry_run):
    print("\n  SMTP Options:")
    print("    1) Set SMTP server")
    print("    2) Clear SMTP server          (silences all email alerts)")
    print("    3) Set from address")
    print("    4) Set port")
    print("    5) Set encryption             (none | ifavail | always | implicit)")
    print("    6) Enable authentication")
    print("    7) Disable authentication")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        server = input("  SMTP server: ").strip()
        if not server:
            print("  No server entered — aborted.")
            return
        cmds  = [(f"smtp -s {server}", f"Set SMTP server to {server}")]
        label = "smtp_set_server"

    elif choice == "2":
        cmds  = [('smtp -s 0.0.0.0', "Set SMTP server to 0.0.0.0 (silences all email alerts)")]
        label = "smtp_clear_server"

    elif choice == "3":
        print("\n  From Address Options:")
        print("    1) Enter manually")
        print("    2) Use device hostname  (reads hostname from device, you provide domain)")
        print("    r) Return")
        sub = input("\n  Select: ").strip()

        if sub == "1":
            from_addr = input("  From address: ").strip()
            if not from_addr:
                print("  No address entered — aborted.")
                return
            cmds  = [(f"smtp -f {from_addr}", f"Set from address to {from_addr}")]
            label = "smtp_set_from_manual"

        elif sub == "2":
            domain = input("  Domain (e.g. company.com): ").strip()
            if not domain:
                print("  No domain entered — aborted.")
                return
            # Per-device hostname read — handled in run_commands via special label
            # Pass domain as a sentinel in cmds, execution engine resolves per device
            cmds  = [(f"__hostname_from__{domain}", f"Set from address to <hostname>@{domain}")]
            label = "smtp_set_from_hostname"

        elif sub in ("r", "R"):
            return
        else:
            print("  Invalid selection.")
            return

    elif choice == "4":
        port = input("  Port [25]: ").strip() or "25"
        cmds  = [(f"smtp -p {port}", f"Set SMTP port to {port}")]
        label = "smtp_set_port"

    elif choice == "5":
        print("  Options: none | ifavail | always | implicit")
        enc = input("  Encryption: ").strip().lower()
        if enc not in ("none", "ifavail", "always", "implicit"):
            print("  Invalid option.")
            return
        cmds  = [(f"smtp -e {enc}", f"Set encryption to {enc}")]
        label = f"smtp_encryption_{enc}"

    elif choice == "6":
        cmds  = [("smtp -a enable", "Enable SMTP authentication")]
        label = "smtp_auth_enable"

    elif choice == "7":
        cmds  = [("smtp -a disable", "Disable SMTP authentication")]
        label = "smtp_auth_disable"

    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


def action_ups(targets, nmc_user, nmc_pass, dry_run):
    print("\n  UPS Actions:")
    print("    1) Run self-test           (initiates immediate UPS self-test)")
    print("    2) Start runtime calibration")
    print("    3) Stop runtime calibration")
    print("    r) Return to main menu")
    choice = input("\n  Select: ").strip()

    if choice == "1":
        print()
        print("  NOTE: Self-test will momentarily switch UPS to battery.")
        print("  Confirm connected equipment can tolerate a brief transfer.")
        cmds  = [("ups -s Start", "Initiate UPS self-test (brief transfer to battery)")]
        label = "ups_selftest"
    elif choice == "2":
        print()
        print("  NOTE: Runtime calibration runs the UPS on battery until low.")
        print("  Only run during a scheduled maintenance window.")
        cmds  = [("ups -r Start", "Start UPS runtime calibration")]
        label = "ups_runtime_calibration_start"
    elif choice == "3":
        cmds  = [("ups -r Stop", "Stop UPS runtime calibration")]
        label = "ups_runtime_calibration_stop"
    elif choice in ("r", "R"):
        return
    else:
        print("  Invalid selection.")
        return

    preview_cmds(cmds)
    _confirm_and_run(targets, nmc_user, nmc_pass, cmds, label, dry_run)


# ── Main menu ─────────────────────────────────────────────────────────────────
MENU_OPTIONS = {
    "1":  ("HTTPS / HTTP",           action_web),
    "2":  ("FTP",                    action_ftp),
    "3":  ("Telnet / SSH",           action_console),
    "4":  ("RADIUS",                 action_radius),
    "5":  ("SNMPv1",                 action_snmpv1),
    "6":  ("SNMPv3",                 action_snmpv3),
    "7":  ("Users / Accounts",       action_users),
    "8":  ("NTP",                    action_ntp),
    "9":  ("IPv6",                   action_ipv6),
    "10": ("System",                 action_system),
    "11": ("DNS",                    action_dns),
    "12": ("Boot / IP Mode",         action_boot),
    "13": ("SMTP",                   action_smtp),
    "14": ("UPS Actions",            action_ups),
}


def print_menu():
    print("\n" + "=" * 60)
    print("  NMC2 Management Tool")
    print("=" * 60)
    for key, (label, _) in MENU_OPTIONS.items():
        print(f"    {key:>2}) {label}")
    print("     q) Quit")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="NMC2 menu-driven hardening tool")
    parser.add_argument("-f", "--file",   help="File with target IPs (one per line)")
    parser.add_argument("-s", "--single", help="Single target IP")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    parser.add_argument("--threads", type=int, default=20,
                        help="Number of concurrent threads (default: 20, use 5-10 for SMTP)")
    args = parser.parse_args()

    if args.single:
        targets = [args.single]
    elif args.file:
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        print("ERROR: No targets specified. Use -f <targets.txt> or -s <ip>.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  NMC2 Management Tool")
    print("=" * 60)
    global THREADS
    THREADS = args.threads

    print(f"  Targets : {len(targets)} device(s)")
    if args.dry_run:
        print("  Mode    : DRY RUN — no changes will be made")
    if args.threads != 20:
        print(f"  Threads : {args.threads}")
    print()

    nmc_user = input("  NMC username: ").strip()
    nmc_pass = getpass.getpass("  Current password: ")

    while True:
        print_menu()
        choice = input("\n  Select: ").strip().lower()

        if choice == "q":
            print("\n  Goodbye.\n")
            break
        elif choice in MENU_OPTIONS:
            label, fn = MENU_OPTIONS[choice]
            print(f"\n-- {label} " + "-" * (56 - len(label)))
            fn(targets, nmc_user, nmc_pass, args.dry_run)
        else:
            print("  Invalid selection.")


if __name__ == "__main__":
    main()
