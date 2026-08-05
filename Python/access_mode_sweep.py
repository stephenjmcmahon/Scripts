#!/usr/bin/env python3
"""
Sweep Cisco IOS devices for interfaces that have
  'switchport access vlan <N>'
but are missing
  'switchport mode access'
while EXCLUDING any interface configured as a trunk
  ('switchport mode trunk').

Usage:
  python sweep_access_vlan_missing_mode_access.py --inventory devices.txt --outdir ./out

Inventory file: one IP or hostname per line.
Outputs:
  - out/results.csv
  - out/results.json
  - out/logs/<IP>_session.log (raw Netmiko session logs)
  - out/sweep.log (high-level app log)
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import socket
from getpass import getpass
from typing import List, Dict, Any

# --- Netmiko imports (compatible across 2.x/3.x/4.x) ---
from netmiko import ConnectHandler
try:
    # Netmiko 3.x/4.x
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    # Back-compat for older Netmiko
    try:
        from netmiko.ssh_exception import NetMikoTimeoutException as NetmikoTimeoutException
        from netmiko.ssh_exception import NetMikoAuthenticationException as NetmikoAuthenticationException
    except ImportError:
        from netmiko import NetMikoTimeoutException as NetmikoTimeoutException
        from netmiko import NetMikoAuthenticationException as NetmikoAuthenticationException
# ----------------------------------------------------------------------

SECTION_SPLIT_RE = re.compile(r"(?m)^\s*interface\s+(\S+)\s*$")

def parse_args():
    p = argparse.ArgumentParser(description="Find interfaces with 'switchport access vlan' but missing 'switchport mode access', excluding trunks.")
    p.add_argument("--inventory", required=True, help="Path to file with device IPs/hostnames, one per line")
    p.add_argument("--outdir", default="./out", help="Output directory (default: ./out)")
    p.add_argument("--device_type", default="cisco_ios", help="Netmiko device_type (default: cisco_ios)")
    p.add_argument("--cmd_timeout", type=int, default=60, help="Per-command timeout seconds (default: 60)")
    p.add_argument("--ssh_port", type=int, default=22, help="SSH port (default: 22)")
    return p.parse_args()

def read_inventory(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return lines

def ensure_dirs(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(os.path.join(outdir, "logs"), exist_ok=True)

def app_log(outdir: str, msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    sys.stdout.write(line)
    with open(os.path.join(outdir, "sweep.log"), "a", encoding="utf-8") as f:
        f.write(line)

def get_running_config(conn, cmd_timeout: int) -> str:
    return conn.send_command("show running-config", use_textfsm=False, read_timeout=cmd_timeout)

def get_hostname_from_run(run_cfg: str) -> str:
    m = re.search(r"(?m)^\s*hostname\s+(\S+)", run_cfg)
    return m.group(1) if m else ""

def parse_interfaces(run_cfg: str) -> Dict[str, str]:
    """
    Split the running-config into interface stanzas.
    Returns dict: { interface_name: stanza_text }
    """
    blocks = {}
    matches = list(SECTION_SPLIT_RE.finditer(run_cfg))
    for i, m in enumerate(matches):
        intf = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(run_cfg)
        blocks[intf] = run_cfg[start:end]
    return blocks

def analyze_interface_block(intf_block: str):
    """
    Check if:
      - has 'switchport access vlan <N>'
      - has 'switchport mode access'
      - has 'switchport mode trunk' (for exclusion)
    """
    lines = [ln.strip() for ln in intf_block.splitlines()]
    has_access_vlan = False
    access_vlan = None
    has_mode_access = False
    is_trunk = False

    for ln in lines:
        m_vlan = re.fullmatch(r"switchport\s+access\s+vlan\s+(\d+)", ln, flags=re.IGNORECASE)
        if m_vlan:
            has_access_vlan = True
            access_vlan = m_vlan.group(1)
        if re.fullmatch(r"switchport\s+mode\s+access", ln, flags=re.IGNORECASE):
            has_mode_access = True
        if re.fullmatch(r"switchport\s+mode\s+trunk", ln, flags=re.IGNORECASE):
            is_trunk = True

    return has_access_vlan, access_vlan, has_mode_access, is_trunk

# --- Fast TCP/22 pre-check to skip unreachable hosts ---
def tcp_port_open(host: str, port: int = 22, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
# -------------------------------------------------------

def main():
    args = parse_args()
    ensure_dirs(args.outdir)

    print("== Credentials ==")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    enable_secret = getpass("Enable secret (press Enter if not needed): ")

    devices = read_inventory(args.inventory)
    if not devices:
        print("Inventory is empty. Exiting.")
        sys.exit(1)

    results: List[Dict[str, Any]] = []

    for host in devices:
        session_log = os.path.join(args.outdir, "logs", f"{host}_session.log")

        if not tcp_port_open(host, args.ssh_port, timeout=1.0):
            app_log(args.outdir, f"{host}: TCP/{args.ssh_port} not reachable; skipping.")
            continue

        app_log(args.outdir, f"Connecting to {host} ...")
        try:
            conn = ConnectHandler(
                device_type=args.device_type,
                host=host,
                username=username,
                password=password,
                secret=enable_secret if enable_secret else None,
                port=args.ssh_port,
                session_log=session_log,
                fast_cli=False,
            )

            try:
                if enable_secret:
                    conn.enable()
            except Exception as e:
                app_log(args.outdir, f"{host}: enable() skipped/failed ({e})")

            run_cfg = get_running_config(conn, args.cmd_timeout)
            hostname = get_hostname_from_run(run_cfg) or host
            interfaces = parse_interfaces(run_cfg)

            for intf_name, block in interfaces.items():
                has_access_vlan, access_vlan, has_mode_access, is_trunk = analyze_interface_block(block)

                # Condition: has 'switchport access vlan' but missing 'switchport mode access'
                # Exclude trunk ports
                if has_access_vlan and not has_mode_access and not is_trunk:
                    results.append(
                        {
                            "device": host,
                            "hostname": hostname,
                            "interface": intf_name,
                            "access_vlan": access_vlan,
                            "has_mode_access": has_mode_access,
                            "is_trunk": is_trunk,
                        }
                    )

            app_log(args.outdir, f"Completed {host} (found {sum(1 for r in results if r['device']==host)} issues).")

        except NetmikoAuthenticationException as e:
            app_log(args.outdir, f"AUTH FAILURE on {host}: {e}")
        except NetmikoTimeoutException as e:
            app_log(args.outdir, f"TIMEOUT on {host}: {e}")
        except Exception as e:
            app_log(args.outdir, f"ERROR on {host}: {e}")
        finally:
            try:
                if 'conn' in locals():
                    conn.disconnect()
            except Exception:
                pass

    # Write outputs
    csv_path = os.path.join(args.outdir, "results.csv")
    json_path = os.path.join(args.outdir, "results.json")

    fieldnames = ["device", "hostname", "interface", "access_vlan", "has_mode_access", "is_trunk"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    app_log(
        args.outdir,
        f"Done. Summary: {len(results)} interface(s) with 'switchport access vlan' but missing 'switchport mode access' "
        f"(trunk ports excluded). See {csv_path} and {json_path} for details.",
    )


if __name__ == "__main__":
    main()
