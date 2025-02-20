import json
import os
import re
import datetime
import argparse
from netmiko import ConnectHandler
import getpass  # Secure password input

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Generate unique log filenames with timestamps
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f"logs/vlan_sync_log_{timestamp}.log"
cmds_filename = f"logs/vlan_commands_log_{timestamp}.log"

def log_message(message, log_file):
    """Prints message to terminal and writes to log file."""
    print(message)
    with open(log_file, "a") as file:
        file.write(message + "\n")

def parse_vlan_output(vlan_output):
    """Parses 'show vlan brief' output and returns a dictionary {vlan_id: vlan_name}."""
    vlan_mapping = {}
    for line in vlan_output.splitlines():
        match = re.match(r"(\d+)\s+([\w-]+)", line)
        if match:
            vlan_id, vlan_name = match.groups()
            vlan_mapping[vlan_id] = vlan_name
    return vlan_mapping

def fetch_core_vlans(core_switch):
    """Connects to the core switch and retrieves VLAN info."""
    try:
        log_message(f"\n🔗 Connecting to Core Switch ({core_switch['host']})...", log_filename)
        conn = ConnectHandler(**core_switch)
        conn.enable()

        vlan_output = conn.send_command("show vlan brief")
        core_vlans = parse_vlan_output(vlan_output)

        conn.disconnect()

        # Save VLAN mapping to core_vlans.json
        with open("core_vlans.json", "w") as json_file:
            json.dump(core_vlans, json_file, indent=4)

        log_message(f"\n✅ VLAN list retrieved and saved to core_vlans.json", log_filename)

        # Display VLANs for user review
        print("\n📋 Retrieved VLAN List from Core:")
        for vlan_id, vlan_name in core_vlans.items():
            print(f" - VLAN {vlan_id}: {vlan_name}")

        log_message("\n📋 Core VLAN List:", log_filename)
        for vlan_id, vlan_name in core_vlans.items():
            log_message(f" - VLAN {vlan_id}: {vlan_name}", log_filename)

        # Confirm before applying to access switches
        confirm = input("\n❓ Do you want to proceed with syncing these VLANs to access switches? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("\n🚫 VLAN sync aborted.")
            log_message("\n🚫 VLAN sync aborted by user.", log_filename)
            exit(0)

        return core_vlans

    except Exception as e:
        log_message(f"❌ Error retrieving VLANs from Core Switch: {e}", log_filename)
        exit(1)

def generate_fix_commands(access_vlans, core_vlans):
    """Compares VLAN names and generates CLI commands to correct mismatches."""
    commands = []
    mismatched_vlans = []
    for vlan_id, current_name in access_vlans.items():
        if vlan_id in core_vlans and core_vlans[vlan_id] != current_name:
            commands.append(f"vlan {vlan_id}")
            commands.append(f" name {core_vlans[vlan_id]}")
            mismatched_vlans.append((vlan_id, current_name, core_vlans[vlan_id]))
    return commands, mismatched_vlans

def update_switch_vlans(switch, core_vlans):
    """Connects to the switch, retrieves VLAN info, and corrects mismatches."""
    try:
        hostname = switch["hostname"]
        ip = switch["ip"]

        log_message(f"\n🔗 Connecting to {hostname} ({ip})...", log_filename)
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip,
            username=username,
            password=password
        )

        vlan_output = conn.send_command("show vlan brief")
        switch_vlan_mapping = parse_vlan_output(vlan_output)

        commands, mismatched_vlans = generate_fix_commands(switch_vlan_mapping, core_vlans)

        if mismatched_vlans:
            log_message(f"\n🔄 VLANs needing updates on {hostname} ({ip}):", log_filename)
            for vlan_id, old_name, new_name in mismatched_vlans:
                log_message(f" - VLAN {vlan_id}: '{old_name}' → '{new_name}'", log_filename)

            log_message(f"\n⚙️ Applying VLAN name fixes on {hostname} ({ip})...", log_filename)
            conn.send_config_set(commands)

            with open(cmds_filename, "a") as cmd_file:
                cmd_file.write(f"\nCommands sent to {hostname} ({ip}):\n")
                for cmd in commands:
                    cmd_file.write(cmd + "\n")

            log_message("✅ Configuration applied successfully!", log_filename)
        else:
            log_message(f"✅ No changes needed on {hostname} ({ip}).", log_filename)

        conn.disconnect()

    except Exception as e:
        log_message(f"❌ Error connecting to {hostname} ({ip}): {e}", log_filename)

if __name__ == "__main__":
    # Setup argument parser
    parser = argparse.ArgumentParser(description="VLAN Sync Script for Cisco Switches")
    parser.add_argument("--fetch", action="store_true", help="Fetch VLANs from the core switch and save to core_vlans.json")
    parser.add_argument("--sync", action="store_true", help="Sync VLANs from core_vlans.json to access switches")
    parser.add_argument("--all", action="store_true", help="Fetch VLANs from core and sync to access switches (full automation)")

    args = parser.parse_args()

    # If no flags provided, show help and exit
    if not any(vars(args).values()):
        print("\n❌ No flags provided. Please use one of the following options:")
        print("  --fetch   Fetch VLANs from the core switch and save to core_vlans.json")
        print("  --sync    Sync VLANs from core_vlans.json to access switches")
        print("  --all     Fetch VLANs from core and sync to access switches (full automation)")
        exit(1)

    log_message(f"\n🚀 VLAN Synchronization Started - {timestamp}\n", log_filename)

    # Prompt for credentials
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")  # Secure input

    # Load switch details
    with open("switches.json", "r") as switch_file:
        switch_data = json.load(switch_file)
        switches = switch_data["switches"]
        core_switch = switch_data["core_switch"]

    core_switch_info = {
        "device_type": "cisco_ios",
        "host": core_switch["ip"],
        "username": username,
        "password": password
    }

    # Fetch VLANs from Core
    if args.fetch or args.all:
        core_vlans = fetch_core_vlans(core_switch_info)
    else:
        with open("core_vlans.json", "r") as json_file:
            core_vlans = json.load(json_file)

    # Sync VLANs to Access Switches
    if args.sync or args.all:
        for switch in switches:
            update_switch_vlans(switch, core_vlans)

    log_message("\n✅ VLAN Synchronization Complete! Logs saved.", log_filename)
