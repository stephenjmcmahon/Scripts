import json
import os
import re
import datetime
import argparse
from netmiko import ConnectHandler
import getpass  # Secure password input

# Generate unique timestamp for this execution
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Create a unique folder for this run inside logs/
log_directory = f"logs/{timestamp}"
os.makedirs(log_directory, exist_ok=True)

# Define console and command log file inside the timestamped folder
console_log_filename = f"{log_directory}/console.log"
command_log_filename = f"{log_directory}/command_log.txt"

def log_message(message, log_file, print_to_terminal=True):
    """Logs messages to a file and optionally prints to terminal."""
    if print_to_terminal:
        print(message)
    with open(log_file, "a") as file:
        file.write(message + "\n")

def fetch_switch_vlans(conn, switch_name, ip):
    """Retrieves VLANs from a switch and logs the command output."""
    log_message(f"\n📡 Retrieving VLANs from {switch_name} ({ip})...", console_log_filename)

    # Log the command being executed
    vlan_output = conn.send_command("show vlan brief")
    with open(command_log_filename, "a") as cmd_log:
        cmd_log.write(f"\n[{switch_name} - {ip}]\n")
        cmd_log.write("Command: show vlan brief\n")
        cmd_log.write(vlan_output + "\n")

    # Extract VLANs correctly
    vlan_mapping = {}
    for line in vlan_output.splitlines():
        match = re.match(r"(\d+)\s+([\w.-]+)", line)  # Capture full VLAN names with dots & dashes
        if match:
            vlan_id, vlan_name = match.groups()
            vlan_mapping[vlan_id] = vlan_name.strip()

    log_message(f"✅ Retrieved VLANs from {switch_name}:", console_log_filename)
    for vlan_id, vlan_name in vlan_mapping.items():
        log_message(f" - VLAN {vlan_id}: {vlan_name}", console_log_filename)

    return vlan_mapping

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

        log_message(f"\n🔗 Connecting to {hostname} ({ip})...", console_log_filename)
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip,
            username=username,
            password=password
        )

        # Fetch VLANs from the switch
        switch_vlan_mapping = fetch_switch_vlans(conn, hostname, ip)

        # Compare VLANs and generate required fixes
        commands, mismatched_vlans = generate_fix_commands(switch_vlan_mapping, core_vlans)

        if mismatched_vlans:
            log_message(f"\n🔄 VLANs needing updates on {hostname}:", console_log_filename)
            for vlan_id, old_name, new_name in mismatched_vlans:
                log_message(f" - VLAN {vlan_id}: '{old_name}' → '{new_name}'", console_log_filename)

            log_message(f"\n⚙️  Applying VLAN name fixes on {hostname}...", console_log_filename)
            conn.send_config_set(commands)

            # Save the config after applying changes
            log_message(f"\n💾 Saving configuration on {hostname}...", console_log_filename)
            conn.send_command("write memory")

            # Log all commands run on the switch
            with open(command_log_filename, "a") as cmd_file:
                cmd_file.write(f"\nCommands sent to {hostname} ({ip}):\n")
                for cmd in commands:
                    cmd_file.write(cmd + "\n")
                cmd_file.write("write memory\n")

            log_message("✅ Configuration applied and saved successfully!", console_log_filename)
        else:
            log_message(f"✅ No changes needed on {hostname}.", console_log_filename)

        conn.disconnect()

    except Exception as e:
        log_message(f"❌ Error connecting to {hostname}: {e}", console_log_filename)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VLAN Sync Script for Cisco Switches")
    parser.add_argument("--fetch", action="store_true", help="Fetch VLANs from the core switch and save to core_vlans.json")
    parser.add_argument("--sync", action="store_true", help="Sync VLANs from core_vlans.json to access switches")
    parser.add_argument("--all", action="store_true", help="Fetch VLANs from core and sync to access switches (full automation)")

    args = parser.parse_args()

    if not any(vars(args).values()):
        print("\n❌ No flags provided. Please use one of the following options:")
        print("  --fetch   Fetch VLANs from the core switch and save to core_vlans.json")
        print("  --sync    Sync VLANs from core_vlans.json to access switches")
        print("  --all     Fetch VLANs from core and sync to access switches (full automation)")
        exit(1)

    log_message(f"\n🚀 VLAN Synchronization Started - {timestamp}\n", console_log_filename)

    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    with open("switches.json", "r") as switch_file:
        switch_data = json.load(switch_file)

    if not isinstance(switch_data, dict) or "switches" not in switch_data:
        print("❌ Error: `switches.json` is incorrectly formatted.")
        exit(1)

    switches = switch_data["switches"]
    core_switch = switch_data["core_switch"]

    core_switch_info = {
        "device_type": "cisco_ios",
        "host": core_switch["ip"],
        "username": username,
        "password": password
    }

    if args.fetch or args.all:
        core_vlans = fetch_switch_vlans(ConnectHandler(**core_switch_info), core_switch["hostname"], core_switch["ip"])

        # Save the core VLANs
        with open("core_vlans.json", "w") as json_file:
            json.dump(core_vlans, json_file, indent=4)

        log_message("\n✅ VLAN list retrieved and saved to core_vlans.json", console_log_filename)

    if args.sync or args.all:
        with open("core_vlans.json", "r") as json_file:
            core_vlans = json.load(json_file)

        confirm = input("\n❓ Do you want to proceed with applying these VLANs to access switches? (yes/no): ").strip().lower()
        if confirm != "yes":
            log_message("\n🚫 VLAN sync aborted.", console_log_filename)
            exit(0)

        for switch in switches:
            update_switch_vlans(switch, core_vlans)

    log_message("\n✅ VLAN Synchronization Complete! Logs saved.", console_log_filename)
