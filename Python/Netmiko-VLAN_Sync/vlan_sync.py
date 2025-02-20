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

# Define console log file inside the timestamped folder
console_log_filename = f"{log_directory}/console.log"

def log_message(message, log_file, print_to_terminal=True):
    """Logs messages to a file and optionally prints to terminal."""
    if print_to_terminal:
        print(message)
    with open(log_file, "a") as file:
        file.write(message + "\n")

def parse_vlan_output(vlan_output):
    """Parses 'show vlan brief' output and returns a dictionary {vlan_id: vlan_name}."""
    vlan_mapping = {}
    
    # VLANs to be skipped
    skipped_vlans = {
        "1": "default",
        "1002": "fddi-default",
        "1003": "token-ring-default",
        "1004": "fddinet-default",
        "1005": "trnet-default"
    }

    for line in vlan_output.splitlines():
        match = re.match(r"(\d+)\s+([\w-]+)", line)
        if match:
            vlan_id, vlan_name = match.groups()

            if vlan_id in skipped_vlans:
                log_message(f"⚠️  Skipping default VLAN {vlan_id}: {skipped_vlans[vlan_id]}", console_log_filename)
                continue

            vlan_mapping[vlan_id] = vlan_name

    return vlan_mapping

def fetch_core_vlans(core_switch):
    """Connects to the core switch and retrieves VLAN info."""
    try:
        hostname = core_switch.get("hostname", core_switch["ip"])  # Use hostname if available, otherwise IP
        ip_address = core_switch["ip"]
        command_log_filename = f"{log_directory}/{hostname}.log"

        log_message(f"\n🔗 Connecting to Core Switch ({hostname} - {ip_address})...", console_log_filename)
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip_address,  # Use IP for SSH connection
            username=username,
            password=password
        )
        conn.enable()

        vlan_output = conn.send_command("show vlan brief")
        log_message(f"✅ VLAN list retrieved from {hostname}", console_log_filename)

        # Log the command sent to the core switch
        with open(command_log_filename, "a") as cmd_file:
            cmd_file.write(f"\nCommands sent to {hostname} ({ip_address}):\n")
            cmd_file.write("show vlan brief\n")

        core_vlans = parse_vlan_output(vlan_output)
        conn.disconnect()

        # Save VLAN mapping to core_vlans.json
        with open("core_vlans.json", "w") as json_file:
            json.dump(core_vlans, json_file, indent=4)

        log_message("\n✅ VLAN list saved to core_vlans.json", console_log_filename)

        # Display the final VLAN list after skipping defaults
        log_message("\n📋 Final VLAN List from Core (Skipping Default VLANs 1, 1002-1005):", console_log_filename)
        for vlan_id, vlan_name in core_vlans.items():
            log_message(f" - VLAN {vlan_id}: {vlan_name}", console_log_filename)

        # Confirm before applying to access switches
        confirm = input("\n❓ Do you want to proceed with syncing these VLANs to access switches? (yes/no): ").strip().lower()
        if confirm != "yes":
            log_message("\n🚫 VLAN sync aborted.", console_log_filename)
            exit(0)

        return core_vlans

    except Exception as e:
        log_message(f"❌ Error retrieving VLANs from Core Switch: {e}", console_log_filename)
        exit(1)

def update_switch_vlans(switch, core_vlans):
    """Connects to the switch, retrieves VLAN info, and corrects mismatches."""
    try:
        hostname = switch.get("hostname", switch["ip"])  # Use hostname if available, otherwise IP
        ip_address = switch["ip"]
        command_log_filename = f"{log_directory}/{hostname}.log"

        log_message(f"\n🔗 Connecting to {hostname} ({ip_address})...", console_log_filename)
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip_address,  # Use IP for SSH connection
            username=username,
            password=password
        )

        vlan_output = conn.send_command("show vlan brief")
        switch_vlan_mapping = parse_vlan_output(vlan_output)

        commands, mismatched_vlans = generate_fix_commands(switch_vlan_mapping, core_vlans)

        if mismatched_vlans:
            log_message(f"\n🔄 VLANs needing updates on {hostname}:", console_log_filename)
            for vlan_id, old_name, new_name in mismatched_vlans:
                log_message(f" - VLAN {vlan_id}: '{old_name}' → '{new_name}'", console_log_filename)

            log_message(f"\n⚙️ Applying VLAN name fixes on {hostname}...", console_log_filename)
            conn.send_config_set(commands)

            # Save the config after applying changes
            log_message(f"\n💾 Saving configuration on {hostname}...", console_log_filename)
            conn.send_command("write memory")

            # Log all commands run on the switch
            with open(command_log_filename, "a") as cmd_file:
                cmd_file.write(f"\nCommands sent to {hostname} ({ip_address}):\n")
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

    if not any(vars(args).values()):  # No flags provided
        print("\n❌ No flags provided. Please use one of the following options:")
        print("  --fetch   Fetch VLANs from the core switch and save to core_vlans.json")
        print("  --sync    Sync VLANs from core_vlans.json to access switches")
        print("  --all     Fetch VLANs from core and sync to access switches (full automation)")
        exit(1)  # Exit so script does not continue

    log_message(f"\n🚀 VLAN Synchronization Started - {timestamp}\n", console_log_filename)

    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    with open("switches.json", "r") as switch_file:
        switch_data = json.load(switch_file)
        switches = switch_data["switches"]
        core_switch = switch_data["core_switch"]

    if args.fetch or args.all:
        core_vlans = fetch_core_vlans(core_switch)
    else:
        with open("core_vlans.json", "r") as json_file:
            core_vlans = json.load(json_file)

    if args.sync or args.all:
        for switch in switches:
            update_switch_vlans(switch, core_vlans)

    log_message("\n✅ VLAN Synchronization Complete! Logs saved.", console_log_filename)
