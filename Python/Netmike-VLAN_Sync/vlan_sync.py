import json
import os
import re
import datetime
from netmiko import ConnectHandler
import getpass  # Secure password input

# Load VLAN mapping from core_vlans.json
with open("core_vlans.json", "r") as vlan_file:
    core_vlan_mapping = json.load(vlan_file)

# Load switch details from switches.json
with open("switches.json", "r") as switch_file:
    switch_data = json.load(switch_file)
    switches = switch_data["switches"]

# Securely prompt for credentials
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")  # Hides input for security

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Generate unique log filenames with timestamps
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f"logs/vlan_sync_log_{timestamp}.log"
cmds_filename = f"logs/vlan_commands_log_{timestamp}.log"

def log_message(message, log_file):
    """
    Prints message to the terminal and writes it to the log file.
    """
    print(message)
    with open(log_file, "a") as file:
        file.write(message + "\n")

def parse_vlan_output(vlan_output):
    """
    Parses 'show vlan brief' output and returns a dictionary {vlan_id: vlan_name}.
    """
    vlan_mapping = {}
    for line in vlan_output.splitlines():
        match = re.match(r"(\d+)\s+([\w-]+)", line)
        if match:
            vlan_id, vlan_name = match.groups()
            vlan_mapping[vlan_id] = vlan_name
    return vlan_mapping

def generate_fix_commands(access_vlans, core_vlans):
    """
    Compares VLAN names and generates CLI commands to correct mismatches.
    """
    commands = []
    mismatched_vlans = []
    for vlan_id, current_name in access_vlans.items():
        if vlan_id in core_vlans and core_vlans[vlan_id] != current_name:
            commands.append(f"vlan {vlan_id}")
            commands.append(f" name {core_vlans[vlan_id]}")
            mismatched_vlans.append((vlan_id, current_name, core_vlans[vlan_id]))
    return commands, mismatched_vlans

def update_switch_vlans(switch):
    """
    Connects to the switch, retrieves VLAN info, and corrects mismatches.
    """
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

        commands, mismatched_vlans = generate_fix_commands(switch_vlan_mapping, core_vlan_mapping)

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

        missing_vlans = [vlan for vlan in switch_vlan_mapping if vlan not in core_vlan_mapping]
        if missing_vlans:
            log_message(f"\n⚠️ VLANs found on {hostname} ({ip}) but not in core reference:", log_filename)
            for vlan in missing_vlans:
                log_message(f" - VLAN {vlan}: '{switch_vlan_mapping[vlan]}'", log_filename)

        conn.disconnect()

    except Exception as e:
        log_message(f"❌ Error connecting to {hostname} ({ip}): {e}", log_filename)

if __name__ == "__main__":
    log_message(f"\n🚀 VLAN Synchronization Started - {timestamp}\n", log_filename)

    for switch in switches:
        update_switch_vlans(switch)

    log_message("\n✅ VLAN Synchronization Complete! Logs saved.", log_filename)
