import json
import os
import re
import datetime
import csv
from netmiko import ConnectHandler
import getpass  # Secure password input

# Generate unique timestamp for logs & CSV output
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Create a unique log directory
log_directory = f"logs/{timestamp}"
os.makedirs(log_directory, exist_ok=True)

# Prompt for VLAN ID
VLAN_ID = input("Enter VLAN ID to check: ").strip()

# File Paths
csv_filename = f"{log_directory}/vlan_{VLAN_ID}_interfaces.csv"
console_log_filename = f"{log_directory}/console_log.txt"
command_log_filename = f"{log_directory}/command_log.txt"

def log_message(message, log_file, print_to_terminal=True):
    """Logs messages to a file and optionally prints to terminal."""
    if print_to_terminal:
        print(message)
    with open(log_file, "a") as file:
        file.write(message + "\n")

    # Also log everything to a single console log file
    with open(console_log_filename, "a") as console_file:
        console_file.write(message + "\n")

def parse_vlan_ports(vlan_output):
    """Extracts valid interface names assigned to VLAN from 'show vlan id <VLAN_ID>' output."""
    vlan_ports = []
    capture_ports = False
    interface_pattern = re.compile(r"^(Fa|Gi|Te|Fi|Po|Eth|Hu)\d+\/\d+\/?\d*$")  # Match valid interfaces

    for line in vlan_output.splitlines():
        line = line.strip()
        if "active" in line.lower():
            capture_ports = True  

        if capture_ports:
            if "VLAN Type" in line or line == "":
                break  

            parts = re.split(r"[,\s]+", line)
            for part in parts:
                if interface_pattern.match(part):
                    vlan_ports.append(part)

    return vlan_ports

def extract_max_speed(media_output):
    """Extracts the maximum speed capability from media type output."""
    speed_matches = re.findall(r"(\d+G?)", media_output)
    if speed_matches:
        return max(speed_matches, key=lambda x: int(x.replace("G", "0000")))
    return "Unknown"

def check_interface_status(conn, interface):
    """Checks the line status, speed, and potential errors of a given interface."""
    status_output = conn.send_command(f"show interface {interface} | include line")
    speed_output = conn.send_command(f"show interface {interface} | include media type")
    error_output = conn.send_command(f"show interface {interface} | include error|carrier")

    # Log the commands run
    with open(command_log_filename, "a") as cmd_log:
        cmd_log.write(f"\n[{interface}]\n")
        cmd_log.write(f"Command: show interface {interface} | include line\n{status_output}\n")
        cmd_log.write(f"Command: show interface {interface} | include media type\n{speed_output}\n")
        cmd_log.write(f"Command: show interface {interface} | include error|carrier\n{error_output}\n")

    # Extract speed and error details
    status_match = re.search(r"(\S+) is (\S+),", status_output)
    speed_match = re.search(r"(\d+Mb/s)", speed_output)

    status = status_match.group(2) if status_match else "Unknown"
    actual_speed = speed_match.group(1) if speed_match else "Unknown"
    max_speed = extract_max_speed(speed_output)
    total_errors = sum(map(int, re.findall(r"(\d+)", error_output)))

    return status, actual_speed, max_speed, total_errors

def check_vlan_interfaces(switch, csv_writer):
    """Logs into the switch, retrieves VLAN interfaces, and checks their status, speed, and errors."""
    hostname = switch["hostname"]
    ip_address = switch["ip"]

    log_message(f"\n🔗 Connecting to {hostname} ({ip_address})...", console_log_filename)

    try:
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=ip_address,
            username=username,
            password=password
        )

        vlan_output = conn.send_command(f"show vlan id {VLAN_ID}")
        vlan_ports = parse_vlan_ports(vlan_output)

        if not vlan_ports:
            log_message(f"⚠️ No active ports found in VLAN {VLAN_ID} on {hostname}.", console_log_filename)
        else:
            log_message(f"\n📋 Ports in VLAN {VLAN_ID} on {hostname}:", console_log_filename)
            for port in vlan_ports:
                status, actual_speed, max_speed, total_errors = check_interface_status(conn, port)
                log_message(f" - {port}: Status={status}, Speed={actual_speed}, Max={max_speed}, Errors={total_errors}", console_log_filename)

                csv_writer.writerow([hostname, ip_address, port, status, actual_speed, max_speed, total_errors])

        conn.disconnect()

    except Exception as e:
        log_message(f"❌ Error connecting to {hostname}: {e}", console_log_filename)

if __name__ == "__main__":
    with open("switches.json", "r") as switch_file:
        switch_data = json.load(switch_file)

    if not isinstance(switch_data, dict) or "switches" not in switch_data:
        print("❌ Error: `switches.json` is incorrectly formatted.")
        exit(1)

    switches = switch_data["switches"]
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    with open(csv_filename, mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Hostname", "IP Address", "Interface", "Status", "Actual Speed", "Max Speed", "Total Errors"])

        for switch in switches:
            check_vlan_interfaces(switch, csv_writer)

print(f"✅ CSV file saved: {csv_filename}")
