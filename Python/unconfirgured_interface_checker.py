import json
import re
import getpass
import csv
from netmiko import ConnectHandler

# Load switch inventory from JSON file
with open("switches.json", "r") as file:
    switches = json.load(file)

# Prompt user for credentials (input is hidden for security)
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")

# Regex pattern to find interfaces with NO configuration (only "interface <name>" followed by "!")
# Excludes AppGigabitEthernet, Loopback, and Vlan interfaces
empty_interface_pattern = r"interface (?!AppGigabitEthernet|Loopback|Vlan)(\S+)\n!\n"

# Output CSV file
output_csv = "switch_empty_interfaces.csv"

# Prepare CSV file
with open(output_csv, "w", newline="") as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(["Hostname", "IP Address", "Empty Interfaces", "Total Empty Interfaces"])

    total_empty_interfaces = 0
    switch_empty_counts = {}

    for switch in switches:
        device = {
            "device_type": "cisco_ios",
            "host": switch["host"],
            "username": username,  # Use runtime credentials
            "password": password,
            "secret": password,  # Assuming enable password is the same
        }

        hostname = switch.get("hostname", switch["host"])  # Use hostname if available

        try:
            print(f"\n🔄 Connecting to {hostname} ({switch['host']})...")
            connection = ConnectHandler(**device)
            connection.enable()

            # Run command to get running config
            output = connection.send_command("show running-config")

            # Find interfaces that have NO configuration, ignoring unwanted ones
            matches = re.findall(empty_interface_pattern, output, re.MULTILINE)

            empty_count = len(matches)
            total_empty_interfaces += empty_count

            if empty_count > 0:
                switch_empty_counts[hostname] = empty_count
                csv_writer.writerow([hostname, switch["host"], ", ".join(matches), empty_count])
                print(f"⚠️ {hostname} - Found {empty_count} empty interface(s): {matches}")
            else:
                print(f"✅ {hostname} - No empty interfaces found.")

            connection.disconnect()

        except Exception as e:
            print(f"❌ Error connecting to {hostname} ({switch['host']}): {e}")

# Print Summary
print("\n=== 📊 Summary Report ===")
print(f"✅ Total switches checked: {len(switches)}")
print(f"⚠️ Total empty interfaces found: {total_empty_interfaces}")

if switch_empty_counts:
    print("\n🔥 Top switches with the most empty interfaces:")
    sorted_empty = sorted(switch_empty_counts.items(), key=lambda x: x[1], reverse=True)
    for switch, count in sorted_empty[:10]:  # Show top 10 problematic switches
        print(f"{switch}: {count} empty interfaces")

print(f"\n📁 Detailed report saved to {output_csv}")
