import json
import re

def convert_to_json(input_file, output_file="switches.json"):
    """Converts a list of hostnames and IPs into the required JSON format for VLAN Sync."""
    switches = []

    with open(input_file, "r") as file:
        lines = file.readlines()

    for line in lines:
        # Allow both tab (`\t`) and space (` `) as separators
        parts = re.split(r'\s+', line.strip())  # Splitting on any whitespace (tab or space)

        if len(parts) == 2:
            hostname, ip = parts
            switches.append({"hostname": hostname, "ip": ip})

    if not switches:
        print("❌ No valid entries found. Ensure your input file is formatted correctly (hostname <TAB> IP or hostname <SPACE> IP).")
        return

    # Prompt user for core switch details
    print("\n🔹 Do you want to set the core switch now?")
    set_core = input("Type 'yes' to enter it now, or 'no' to do it manually later: ").strip().lower()

    if set_core == "yes":
        core_hostname = input("Enter the Core Switch Hostname: ").strip()
        core_ip = input("Enter the Core Switch IP Address: ").strip()
        core_switch = {"hostname": core_hostname, "ip": core_ip}
        print("\n✅ Core switch set successfully!\n")
    else:
        core_switch = {"hostname": "", "ip": ""}
        print("\n⚠️  You must manually edit `switches.json` and set the core switch before running VLAN Sync.\n")

    # Construct JSON structure
    json_data = {
        "core_switch": core_switch,
        "switches": switches
    }

    # Save to output JSON file
    with open(output_file, "w") as json_out:
        json.dump(json_data, json_out, indent=4)

    print(f"✅ Conversion complete! JSON saved to `{output_file}`")

# Example usage
input_filename = "switches_list.txt"  # Change this to your input file
convert_to_json(input_filename)
