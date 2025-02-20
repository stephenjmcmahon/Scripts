import json

def convert_to_json(input_file, output_file="switches.json"):
    """Converts a list of hostnames and IPs into the required JSON format for VLAN Sync."""
    switches = []

    with open(input_file, "r") as file:
        lines = file.readlines()

    for line in lines:
        parts = line.strip().split("\t")  # Splitting on tab
        if len(parts) == 2:
            hostname, ip = parts
            switches.append({"hostname": hostname, "ip": ip})

    if not switches:
        print("❌ No valid entries found. Ensure your input file is formatted correctly.")
        return

    # Leave core_switch blank for manual entry
    json_data = {
        "core_switch": {
            "hostname": "",
            "ip": ""
        },
        "switches": switches
    }

    # Save to output JSON file
    with open(output_file, "w") as json_out:
        json.dump(json_data, json_out, indent=4)

    print(f"✅ Conversion complete! JSON saved to {output_file}")
    print("🔹 Please manually update 'core_switch' in switches.json before running VLAN Sync.")

# Example usage
input_filename = "switches_list.txt"  # Change this to your input file
convert_to_json(input_filename)
