#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x maclookup.sh'

# Metadata for configuration in Raycast
# @raycast.schemaVersion 1
# @raycast.title Lookup MAC Address
# @raycast.mode fullOutput
# @raycast.icon 💻
# @raycast.packageName Network
# @raycast.argument1 { "type": "text", "placeholder": "Enter MAC Address" }

# Documentation:
# @raycast.description This script checks if the provided MAC address is randomized, formats it, and looks up the MAC vendor using the macvendorlookup API.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon
# @raycast.credit Idea and print emojis layout from https://www.raycast.com/olavgjerde/looksee and macvendorlookup (https://www.macvendorlookup.com/)
# @raycast.dependencies curl, python3

# MAC address input from Raycast argument
input_mac=$1

# Function to format the MAC address using Python
format_mac_address() {
    local mac=$1
    python3 - <<END
import re

def format_mac_address(mac_address: str) -> str:
    """
    Formats the MAC address to the standard format: lowercase with colons.
    """
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address).lower()
    return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))

print(format_mac_address("$mac"))
END
}

# Function to check if a MAC address is private
is_private_mac() {
    local mac_address=$1
    local first_byte_second_hex=${mac_address:1:1}

    # Check if the second hex digit is 2, 6, A, or E (indicating a randomized/private MAC)
    if [[ "$first_byte_second_hex" =~ [26AEae] ]]; then
        return 0  # Return 0 (true) if the MAC address is private
    else
        return 1  # Return 1 (false) if the MAC address is public
    fi
}

# Format the MAC address entered by the user
mac_address=$(format_mac_address "$input_mac")

# Validate MAC address format (basic check for correct length and format)
if [[ ! "$mac_address" =~ ^([0-9a-f]{2}:){5}([0-9a-f]{2})$ ]]; then
    echo "Invalid MAC address format. Please enter a valid MAC address."
    exit 1
fi

# Check if the MAC address is private
if is_private_mac "$mac_address"; then
    echo "This is a randomized MAC address and cannot be looked up."
    exit 0
fi

# Perform the API lookup if the MAC address is not private
response=$(curl -s "https://www.macvendorlookup.com/api/v2/${mac_address}")

# Format the response for readability
if [[ "$response" == "[]" ]]; then
    echo "MAC address not found in the database."
else
    # Display the formatted MAC address and the response fields
    echo -e "$mac_address\n"
    echo "$response" | \
    sed -e 's/[{}"]/ /g' -e 's/]//g' | \
    awk -F ',' '{
        for (i=1; i<=NF; i++) {
            if ($i ~ /startHex/) { sub(/.*startHex *: */, "", $i); start_hex=$i }
            if ($i ~ /endHex/) { sub(/.*endHex *: */, "", $i); end_hex=$i }
            if ($i ~ /startDec/) { sub(/.*startDec *: */, "", $i); start_dec=$i }
            if ($i ~ /endDec/) { sub(/.*endDec *: */, "", $i); end_dec=$i }
            if ($i ~ /company/) { sub(/.*company *: */, "", $i); company=$i }
            if ($i ~ /addressL1/) { sub(/.*addressL1 *: */, "", $i); address1=$i }
            if ($i ~ /addressL2/) { sub(/.*addressL2 *: */, "", $i); address2=$i }
            if ($i ~ /addressL3/) { sub(/.*addressL3 *: */, "", $i); address3=$i }
            if ($i ~ /country/) { sub(/.*country *: */, "", $i); country=$i }
            if ($i ~ /type/) { sub(/.*type *: */, "", $i); type=$i }
        }
        # Print structured information with labels for each field
        printf "🌍 Country: %s\n", country
        printf "🏢 Company: %s\n", company
        printf "📫 Address L1: %s\n", address1
        printf "📫 Address L2: %s\n", address2
        printf "📫 Address L3: %s\n", address3
        printf "📠 Hex start: %s\n", start_hex
        printf "📠 Hex end: %s\n", end_hex
        printf "📠 Dec start: %s\n", start_dec
        printf "📠 Dec end: %s\n", end_dec
        printf "📜 Type: %s\n", type
    }'
fi
