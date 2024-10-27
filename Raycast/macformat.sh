#!/usr/bin/env python3

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x formatmac.sh'

# Metadata for configuration of the command in Raycast
# @raycast.schemaVersion 1
# @raycast.title Format MAC Address
# @raycast.mode fullOutput
# @raycast.icon 💻
# @raycast.packageName Utility
# @raycast.argument1 { "type": "text", "placeholder": "Enter MAC Address" }

# Documentation:
# @raycast.description This script formats a given MAC address into a standard format: lowercase with colons every two characters.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon

import sys
import re

def format_mac_address(mac_address: str) -> str:
    """
    Formats the MAC address to the standard format: lowercase with colons.
    
    Args:
    mac_address (str): The MAC address in input format.

    Returns:
    str: The MAC address in standard format.
    """
    # Remove all non-alphanumeric characters
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address)
    # Convert to lowercase
    clean_mac = clean_mac.lower()
    # Insert ':' every 2 characters
    formatted_mac = ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
    return formatted_mac

if __name__ == "__main__":
    # Read the MAC address from the first command-line argument
    input_mac_address = sys.argv[1] if len(sys.argv) > 1 else ""
    if input_mac_address:
        # Format the MAC address and print it
        formatted_mac = format_mac_address(input_mac_address)
        print(formatted_mac)
    else:
        # Print an error message if no MAC address was provided
        print("No MAC address provided.")
