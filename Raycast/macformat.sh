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
# @raycast.description Formats a MAC address into all common formats: colon/dash separated, upper/lowercase.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon
import sys
import re

def format_mac_address(mac_address: str) -> dict:
    """
    Formats the MAC address into colon and dot-separated formats (lowercase).
    
    Args:
    mac_address (str): The MAC address in any format.
    Returns:
    dict: Dictionary with colon and dot formats.
    """
    # Remove all non-alphanumeric characters
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address).lower()
    
    # Validate length
    if len(clean_mac) != 12:
        return None
    
    # Colon every 2 characters: aa:bb:cc:dd:ee:ff
    colon = ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
    
    # Dot every 4 characters: aabb.ccdd.eeff
    dot = '.'.join(clean_mac[i:i+4] for i in range(0, 12, 4))
    
    return {'colon': colon, 'dot': dot}

if __name__ == "__main__":
    # Read the MAC address from the first command-line argument
    input_mac_address = sys.argv[1] if len(sys.argv) > 1 else ""
    
    if input_mac_address:
        formats = format_mac_address(input_mac_address)
        if formats:
            print(formats['colon'])
            print(formats['dot'])
        else:
            print("Invalid MAC address. Please provide 12 hexadecimal characters.")
    else:
        print("No MAC address provided.")
