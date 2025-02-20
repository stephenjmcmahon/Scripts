# 📌 VLAN Sync - Automated VLAN Synchronization for Cisco Switches
This Python script automates VLAN synchronization across Cisco IOS-XE switches. It ensures VLAN name consistency by:
- **Fetching VLAN data from a core switch**
- **Allowing the user to review VLANs before applying changes**
- **Syncing access/distribution switches to match the core**
- **Logging all changes for auditing and troubleshooting**

# 📌 Installation & Setup

## 1️⃣ Install Python & Virtual Environment (Recommended)
It’s best to use a **Python virtual environment** to keep dependencies isolated.

**MacOS & Linux**

**Ensure Python 3 is installed**

    python3 --version

**Install virtualenv if not already installed**

    pip3 install virtualenv

**Create a virtual environment**

    python3 -m venv vlan-sync-env

**Activate the virtual environment**

    source vlan-sync-env/bin/activate

## 2️⃣ Install Dependencies
This script requires the following Python packages:

Netmiko (for SSH automation)
Argparse (for command-line arguments)
JSON (for handling VLAN data)
Datetime (for timestamped logs)
OS (for file handling)
Re (Regex) (for parsing switch output)
To install them manually, run:

    pip install netmiko

## 3️⃣ Set Up VLANs & Switches
Edit switches.json (Switch List)
Define the core switch (where VLANs are retrieved from).
List all distribution/access switches that need to be synced.
Note: core_vlans.json will be automatically created from the core switch.

# 🚀 Running the Script
The script supports command-line arguments to allow flexible execution.

## Fetch VLANs from the Core (Only)
    python3 vlan_sync.py --fetch
Connects to the core switch.
Retrieves VLANs and saves them in core_vlans.json.
Displays the VLAN list for review before syncing.

## Sync VLANs to Access Switches (Using Existing core_vlans.json)
     python3 vlan_sync.py --sync
Reads VLANs from core_vlans.json and applies them to access switches.

## Full Automation (Fetch VLANs & Sync)
    python3 vlan_sync.py --all
Fetches VLANs from the core and syncs them to access switches.
