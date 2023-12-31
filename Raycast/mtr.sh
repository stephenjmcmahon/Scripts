#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x mtr.sh'

# Metadata for configuration of the command in Raycast
# @raycast.schemaVersion 1
# @raycast.title Run MTR Command
# @raycast.mode fullOutput
# @raycast.icon 🌐
# @raycast.packageName Network
# @raycast.argument1 { "type": "text", "placeholder": "Enter IP Address" }

# Documentation:
# @raycast.description This script opens a terminal window and runs the mtr command with the IP provided.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon
# @raycast.dependencies Homebrew (https://brew.sh/), mtr (https://formulae.brew.sh/formula/mtr)
# @raycast.credit mtr (https://github.com/traviscross/mtr)

# Hidden file path
hidden_file="$HOME/.raycast_mtr_checked"

# Function to check Homebrew and MTR
check_dependencies() {
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew could not be found, please ensure it is installed and in the PATH"
        return 1
    fi

    # Check if MTR is installed
    if ! brew list mtr | grep -q 'sbin/mtr'; then
        echo "MTR could not be found in the expected location (brew list mtr | grep sbin/mtr), please ensure it is installed via Homebrew"
        return 1
    fi

    # Mark as checked
    touch "$hidden_file"
}

# Function to validate IPv4 address
validate_ip() {
    local ip=$1
    local stat=1

    # Regex for IPv4
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        stat=0
    fi

    return $stat
}

# IP address from Raycast prompt
ip_address=$1

# Function to run MTR with the provided IP address
run_mtr() {
    osascript \
    -e "tell application \"Terminal\"" \
    -e "activate" \
    -e "do script \"mtr $ip_address\"" \
    -e "end tell"
}

# Perform checks if hidden file does not exist
if [[ ! -e "$hidden_file" ]]; then
    echo "Setting up for the first time. Caching for speed..."

    if ! check_dependencies; then
        echo "Unable to run MTR due to missing dependencies. Troubleshooting steps:"
        echo "1. Verify Homebrew installation: Run 'brew --version' and all below commands in the terminal."
        echo "   - If Homebrew is not installed, visit https://brew.sh for installation instructions."
        echo "2. Check if MTR is installed: Run 'brew list mtr'."
        echo "   - If MTR is not installed, run 'brew install mtr' to install it."
        echo "3. Verify MTR installation and location: Run 'brew list mtr | grep -q 'sbin/mtr'."
        echo "After addressing these steps, please retry running this script."
        exit 1
    fi
    echo "First time setup checks completed successfully."
fi

# Validate IPv4 address
if ! validate_ip "$ip_address"; then
    echo "Invalid IPv4 address provided. Please enter a valid IPv4 address."
    exit 1
fi

# Try to run MTR
run_mtr
