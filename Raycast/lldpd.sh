#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x lldpd.sh'

# Metadata for configuration of the command in Raycast
# @raycast.schemaVersion 1
# @raycast.title Show LLDP Neighbor(s)
# @raycast.mode fullOutput
# @raycast.icon 💻 
# @raycast.packageName Network

# Documentation:
# @raycast.description Show detailed LLDP (Link Layer Discovery Protocol) neighbor(s) info using lldpd.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon
# @raycast.dependencies Homebrew (https://brew.sh/), lldpd (https://formulae.brew.sh/formula/lldpd)
# @raycast.credit lldpd (https://github.com/lldpd/lldpd)

# Hidden file path
hidden_file="$HOME/.raycast_lldpd_checked"

# Function to check if a given package is installed
check_package_installation() {
    local package=$1
    local binary_path=$2

    if ! command -v brew &> /dev/null; then
        echo "Homebrew could not be found, please ensure it is installed and in the PATH"
        return 1
    fi

    if ! brew list "$package" | grep -q "$binary_path"; then
        echo "$package could not be found in the expected location (brew list $package | grep $binary_path), please ensure it is installed via Homebrew"
        return 1
    fi

    return 0
}

# Function to discover and cache the path of lldpcli
discover_lldpcli_path() {
    lldpcli_path=$(find "$(brew --prefix lldpd)/sbin" -name lldpcli 2>/dev/null)

    if [ -z "$lldpcli_path" ]; then
        echo "lldpcli could not be found, please ensure lldpd is installed via Homebrew"
        exit 1
    fi

    if [ "$(echo "$lldpcli_path" | wc -l)" -gt 1 ]; then
        echo "More than one expected location for lldpcli was found. Please resolve this issue."
        exit 1
    fi

    echo "$lldpcli_path" > "$HOME/.raycast_lldpcli_location"
    touch "$hidden_file"
}

# Function to run the lldpcli command
run_lldpcli() {
    # Run the lldpcli command with the 'show neighbors detail' argument and store output
    output=$("$lldpcli_path" show neighbors detail 2>&1)

    # If the command fails, recheck dependencies and try again
    if [[ $output == *"lldpcli: command not found"* ]]; then
        # remove cached path
        rm "$HOME/.raycast_lldpcli_location"
        # Recheck dependencies
        check_package_installation "lldpd" "sbin/lldpd"
        # Try to re-discover the path
        discover_lldpcli_path
        # Rerun the command if the path is found
        if [ -n "$lldpcli_path" ]; then
            output=$("$lldpcli_path" show neighbors detail 2>&1)
        else
            echo "lldpcli could not be found, please ensure it is installed via Homebrew"
            exit 1
        fi
    fi

    # Print the output
    echo "$output"
}

# Perform checks if hidden file does not exist
if [[ ! -e "$hidden_file" ]]; then
    echo "Setting up for the first time. Caching for speed..."
    if ! check_package_installation "lldpd" "sbin/lldpd"; then
        echo "Unable to run lldpd due to missing dependencies."
        exit 1
    fi
    discover_lldpcli_path
fi

# Default empty path for lldpcli
lldpcli_path=""

# Checking if a cached lldpcli location exists
if [ -f "$HOME/.raycast_lldpcli_location" ]; then
    lldpcli_path=$(cat "$HOME/.raycast_lldpcli_location")
fi

# If lldpcli still not found, exit with an error
if [ -z "$lldpcli_path" ]; then
    echo "lldpcli could not be found in the expected location, please ensure it is installed via Homebrew"
    exit 1
fi

# Run the lldpcli command function
run_lldpcli
