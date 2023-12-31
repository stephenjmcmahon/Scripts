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
        echo "You can verify if Homebrew is installed and configured correctly by running 'brew --version' in the terminal."
        return 1
    fi

    if ! brew list "$package" | grep -q "$binary_path"; then
        echo "$package could not be found in the expected location, please ensure it is installed via Homebrew"
        echo "You can verify if $package is installed correctly by running 'brew list $package | grep $binary_path' in the terminal."
        return 1
    fi

    return 0
}

# Function to discover and cache the path of lldpcli with retry logic
discover_lldpcli_path() {
    local retries=3
    local attempt=1
    while [ $attempt -le $retries ]; do
        lldpcli_path=$(find "$(brew --prefix lldpd)/sbin" -name lldpcli 2>/dev/null)

        # Checking for multiple installations
        if [ -n "$lldpcli_path" ]; then
            if [ "$(echo "$lldpcli_path" | wc -l)" -gt 1 ]; then
                echo "More than one expected location for lldpcli was found, please resolve this issue."
                echo "You can review the multiple locations detected by running 'find "$(brew --prefix lldpd)/sbin" -name lldpcli 2>/dev/null' in the terminal."
                exit 1
            fi
            echo "$lldpcli_path" > "$HOME/.raycast_lldpcli_location"
            touch "$hidden_file"
            return 0
        fi

        echo "Attempt $attempt to find lldpcli failed. Retrying..."
        attempt=$((attempt + 1))
        sleep 1
    done

    echo "lldpcli could not be found after $retries attempts, please ensure lldpd is installed via Homebrew"
    echo "You can verify if lldpcli is installed correctly by running 'find \"$(brew --prefix lldpd)/sbin\" -name lldpcli 2>/dev/null' in the terminal."
    exit 1
}

# Function to run the lldpcli command
run_lldpcli() {
    # Run the lldpcli command with the 'show neighbors detail' argument and store output
    output=$("$lldpcli_path" show neighbors detail 2>&1)

    # If the command fails, recheck dependencies and try again
    if [[ $output == *"lldpcli: command not found"* ]]; then
        # Remove cached path
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
            echo "You can verify if lldpcli is installed correctly by running 'find \"$(brew --prefix lldpd)/sbin\" -name lldpcli 2>/dev/null' in the terminal."
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
        echo "Unable to run lldpd due to missing dependencies. Troubleshooting steps:"
        echo "1. Verify Homebrew installation: Run 'brew --version' and all below commands in the terminal."
        echo "   - If Homebrew is not installed, visit https://brew.sh for installation instructions."
        echo "2. Check if lldpd is installed: Run 'brew list lldpd'."
        echo "   - If lldpd is not installed, run 'brew install lldpd' to install it."
        echo "3. Verify 'lldpcli' installation and location: Run 'find \"$(brew --prefix lldpd)/sbin\" -name lldpcli 2>/dev/null'."
        echo "   - There should only be one instance of 'lldpcli' present. If multiple or none are found, ensure lldpd installation is correct."
        echo "After addressing these steps, please retry running this script."
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

# If lldpcli path not found, attempt rediscovery
if [ -z "$lldpcli_path" ]; then
    echo "Cached lldpcli path not found. Attempting to rediscover..."
    discover_lldpcli_path

    # Recheck if lldpcli path is now available
    if [ -f "$HOME/.raycast_lldpcli_location" ]; then
        lldpcli_path=$(cat "$HOME/.raycast_lldpcli_location")
    fi

    # If lldpcli still not found, exit with an error
    if [ -z "$lldpcli_path" ]; then
        echo "lldpcli could not be found in the expected location, please ensure it is installed via Homebrew"
        echo "You can verify if lldpcli is installed correctly by running 'find \"$(brew --prefix lldpd)/sbin\" -name lldpcli 2>/dev/null' in the terminal."
        exit 1
    fi
fi

# Run the lldpcli command function
run_lldpcli
