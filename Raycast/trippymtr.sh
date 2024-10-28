#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x trippymtr.sh'

# Metadata for configuration of the command in Raycast
# @raycast.schemaVersion 1
# @raycast.title Run Trippy MTR Command
# @raycast.mode fullOutput
# @raycast.icon 🌐
# @raycast.packageName Network
# @raycast.argument1 { "type": "text", "placeholder": "Enter IP or Hostname" }
# @raycast.argument2 { "type": "text", "placeholder": "Enter Mode (u for unprivileged, p for privileged)" }

# Documentation:
# @raycast.description This script opens a terminal window and runs the trip command with the IP or hostname provided in either unprivileged or privileged mode.
# @raycast.author Stephen McMahon
# @raycast.authorURL https://github.com/stephenjmcmahon
# @raycast.dependencies Homebrew (https://brew.sh/), trippy (https://github.com/fujiapple852/trippy)
# @raycast.credit trip (https://github.com/fujiapple852/trippy)

# Hidden file path
hidden_file="$HOME/.raycast_trip_checked"

# Function to check if Trippy is installed and Trip is in PATH
check_dependencies() {
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew could not be found, please ensure it is installed and in the PATH."
        return 1
    fi

    # Check if Trippy package is installed
    if ! brew list trippy &> /dev/null; then
        echo "Trippy package could not be found. Please install it via Homebrew with 'brew install trippy'."
        return 1
    fi

    # Check if Trip command is available
    if ! command -v trip &> /dev/null; then
        echo "Trip command not found. Ensure 'trip' is in the PATH."
        return 1
    fi

    # Mark as checked
    touch "$hidden_file"
}

# IP address or hostname from Raycast prompt
address=$1
mode=$2

# Validate mode
if [[ "$mode" != "u" && "$mode" != "p" ]]; then
    echo "Invalid mode provided. Please enter 'u' for unprivileged or 'p' for privileged mode."
    exit 1
fi

# Function to run Trip with the provided IP or hostname and chosen mode
run_trip() {
    if [[ "$mode" == "u" ]]; then
        osascript \
        -e "tell application \"Terminal\"" \
        -e "activate" \
        -e "do script \"trip -u $address\"" \
        -e "end tell"
    else
        osascript \
        -e "tell application \"Terminal\"" \
        -e "activate" \
        -e "do script \"sudo trip $address\"" \
        -e "end tell"
    fi
}

# Perform checks if hidden file does not exist
if [[ ! -e "$hidden_file" ]]; then
    echo "Setting up for the first time. Caching for speed..."

    if ! check_dependencies; then
        echo "Unable to run Trip due to missing dependencies. Ensure 'trippy' is installed and 'trip' is in the PATH."
        exit 1
    fi
    echo "First time setup checks completed successfully."
fi

# Try to run Trip
run_trip
