#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x fileping.sh'

# Define the output file
output_file="ip_output.txt"

# Empty the output file
> "$output_file"

# Define the RFC 1918 subnets to scan
declare -a rfc1918_ranges=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
)

# Function to ping and log results
ping_ip() {
    local ip=$1
    if ping -c 1 -i 0.5 -W 1 "$ip" &>/dev/null; then
        echo "$ip - did ping" | tee -a "$output_file"
    else
        echo "$ip - did not ping" | tee -a "$output_file"
    fi
}

# Function to determine subnet mask using ipcalc
get_subnet_mask() {
    local ip=$1
    ipcalc -n "$ip" | grep -o '\/[0-9]\+' | tr -d '/'
}

# Function to calculate all IPs in the subnet and ping each
scan_subnet() {
    local base_ip=$1
    local cidr=$2

    # Get network range using ipcalc
    local network_range=$(ipcalc -n "$base_ip/$cidr" | grep Network | awk '{print $2}')
    local start_ip="${network_range%.*}.0"

    # Loop through all IPs in the calculated subnet
    IFS=. read -r i1 i2 i3 i4 <<< "$start_ip"
    for ((i=1; i <= (1 << (32 - cidr)) - 2; i++)); do
        ip="${i1}.${i2}.${i3}.$((i + 1))"
        echo "Pinging $ip..."
        ping_ip "$ip"
    done
}

# Loop through RFC 1918 ranges and ping each .1 gateway
for range in "${rfc1918_ranges[@]}"; do
    IFS=. read -r prefix1 prefix2 <<< "$(echo "$range" | awk -F. '{print $1"."$2}')"

    for ((i=0; i < 256; i++)); do
        # Define gateway IP based on range
        gateway="${prefix1}.${prefix2}.${i}.1"
        echo "Checking gateway: $gateway"

        # Ping the .1 gateway
        if ping -c 1 -i 0.5 -W 1 "$gateway" &>/dev/null; then
            echo "$gateway - did ping" | tee -a "$output_file"
            
            # Determine subnet mask for this gateway
            cidr=$(get_subnet_mask "$gateway" || echo 24)  # Default to /24 if mask cannot be determined
            echo "Subnet mask determined as /$cidr for $gateway"

            # Scan the subnet if gateway responds
            scan_subnet "$gateway" "$cidr"
        else
            echo "$gateway - did not ping" | tee -a "$output_file"
        fi
    done
done

echo "Scanning completed. Results saved to $output_file."
