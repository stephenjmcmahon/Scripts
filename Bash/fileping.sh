#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x fileping.sh'

# Define the input and output files
input_file="ip_list.txt"
output_file="ip_result.txt"

# Empty the output file
> $output_file

# Read the file line by line
while IFS= read -r line
do
    # Ping the IP address with a 0.5 second interval between pings
    ping -c 1 -i 0.5 "$line" >/dev/null

    # Check the exit status of the ping command
    if [ $? -eq 0 ];
    then
        echo "$line - did ping" | tee -a $output_file
    else
        echo "$line - did not ping" | tee -a $output_file
    fi
done < "$input_file"
