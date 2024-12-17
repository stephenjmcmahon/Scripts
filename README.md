# Scripts

Scripts for personal use at work at home.

## Bash

* **File Ping:** Reads a list of IP addresses from an input file named `ip_list.txt`, pings each IP once at an interval of 0.5 seconds, and provides output indicating whether each IP did respond or did not respond. The output is both displayed in the console and written in an output file named `ip_result.txt`.
* **Folder Renamer by File:** A versatile script that renames subfolders based on a specific file inside each folder. When executed, it prompts the user for a filename pattern (e.g., *.mp4, *.txt, example.docx). It then searches each subfolder for a matching file, extracts the file's name (without extension), sanitizes it, and renames the folder to match. This is ideal for organizing content like videos, reports, or other files into meaningful folder names.
* **Subnet Sweeper:** Network discovery tool designed to scan private IP address ranges (RFC 1918) and identify active gateway addresses. It pings .1 gateway addresses within each subnet in the specified ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). If a gateway responds, Subnet Sweeper proceeds to dynamically assess the subnet size and scan each address in that subnet, reporting back on active IPs. The results are logged in a text file, providing a quick overview of reachable devices and networks in local or lab environments.

## Raycast

* **LLDP:** Show detailed LLDP (Link Layer Discovery Protocol) neighbor(s) info using lldpd.
* **MAC Format:** Formats a given MAC address into a standard format: lowercase with colons every two characters.
* **MAC Lookup:** Checks if the provided MAC address is randomized, formats it, and looks up the MAC vendor using the macvendorlookup API which is graciously provided for free.
* **MTR:** Opens a terminal window and runs the mtr command with the IP provided.
* **Trippy MTR:** Opens a terminal window and runs the trip command with the IP or hostname provided in either unprivileged or privileged mode.
