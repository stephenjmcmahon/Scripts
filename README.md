# Scripts

Scripts for personal use at work at home.

## Bash

* **File Ping:** Reads a list of IP addresses from an input file named `ip_list.txt`, pings each IP once at an interval of 0.5 seconds, and provides output indicating whether each IP did respond or did not respond. The output is both displayed in the console and written in an output file named `ip_result.txt`.

## Raycast

* **LLDP:** Show detailed LLDP (Link Layer Discovery Protocol) neighbor(s) info using lldpd.
* **MAC Format:** Formats a given MAC address into a standard format: lowercase with colons every two characters.
* **MAC Lookup:** Checks if the provided MAC address is randomized, formats it, and looks up the MAC vendor using the macvendorlookup API which is graciously provided for free.
* **MTR:** Opens a terminal window and runs the mtr command with the IP provided.
* **Trippy MTR:** Opens a terminal window and runs the trip command with the IP or hostname provided in either unprivileged or privileged mode.
