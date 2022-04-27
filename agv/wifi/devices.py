"""Retrieves devices connected to a BSS.

Usage:
	python3 -m agv.wifi.devices <bss> <interface> [timeout]

Args:
	bssid: SSID or BSSID.
	interface: interface to use.
	timeout: seconds to wait before to stop.

Examples:
	python3 -m agv.wifi.devices MyWiFi phy0.mon
	python3 -m agv.wifi.devices MyWiFi phy0.mon 5
	
"""
import sys
from .jobs import list_bss_clients
from .utils import create_socket
from .misc import read_bssid_or_die, read_interface_or_die


if __name__ == "__main__":
	# Parse arguments
	interface = read_interface_or_die(sys.argv[2])
	bssid = read_bssid_or_die(sys.argv[1], interface)
	wait = float(sys.argv[3]) if len(sys.argv) > 3 else None
	# Loop
	try:
		for i in list_bss_clients(bssid, create_socket(interface), wait=wait):
			print(i)
	except KeyboardInterrupt:
		pass

