"""Retrieves BSSID given a SSID.

Usage:
	python3 -m agv.wifi.bssid <ssid> <interface>

Args:
	ssid: SSID.
	interface: interface to use.

Examples:
	python3 -m agv.wifi.bssid MyWifi mon0

"""
import sys
from agave.utils.interfaces import NetworkInterfaceNotFound
from .jobs import ServiceSetNotFound, get_service_set_address


if __name__ == "__main__":
	# Parse arguments
	interface = sys.argv[2]
	ssid = sys.argv[1]
	try:
		print(get_service_set_address(ssid, interface))
	except ServiceSetNotFound:
		print("Couldn't find a SS {}".format(ssid))
	except NetworkInterfaceNotFound as e:
		print(e)

