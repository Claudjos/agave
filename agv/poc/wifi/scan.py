"""Actively scan for APs.

Usage:
	python3 -m agv.poc.wifi.scan <interface> [[SSID], ...]

Args:
	interface: interface to use.
	SSID: list of SSIDs. If used, scan stops when these SSIDs are found.

Examples:
	python3 -m agv.poc.wifi.scan phy0.mon
	python3 -m agv.poc.wifi.scan phy0.mon MyWiFi OtherSSID
	
"""
import socket, sys
from agave.core.ethernet import MACAddress
from agave.utils.interfaces import NetworkInterface
from agv.jobs.wifi import Scanner


if __name__ == "__main__":
	# Check input
	if len(sys.argv) < 2:
		print("Too few parameters.")
		exit(0)
	# Parse input
	interface = NetworkInterface.get_by_name(sys.argv[1])
	ssids = [sys.argv[i] for i in range(2, len(sys.argv))]
	# Creates socket
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind((interface.name, 0))
	# Create job
	job = Scanner(sock, interface, ssids, 
		Scanner.build_probe_request(interface.mac, ssids), 
		repeat=3, interval=0.1, wait=10 if len(ssids) == 0 else 1)
	# Stream job results
	for mac, ssid, settings in job.stream():
		print(f"{ssid} ({mac})")
	# Other
	others = job.get_others()
	if len(others) > 0:
		print("Other APs found:")
		for mac, ssid, settings in others:
			print(f"\t{ssid} ({mac})")
	# Requested
	reqs = job.get_requests()
	if len(reqs) > 0:
		print("SSID requested by others:")
		for ssid in reqs:
			print("\t", ssid)

