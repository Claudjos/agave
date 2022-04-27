"""Actively scan for APs.

Usage:
	python3 -m agv.wifi.scan <interface> [timeout]

Args:
	interface: interface to use.

Examples:
	python3 -m agv.wifi.scan mon0
	
"""
import socket, sys
from agave.models.ethernet import MACAddress
from agave.models.wifi.tags import (
	PARAM_DS_PARAMETER_SET, PARAM_RSN_INFORMATION, 
	TaggedParameterNotFound
)
from agave.utils.interfaces import NetworkInterface
from .jobs import Scanner
from .utils import create_socket


if __name__ == "__main__":
	# Check input
	if len(sys.argv) < 2:
		print("Too few parameters.")
		exit(0)
	# Parse input
	interface = NetworkInterface.get_by_name(sys.argv[1])
	wait = float(sys.argv[2]) if len(sys.argv) > 2 else 10
	# Create job
	job = Scanner(create_socket(interface), interface, [], 
		Scanner.build_probe_request(interface.mac, []), 
		repeat=3, interval=0.1, wait=wait)
	# Stream job results
	try:
		print("{:17} {:2} {:7} {:3} {}".format("BSSID", "Ch", "Privacy", "", "SSID"))
		for bssid, ssid, frame in job.stream():
			try:
				channel = frame.tags.get(PARAM_DS_PARAMETER_SET).channel
			except TaggedParameterNotFound:
				channel = ""
			try:
				rsn = frame.tags.get(PARAM_RSN_INFORMATION)
				rsn = "RSN"
			except TaggedParameterNotFound:
				rsn = ""
			privacy = "Secured" if frame.privacy else "OPEN"
			print(f"{bssid} {channel:2} {privacy:7} {rsn:3} {ssid}")
	except KeyboardInterrupt:
		print("\r   ", end="\r")
	# Requested
	reqs = job.get_requests()
	if len(reqs) > 0:
		print("SSID requested by others:")
		for ssid in reqs:
			print("\t", ssid)

