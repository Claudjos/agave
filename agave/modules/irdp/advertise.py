from agave.frames import irdp
from agave.frames.core import Buffer
from ipaddress import ip_address
import socket


def main(argv):

	rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	rawsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	current_preference = int(argv[0])
	preferences = []
	addresses = []
	for addr in argv[1:]:
		addresses.append(ip_address(addr).packed)
		preferences.append(current_preference)
		current_preference -= 1

	irdp_frame = irdp.IRDP.advertise(addresses, preferences)
	buf = Buffer.from_bytes()
	irdp_frame.write_to_buffer(buf)

	rawsocket.sendto(bytes(buf), ('255.255.255.255', 0))
	rawsocket.sendto(bytes(buf), ('224.0.0.1', 0))
