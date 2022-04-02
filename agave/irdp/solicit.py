"""
Solicits routers to advertise.

Usage:
	python3 -m agave.irdp.solicit

Example:
	python3 -m agave.irdp.solicit

"""
from agave.frames import irdp
from agave.frames.core import Buffer
import socket, sys


if __name__ == "__main__":

	# creates socket and enable broadcast messages
	rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	rawsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	# builds packet
	irdp_frame = irdp.IRDP.solicitation()
	buf = Buffer.from_bytes()
	irdp_frame.write_to_buffer(buf)
	# send
	rawsocket.sendto(bytes(buf), ('255.255.255.255', 0))
	print("Solicit sent.")

