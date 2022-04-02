if __name__ == "__main__":
	"""
	Advertise routers.

	Usage:
		python3 -m agave.irdp.advertise <preference> <router> [router_2, ... [router_n]]
	
	Example:
		python3 -m agave.irdp.advertise 100 192.168.1.2
		python3 -m agave.irdp.advertise 100 192.168.1.2 192.168.1.5

	"""
	import socket, sys
	from agave.frames import irdp
	from agave.frames.core import Buffer
	from ipaddress import ip_address


	if len(sys.argv) < 3:
		print("Too few parameters")
	else:
		# creates socket and enable broadcast messages
		rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		rawsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		# parses arguments
		current_preference = int(sys.argv[1])
		preferences = []
		addresses = []
		for addr in sys.argv[2:]:
			addresses.append(ip_address(addr).packed)
			preferences.append(current_preference)
			current_preference -= 1
		# builds packet
		irdp_frame = irdp.IRDP.advertise(addresses, preferences)
		buf = Buffer.from_bytes()
		irdp_frame.write_to_buffer(buf)
		# send
		rawsocket.sendto(bytes(buf), ('255.255.255.255', 0))
		rawsocket.sendto(bytes(buf), ('224.0.0.1', 0))
		print("Advertise sent.")

