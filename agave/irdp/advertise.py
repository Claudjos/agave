"""
Advertises routers.

Usage:
	python3 -m agave.irdp.advertise <preference> <router> [...[<preference> <router>]]

Example:
	python3 -m agave.irdp.advertise 100 192.168.1.2
	python3 -m agave.irdp.advertise 100 192.168.1.2 40 192.168.1.5

"""
if __name__ == "__main__":

	import socket, sys
	from agave.core.irdp import IRDP, ROUTER_ADVERTISMENT_MULTICAST_ADDRESS
	from agave.core.buffer import Buffer
	from ipaddress import ip_address

	
	if len(sys.argv) < 3:
		print("Too few arguments")
	elif (len(sys.argv) -1 ) % 2 != 0:
		print("Malformed arguments")
	else:
		# creates socket and enable broadcast messages
		rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		rawsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		# parses arguments
		preferences = []
		addresses = []
		for i in range(1, len(sys.argv), 2):
			preferences.append(int(sys.argv[i]))
			addresses.append(ip_address(sys.argv[i+1]).packed)
		# builds packet
		irdp_frame = IRDP.advertise(addresses, preferences)
		buf = Buffer.from_bytes()
		irdp_frame.write_to_buffer(buf)
		# send
		rawsocket.sendto(bytes(buf), (ROUTER_ADVERTISMENT_MULTICAST_ADDRESS, 0))
		print("Advertise sent.")

