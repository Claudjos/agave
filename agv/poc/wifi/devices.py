import sys
from agv.blocks.wifi import create_socket, list_bss_clients
from agv.misc import read_bssid_or_die, read_interface_or_die


if __name__ == "__main__":
	# Parse arguments
	interface = read_interface_or_die(sys.argv[2])
	bssid = read_bssid_or_die(sys.argv[1], interface)
	wait = None if len(sys.argv) < 3 else float(sys.argv[3])
	# Loop
	try:
		for i in list_bss_clients(bssid, create_socket(interface), wait=wait):
			print(i)
	except KeyboardInterrupt:
		pass

