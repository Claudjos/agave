import sys
import logging
from .modules import arp_listen, arp_stimulate


if len(sys.argv) < 2:
	logging.error(f"Too few parameters")
	exit(1)


protocol = sys.argv[1]
command = sys.argv[2]
argv = sys.argv[3:]


if protocol.upper() == "ARP":
	if command.upper() == "LISTEN":
		arp_listen.main(argv)
	elif command.upper() == "STIMULATE":
		arp_stimulate.main(argv)
	else:
		logging.error(f"Unknown command '{command}' for protocol {protocol}")
else:
	logging.error(f"Unknown protocol '{protocol}'")
