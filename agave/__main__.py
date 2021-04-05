import sys
from .modules import arp_listen, arp_solicit, arp_mitm
from .modules import icmp_discover


if len(sys.argv) < 2:
	logging.error(f"Too few parameters")
	exit(1)


protocol = sys.argv[1].upper()
command = sys.argv[2].upper()
argv = sys.argv[3:]


MAP = {
	"ARP": {
		"LISTEN": arp_listen.main,
		"SOLICIT": arp_solicit.main,
		"MITM": arp_mitm.main
	},
	"ICMP": {
		"DISCOVER": icmp_discover.main
	}
}

if protocol in MAP:
	if command in MAP[protocol]:
		MAP[protocol][command](argv)
	else:
		print(f"Unknown command '{command}' for protocol {protocol}")
else:
	print(f"Unknown protocol '{protocol}'")
