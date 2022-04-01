import sys
from .modules.icmp import discover, redirect
from .modules.irdp import advertise, solicit as solicit2
from .examples import arp
from .examples import nic


if len(sys.argv) < 2:
	logging.error(f"Too few parameters")
	exit(1)


protocol = sys.argv[1].upper()
command = sys.argv[2].upper()
argv = sys.argv[3:]


MAP = {
	"NIC": {
		"INFO": nic.main
	},
	"ARP": {
		"LISTEN": arp.arp_listen,
		"DISCOVER": arp.arp_discover,
		"MITM": arp.arp_man_in_the_middle,
		"RESOLVE": arp.resolve_mac,
		"RDISCOVER": arp.resolve_discover
	},
	"ICMP": {
		"DISCOVER": discover.main,
		"REDIRECT": redirect.main
	},
	"IRDP": {
		"ADVERTISE": advertise.main,
		"SOLICIT": solicit2.main
	}
}


if protocol in MAP:
	if command in MAP[protocol]:
		MAP[protocol][command](argv)
	else:
		print(f"Unknown command '{command}' for protocol {protocol}")
else:
	print(f"Unknown protocol '{protocol}'")
