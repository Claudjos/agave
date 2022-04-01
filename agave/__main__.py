import sys
from .modules.arp import mitm
from .modules.icmp import discover, redirect
from .modules.irdp import advertise, solicit as solicit2
from .examples.arp import resolve_mac, resolve_discover, arp_discover, arp_listen
from .examples.nic import main as iface


if len(sys.argv) < 2:
	logging.error(f"Too few parameters")
	exit(1)


protocol = sys.argv[1].upper()
command = sys.argv[2].upper()
argv = sys.argv[3:]


MAP = {
	"NIC": {
		"INFO": iface
	},
	"ARP": {
		"LISTEN": arp_listen,
		"DISCOVER": arp_discover,
		"MITM": mitm.main,
		"RESOLVE": resolve_mac,
		"RDISCOVER": resolve_discover
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
