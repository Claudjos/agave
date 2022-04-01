from agave.modules.arp.resolve import resolve
from agave.modules.arp.discover import discover, r_discover
from agave.modules.nic.interfaces import NetworkInterface, NetworkInterfaceNotFound


def arp_discover(argv):
	_discover(argv, discover)


def resolve_discover(argv):
	_discover(argv, r_discover)


def _discover(argv, call):
	if len(argv) < 1:
		print("Too few parameters")
	else:
		print("Looking for hosts...")
		subnet = argv[1] if len(argv) > 1 else None
		for mac, ip in call(argv[0], subnet=subnet):
			print("{}\t{}".format(ip, str(mac)))


def resolve_mac(argv):
	if len(argv) < 1:
		print("Too few parameters")
	else:
		mac = resolve(NetworkInterface.get_by_host(argv[0]), argv[0])
		print("Host not found" if mac is None else str(mac))
