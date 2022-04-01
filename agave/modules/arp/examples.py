from agave.modules.arp.resolve import resolve, discover as rdiscover
from agave.modules.arp.discover import discover
from agave.modules.nic.interfaces import NetworkInterface, NetworkInterfaceNotFound
from .listen import Network


def arp_discover(argv):
	if len(argv) < 1:
		print("Too few parameters")
	else:
		print("Looking for hosts...")
		subnet = argv[1] if len(argv) > 1 else None
		for op, ip, mac in discover(argv[0], subnet=subnet):
			print("[{}] {}\t{}".format(
				Network.OP[op],
				ip,
				mac
			))


def resolve_discover(argv):
	if len(argv) < 1:
		print("Too few parameters")
	else:
		print("Looking for hosts...")
		subnet = argv[1] if len(argv) > 1 else None
		for mac, ip in rdiscover(argv[0], subnet=subnet):
			print("{}\t{}".format(ip, str(mac)))


def resolve_mac(argv):
	if len(argv) < 1:
		print("Too few parameters")
	else:
		mac = resolve(NetworkInterface.get_by_host(argv[0]), argv[0])
		print("Host not found" if mac is None else str(mac))
