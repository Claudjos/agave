from agave.modules.arp.resolve import resolve
from agave.modules.arp.discover import discover, r_discover
from agave.modules.arp.listen import Listener, HOST
from agave.modules.nic.interfaces import NetworkInterface, NetworkInterfaceNotFound, MACAddress
from ipaddress import IPv4Address


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


def arp_listen(args):
	print("Listening...")
	MyListener().run()


class MyListener(Listener):

	def on_node_discovery(self, host: HOST):
		print("New host discovered {} {}".format(host[0], host[1]), flush=True)

	def on_link_discovery(self, sender: HOST, target: HOST):
		print("New communication discovered {} {}".format(sender[1], target[1]), flush=True)

	def on_mac_change(self, ip: IPv4Address, old_mac: MACAddress, new_mac: MACAddress):
		print("MAC addressed associated to {} changed from {} to {}".format(
			ip, old_mac, new_mac
		), flush=True)

	def on_gratuitous_reply(self, sender: HOST, target: HOST):
		print("A reply {} {} came without {} requesting it".format(
			sender[0], sender[1], target[1]
		), flush=True)
