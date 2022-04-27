"""Primitives to resolve IPv4 addresses into MAC addresses.

Note:
	This module also provides a script to retrieve the MAC
	address(es) given an IPv4 or subnet.

Usage:
	python3 -m agave.arp.resolve <IPv4|subnet> [interface]

Example:
	python3 -m agave.arp.resolve 192.168.0.1
	python3 -m agave.arp.resolve 192.168.0.0/24
	python3 -m agave.arp.resolve 192.168.1.0/24 wlan0

"""
import select, time
from typing import Union, Iterator
from .utils import _create_socket, _parse as parse_arp, SOCKET_PROTO
from .utils import Host, create_filter
from agave.models.ethernet import MACAddress, Ethernet
from agave.models.arp import ARP, OPERATION_REPLY
from agave.utils.jobs import SocketAddress, Job
from agave.utils.interfaces import NetworkInterface
from ipaddress import IPv4Address, IPv4Network


class MACAddressNotFoundError(Exception):
	pass


class Resolver(Job):

	__slots__ = ("_cache", "_count", "interface", "repeat", "subnet", "filter", "address", "_request_to_send")

	def __init__(self, sock, interface, subnet, repeat, **args):
		super().__init__(sock, **args)
		self.interface = interface
		self.subnet = subnet
		self.address = (self.interface.name, SOCKET_PROTO)
		self.repeat = repeat
		self._cache = set()
		self._count = self.subnet.num_addresses
		self.filter = create_filter(OPERATION_REPLY, sender=subnet)
		self._request_to_send = self.generate_packets()

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		_, rep = parse_arp(data)
		if self.filter(rep):
			if rep.sender_protocol_address not in self._cache:
				self._count -= 1
				if self._count < 1:
					self.set_finished()
				self._cache.add(rep.sender_protocol_address)
				return (MACAddress(rep.sender_hardware_address), IPv4Address(rep.sender_protocol_address))

	def loop(self) -> bool:
		for packet in self._request_to_send:
			self.sock.sendto(packet, self.address)
			return True
		return False

	def generate_packets(self) -> Iterator[bytes]:
		for _ in range(0, self.repeat):
			for host in self.subnet.hosts():
				if host.packed not in self._cache:
					yield ARP.who_has(
						host,
						self.interface.mac,
						self.interface.ip,
					)
		return


def resolve_mac(
	address: Union[str, IPv4Address],
	interface: Union[str, NetworkInterface] = None,
	sock: "socket.socket" = None,
	raise_on_miss: bool = False
) -> Union[MACAddress, None]:
	"""Resolve the MAC address for a given IP.
		
	Args:
		address: IPv4 to resolve to MAC.
		interface: interface to use.
		sock: socket to use.
		raise_on_miss: raise exception if MAC is not found.

	Returns:
		The MAC Address or None.

	Raises:
		MACAddressNotFoundError.

	"""
	a = list(resolve(address, interface, sock, repeat=3, wait=0.5, interval=0.1))
	if len(a) > 0:
		return a[0][0]
	else:
		if raise_on_miss:
			raise MACAddressNotFoundError("No MAC address found for host {}".format(address))
		else:
			return None


def resolve(
	subnet: Union[str, IPv4Address, IPv4Network],
	interface: Union[str, NetworkInterface] = None,
	sock: "socket.socket" = None,
	repeat: int = 2,
	wait: float = 1,
	interval: int = 0.003
) -> Iterator[Host]:
	"""Resolve the MAC addresses for a given subnet.
		
	Args:
		subnet: the IPv4 subnet.
		interface: interface to use.
		sock: socket to use.
		repeat: number of request to send before to give up.
		wait: max amount of seconds before to give up.
		interval: delta time between requests.

	Returns:
		An Iterator with the tuple MAC, IPv4 addresses.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str or type(subnet) == IPv4Address:
		subnet = IPv4Network(subnet)
	if interface is None:
		interface = NetworkInterface.get_by_host(subnet.network_address)
	if sock is None:
		sock = _create_socket()
	return Resolver(sock, interface, subnet, repeat, wait=wait, interval=interval).stream()


if __name__ == "__main__":

	import sys


	if len(sys.argv) < 1:
		print("Too few parameters")
	else:
		subnet = IPv4Network(sys.argv[1])
		interface = sys.argv[2] if len(sys.argv) > 2 else None
		if subnet.num_addresses > 1:
			for mac, ip in resolve(subnet, interface=interface):
				print(f"{ip}\t{mac}")
		else:
			mac = resolve_mac(subnet, interface=interface)
			print("Host not found" if mac is None else "{}\t{}".format(subnet.network_address, mac))

