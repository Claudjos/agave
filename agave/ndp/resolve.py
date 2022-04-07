"""Primitives to resolve IPv6 addresses into MAC addresses.

Note:
	This module also provides a script to retrieve the MAC
	address(es) given an IPv6 or subnet.

Usage:
	python3 -m agave.ndp.resolve <IPv6|subnet> [interface]

Notes:
	When I test this module locally using AF_INET6 SOCK_RAW
	IPPROTO_ICMPV6 two problems occur:
	- the hop limit is set to 1, not 255 as for RFC 4861, and
		I failed to change sock option IPV6_HOPLIMIT;
	- the destination Ethernet multicast address used is in the
		format 33-33-xx (as for RFC 2464) yet I don't receive
		any reply back from other nodes.
	This is way I added the code to work at link layer.

"""
import select, time, socket
from typing import Union, Iterator, Tuple
from agave.arp.utils import Host
from agave.core.ethernet import MACAddress, ETHER_TYPE_IPV6
from agave.arp.resolve import MACAddressNotFoundError
from agave.core.helpers import SocketAddress, Job
from agave.core.ndp import (
	SourceLinkLayerAddress, NeighborSolicitation,
	TargetLinkLayerAddress, NeighborAdvertisment,
	NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS
)
from agave.core.ethernet import Ethernet, ETHER_TYPE_IPV6
from agave.core.ip import IPv6, PROTO_ICMPv6
from agave.core.icmpv6 import ICMPv6, TYPE_NEIGHBOR_ADVERTISEMENT
from agave.core.buffer import Buffer
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv6Address, IPv6Network


class NeighborSoliciter(Job):

	__slots__ = ("_cache", "_count", "interface", "repeat", "subnet", "_request_to_send")

	def __init__(self, sock: "socket", interface: NetworkInterface, subnet: IPv6Network, repeat: int, **args):
		super().__init__(sock, **args)
		self.interface: NetworkInterface = interface
		self.subnet: IPv6Network = subnet
		self.repeat: int = repeat
		self._cache: set = set()
		self._count: int = self.subnet.num_addresses
		self._request_to_send: Iterator[Tuple[bytes, SocketAddress]] = self.generate_packets()

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		result = None
		if address[0] not in self._cache:
			source = IPv6Address(address[0])
			if source in self.subnet:
				icmp, = ICMPv6.parse(data)
				if icmp.type == TYPE_NEIGHBOR_ADVERTISEMENT:
					ndp = NeighborAdvertisment.parse(icmp)
					for option in ndp.options:
						if option.type == NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS:
							result = (option.mac, source)
							self._count -= 1
							break
		if self._count < 1:
			self.set_finished()
		return result

	def loop(self) -> bool:
		for message in self._request_to_send:
			self.sock.sendto(*message)
			return True
		return False

	def generate_packets(self) -> Iterator[Tuple[bytes, SocketAddress]]:
		options = [SourceLinkLayerAddress.build(self.interface.mac)]
		for _ in range(0, self.repeat):
			for host in self.subnet.hosts():
				if str(host) not in self._cache:
					yield (
						bytes(NeighborSolicitation(host, options).to_frame()),
						(str(NeighborSolicitation.compute_solicited_node_multicast_address(host)), 0)
					)
		return


class LowLevelNeighborSoliciter(NeighborSoliciter):

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		"""Removes the link and network layer from message."""
		if address[1] == ETHER_TYPE_IPV6:
			buf = Buffer.from_bytes(data)
			eth = Ethernet.read_from_buffer(buf)
			ip = IPv6.read_from_buffer(buf)
			if ip.next_header == PROTO_ICMPv6:
				return super().process(buf.read_remaining(), (str(ip.source), 0))

	def generate_packets(self) -> Iterator[Tuple[bytes, SocketAddress]]:
		"""Adds link and network layer to messages."""
		for data, addr in super().generate_packets():
			# Parses back ICMPv6 message
			icmp = ICMPv6.from_bytes(data)
			# Creates IPv6 header
			dest_ip = IPv6Address(addr[0])
			ip = IPv6(0, 0, len(data), PROTO_ICMPv6, 255,
				self.interface.ipv6, dest_ip)
			# Calculates checksum for ICMPv6
			icmp.set_pseudo_header(ip.get_pseudo_header())
			icmp.set_checksum()
			# Creates EthernetII header
			dest_mac = b'\x33\x33' + dest_ip.packed[12:]
			dest_mac = b'\xff\xff\xff\xff\xff\xff'				# see module doc note.
			eth = Ethernet(dest_mac, self.interface.mac.packed, ETHER_TYPE_IPV6)
			# Yields
			yield (
				bytes(eth) + bytes(ip) + bytes(icmp),
				(self.interface.name, ETHER_TYPE_IPV6)
			)
		return


def resolve_mac(
	address: Union[str, IPv6Address],
	interface: Union[str, NetworkInterface] = None,
	sock: "socket.socket" = None,
	raise_on_miss: bool = False
) -> Union[MACAddress, None]:
	"""Resolve the MAC address for a given IP.
		
	Args:
		address: IPv6 to resolve to MAC.
		interface: interface to use.
		sock: socket to use.
		raise_on_miss: raise exception if MAC is not found.

	Returns:
		The MAC Address or None.

	Raises:
		MACAddressNotFoundError.

	"""
	a = list(resolve(address, interface, sock, repeat=1, wait=0.5, interval=0.1))
	if len(a) > 0:
		return a[0][0]
	else:
		if raise_on_miss:
			raise MACAddressNotFoundError("No MAC address found for host {}".format(address))
		else:
			return None


def resolve(
	subnet: Union[str, IPv6Address, IPv6Network],
	interface: Union[str, NetworkInterface] = None,
	sock: "socket.socket" = None,
	repeat: int = 3,
	wait: float = 1,
	interval: int = 0.003
) -> Iterator[Host]:
	"""Resolve the MAC addresses for a given subnet.
		
	Args:
		subnet: the IPv6 subnet.
		interface: interface to use.
		sock: socket to use.
		repeat: number of request to send before to give up.
		wait: max amount of seconds before to give up.
		interval: delta time between requests.

	Returns:
		An Iterator with the tuple MAC, IPv6 addresses.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str or type(subnet) == IPv6Address:
		subnet = IPv6Network(subnet)
	if interface is None:
		interface = NetworkInterface.get_by_host(subnet.network_address)
	if sock is None:
		try:
			sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
			sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, 255)					# see module doc note.
		except:
			sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE_IPV6))
	if sock.family == socket.AF_INET6:
		return NeighborSoliciter(sock, interface, subnet, repeat, wait=wait, interval=interval).stream()
	if sock.family == socket.AF_PACKET:
		return LowLevelNeighborSoliciter(sock, interface, subnet, repeat, wait=wait, interval=interval).stream()
	else:
		raise ValueError("Socket family must be either AF_INET6 or AF_PACKET.")


if __name__ == "__main__":

	import sys, socket


	if len(sys.argv) < 1:
		print("Too few parameters")
	else:
		subnet = IPv6Network(sys.argv[1])
		interface = sys.argv[2] if len(sys.argv) > 2 else None
		if subnet.num_addresses > 1:
			for mac, ip in resolve(subnet, interface=interface):
				print(f"{ip}\t{mac}")
		else:
			mac = resolve_mac(subnet, interface=interface)
			print("Host not found" if mac is None else "{}\t{}".format(subnet.network_address, mac))

