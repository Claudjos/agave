from agave.core.helpers import Job, SocketAddress
from typing import Union, Iterator, Tuple, Any, Callable
from agave.core.buffer import Buffer
from agave.core.ethernet import Ethernet, ETHER_TYPE_IPV6
from agave.core.ip import IPv6, PROTO_ICMPv6
from agave.core.icmpv6 import ICMPv6
from agave.core.ndp import NDP
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv6Address


class NDPLinkLayerJob(Job):
	"""The only purpose of this class is to define the interface of the classes
	handle_link_layer is gonna be used upon."""

	__slots__ = ("interface")

	def __init__(self, sock: "socket", interface: NetworkInterface, **kwargs):
		super().__init__(sock, **kwargs)
		self.interface = interface

	def generate_packets(self) -> Iterator[Tuple[bytes, SocketAddress]]:
		raise NotImplementedError()


def handle_link_layer(cls: NDPLinkLayerJob) -> NDPLinkLayerJob:
	"""Wraps class methods in order to handle link layer.
	
	Args:
		cls: the class to extend.

	Returns:
		A new class able to handle link layer.

	"""
	class Wrapped(cls):
		pass
	setattr(Wrapped, "process", lambda s, d, a: process(s, d, a, cls.process))
	setattr(Wrapped, "generate_packets", lambda s: generate_packets(s, cls.generate_packets))
	return Wrapped


def process(self, data: bytes, address: SocketAddress, _process: Callable) -> Union[Any, None]:
	"""Removes the link and network layer from message."""
	if address[1] == ETHER_TYPE_IPV6:
		buf = Buffer.from_bytes(data)
		eth = Ethernet.read_from_buffer(buf)
		ip = IPv6.read_from_buffer(buf)
		if ip.next_header == PROTO_ICMPv6:
			return _process(self, buf.read_remaining(), (str(ip.source), 0))


def generate_packets(self, _generate_packets: Callable) -> Iterator[Tuple[bytes, SocketAddress]]:
	"""Adds link and network layer to messages."""
	for data, addr in _generate_packets(self):
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
		dest_mac = NDP.map_multicast_over_ethernet(dest_ip).packed
		dest_mac = b'\xff\xff\xff\xff\xff\xff'
		eth = Ethernet(dest_mac, self.interface.mac.packed, ETHER_TYPE_IPV6)
		# Yields
		yield (
			bytes(eth) + bytes(ip) + bytes(icmp),
			(self.interface.name, ETHER_TYPE_IPV6)
		)
	return

