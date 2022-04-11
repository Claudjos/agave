"""Utilities to handle IRDP package at link layer rather the network.

"""
import socket, struct
from agave.core.helpers import Job, SocketAddress, SendMsgArgs
from typing import Union, Iterator, Tuple, Any, Callable
from agave.core.buffer import Buffer
from agave.core.ethernet import Ethernet, ETHER_TYPE_IPV4
from agave.core.ip import IPv4, PROTO_ICMP
from agave.core.icmpv4 import ICMPv4
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv4Address


class IRDPLinkLayerJob(Job):
	"""The only purpose of this class is to define the interface of the classes
	handle_link_layer is gonna be used upon."""

	__slots__ = ("interface")

	def __init__(self, sock: "socket.socket", interface: NetworkInterface, **kwargs):
		super().__init__(sock, **kwargs)
		self.interface = interface

	def generate_packets(self) -> Iterator[SendMsgArgs]:
		raise NotImplementedError()


def handle_link_layer(cls: IRDPLinkLayerJob) -> IRDPLinkLayerJob:
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
	"""Removes the link layer from the message."""
	if address[1] == ETHER_TYPE_IPV4:
		buf = Buffer.from_bytes(data)
		eth = Ethernet.read_from_buffer(buf)
		buf.mark()
		ip = IPv4.read_from_buffer(buf)
		if ip.protocol == PROTO_ICMP:
			buf.restore()
			return _process(self, buf.read_remaining(), (str(ip.source), 0))


def generate_packets(self, _generate_packets: Callable) -> Iterator[SendMsgArgs]:
	"""Adds link and network layer to messages."""
	for data, ancdata, flags, addr in _generate_packets(self):
		# Parses back ICMPv4 message
		data = b''.join(data)
		icmp = ICMPv4.from_bytes(data)
		icmp.set_checksum()
		# Creates IPv4 header
		dest_ip = IPv4Address(addr[0])
		ip = IPv4.create_message(dest_ip, self.interface.ip, bytes(icmp), PROTO_ICMP, ttl=1)
		# Creates EthernetII header
		# dest_mac = IPv4 Multicast
		dest_mac = b'\xff\xff\xff\xff\xff\xff'
		eth = Ethernet(dest_mac, self.interface.mac.packed, ETHER_TYPE_IPV4)
		# Yields
		yield [bytes(eth), bytes(ip), bytes(icmp)], [], 0, (self.interface.name, ETHER_TYPE_IPV4)
	return


def create_irdp_socket() -> "socket.socket":
	"""
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	return sock
	"""
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE_IPV4))


def join_group(sock: "socket.socket", address: str):
	"""Joins a multicast group. Necessary to receive multicast message on a socket at
	network layer.

	Args:
		sock: socket.
		address: multicast address.

	"""
	mreq = socket.inet_pton(socket.AF_INET, address) + struct.pack('=I', socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

