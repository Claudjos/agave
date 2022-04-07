"""Dummy class for testing. """
from typing import Tuple
from agave.core.helpers import SocketAddress
from agave.core.buffer import Buffer
from agave.core.ethernet import MACAddress
from ipaddress import IPv6Address, IPv6Network


class DummyInterface:

	def __init__(self, name: str = None, mac: MACAddress = None, ipv6: IPv6Address = None,
		netv6: IPv6Network = None):
		self.name = "eth0" if name is None else name
		self.mac = MACAddress("00:11:22:33:44:55") if mac is None else mac
		self.ipv6 = ipv6 if ipv6 is not None else IPv6Address("::1")
		self.netv6 = netv6 if netv6 is not None else IPv6Network("::/128")

	def get_socket_address(self, proto: int = 0, pkttype: int = 1) -> SocketAddress:
		return (self.name, proto, pkttype, 1, self.mac.packed)


class DummySock:

	def __init__(self):
		self.messages = []

	def sendto(self, data: bytes, address: SocketAddress):
		self.messages.append((data, address))

	def get_message(self, index: int) -> Tuple[bytes, SocketAddress]:
		return self.messages[index]

	def get_message_as_buffer(self, index: int) -> Tuple[Buffer, SocketAddress]:
		return Buffer.from_bytes(self.messages[index][0]), self.messages[index][1]
