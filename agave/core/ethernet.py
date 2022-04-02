from typing import Union
from .frame import Frame


ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86dd


class MACAddress:

	__slots__ = ["address"]

	def __init__(self, address: Union[bytes, str]):
		if type(address) == str:
			self.address = self.str_to_mac(address)
		else:
			self.address = address

	@classmethod
	def str_to_mac(cls, address: str):
		return bytes(map(lambda x: int(x, 16), address.split(":")))

	@classmethod
	def mac_to_str(cls, address: bytes):
		return ':'.join('%02x'%i for i in address)

	def __str__(self):
		return self.mac_to_str(self.address)

	def __eq__(self, a) -> bool:
		return a.address == self.address


def mac_to_str(address: bytes) -> str:
	return MACAddress.mac_to_str(address)


def str_to_mac(address: str) -> bytes:
	return MACAddress.str_to_mac(address)


class Ethernet(Frame):
	"""
	Ethernet II
	"""

	def __init__(self, destination: bytes, source: bytes, next_header: int):
		self.source = source
		self.destination = destination
		self.next_header = next_header

	@classmethod
	def read_from_buffer(cls, buf):
		return cls(buf.read(6), buf.read(6), buf.read_short())

	def write_to_buffer(self, buf):
		buf.write(self.destination)
		buf.write(self.source)
		buf.write_short(self.next_header)

	def make_reply(self):
		return Ethernet(self.destination, self.source, self.next_header)

	def __str__(self):
		return "({}) {} -> {}".format(
			self.next_header,
			mac_to_str(self.source),
			mac_to_str(self.destination),
		)
