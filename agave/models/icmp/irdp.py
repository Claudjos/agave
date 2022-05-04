"""IRDP protocol RFC 1256."""
from .icmpv4 import (
	ICMPv4, TYPE_ROUTER_ADVERTISMENT_MESSAGE, 
	TYPE_ROUTER_SOLICITATION_MESSAGE
)
from ..buffer import Buffer
from typing import List, Iterable, Tuple
from ipaddress import IPv4Address


ROUTER_ADVERTISMENT_MULTICAST_ADDRESS = "224.0.0.1"		# all hosts
ROUTER_SOLICITATION_MULTICAST_ADDRESS = "224.0.0.2"		# all routers



class IRDP(ICMPv4):
	"""IRDP message."""
	__slots__ = ()
	
	@property
	def num_address(self):
		return ( self.rest_of_the_header & 0xff000000 ) >> 24

	@num_address.setter
	def num_address(self, a):
		self.rest_of_the_header = ( self.rest_of_the_header & 0x00ffffff ) | ( ( a & 0x000000ff ) << 24 )

	@property
	def address_entry_size(self):
		return ( self.rest_of_the_header & 0x00ff0000 ) >> 16

	@address_entry_size.setter
	def address_entry_size(self,a):
		self.rest_of_the_header = ( self.rest_of_the_header & 0xff00ffff ) | ( ( a & 0x000000ff ) << 16 )

	@property
	def life_time(self):
		return self.rest_of_the_header & 0x0000ffff

	@life_time.setter
	def life_time(self,a):
		self.rest_of_the_header = ( self.rest_of_the_header & 0xffff0000 ) | ( a & 0x0000ffff )

	def get_addresses(self) -> Iterable[Tuple[int, IPv4Address]]:
		for offset in range(0, len(self.data), 8):
			yield (
				IPv4Address(self.data[offset:offset+4]),
				int.from_bytes(self.data[offset+4:offset+8], byteorder="big")
			)
		return

	@classmethod
	def advertise(cls, addresses: List[Tuple[IPv4Address, int]], 
		life_time: int = 1800) -> "IRDP":
		"""Builds an IRDP advertisement message.

		Args:
			addresses: list of pairs router IP, preference.
			life_time: life time.

		Returns:
			An instance of this class.

		"""
		buf = Buffer.from_bytes()
		for router_address, preference in addresses:
			buf.write(router_address.packed)
			buf.write_int(preference)
		frame = cls(TYPE_ROUTER_ADVERTISMENT_MESSAGE, 0, 0, 0, bytes(buf))
		frame.life_time = life_time
		frame.address_entry_size = 2
		frame.num_address = len(addresses)
		frame.set_checksum()
		return frame

	@classmethod
	def solicitation(cls):
		frame = cls(TYPE_ROUTER_SOLICITATION_MESSAGE, 0, 0, 0, b'')
		frame.set_checksum()
		return frame
