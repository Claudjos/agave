"""IRDP protocol RFC 1256."""
from .icmp import (
	ICMPv4, TYPE_ROUTER_ADVERTISMENT_MESSAGE, 
	TYPE_ROUTER_SOLICITATION_MESSAGE
)
from .buffer import Buffer
from typing import List


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

	@classmethod
	def advertise(cls, addresses: List[bytes], prefereces: List[int],
		life_time: int = 1800
	):
		length = len(addresses)
		if length != len(prefereces):
			raise ValueError()

		buf = Buffer.from_bytes()
		for i in range(0, length):
			buf.write(addresses[i])
			buf.write_int(prefereces[i])

		frame = cls(TYPE_ROUTER_ADVERTISMENT_MESSAGE, 0, 0, 0, bytes(buf))
		frame.life_time = life_time
		frame.address_entry_size = 2
		frame.num_address = length
		frame.set_checksum()
		return frame

	@classmethod
	def solicitation(cls):
		frame = cls(TYPE_ROUTER_SOLICITATION_MESSAGE, 0, 0, 0, b'')
		frame.set_checksum()
		return frame
