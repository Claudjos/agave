"""ICMPv4 address mask request/reply.

The module provides a script to discover a subnet address mask
by using ICMPv4 messages. The IP normally is a router.

Usage:
	python3 -m agave.icmp.mask <ip>

Example:
	python3 -m agave.icmp.mask 192.168.1.1

"""
import socket
from agave.utils.jobs import Job, SocketAddress
from agave.models.icmp.icmpv4 import ICMPv4, TYPE_ADDRESS_MASK_REQUEST, TYPE_ADDRESS_MASK_REPLY
from agave.models.ip import IPv4
from ipaddress import IPv4Address
from typing import Tuple, Union


class MaskResolver(Job):

	def __init__(self, sock: "socket.socket", address: str, **kwargs):
		super().__init__(sock, **kwargs)
		self.address = address

	def loop(self) -> bool:
		frame = ICMPv4.address_mask_request(sequence_number=1, identifier=1)
		frame.set_checksum()
		self.sock.sendto(bytes((frame)), (self.address, 0))
		return False

	def process(self, data: bytes, address: SocketAddress) -> Tuple[bool, IPv4Address, int]:
		if address[0] == self.address:
			ip_h, icmp_h = ICMPv4.parse(data)
			if address[0] not in self._cache and icmp_h.type == TYPE_NETWORK_MASK_REPLY:
				self.set_finished()
				return IPv4Address(icmp_h.data)

	@classmethod
	def resolve(cls, sock: "socket.socket", address: Union[str, IPv4Address], **kwargs) -> IPv4Address:
		if type(address) == IPv4Address:
			address = str(address)
		job = cls(sock, address, **kwargs)
		a = [i for i in job.stream()]
		return a[0] if len(a) > 0 else None


if __name__ == "__main__":

	import sys


	# Parsing arguments
	if len(sys.argv) < 2:
		print("Too few parameters")
		exit(0)
	# Create Job
	print("[INFO] Waiting...")
	mask = MaskResolver.resolve(
		socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
		sys.argv[1],
		wait=5
	)
	# Print
	if mask is None:
		print("[ERROR] No reply received.")
	else:
		print("[INFO] {}".format(mask))
	
