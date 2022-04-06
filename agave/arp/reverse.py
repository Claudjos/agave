"""RARP. Primitives to obtain network protocol address given 
a hardware protocol address.

This module also provides a script to retrieve the MAC
address(es) given an IPv4.

Usage:
	python3 -m agave.arp.reverse <mac> <interface>

Example:
	python3 -m agave.arp.reverse aa:bb:cc:00:11:22 <eth0>

"""
import socket
from typing import Union
from .utils import _parse as parse_arp
from .utils import Host
from agave.core.ethernet import MACAddress, ETHER_TYPE_RARP
from agave.core.arp import ARP, OPERATION_REPLY_REVERSE
from agave.core.helpers import SocketAddress, Job
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv4Address


class ReverseResolver(Job):

	__slots__ = ("interface", "target")

	def __init__(self, sock: "socket.socket", interface: NetworkInterface, target: MACAddress, **args):
		super().__init__(sock, **args)
		self.interface = interface
		self.target = target

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		_, rep = parse_arp(data)
		if (
			rep.operation == OPERATION_REPLY_REVERSE and
			rep.target_hardware_address == self.target.packed
		):
			return (MACAddress(rep.sender_hardware_address), IPv4Address(rep.sender_protocol_address))

	def loop(self) -> bool:
		self.sock.sendto(
			bytes(ARP.request_reverse(self.interface.mac, self.target)),
			(self.interface.name, ETHER_TYPE_RARP)
		)
		return False


def reverse(
	sock: "socket.socket",
	target: Union[str, MACAddress],
	interface: Union[str, NetworkInterface],
	wait: float = 1
) -> Host:
	"""Finds the IPv4 address given a MAC address.
		
	Args:
		sock: socket to use.
		subnet: the MAC address.
		interface: interface to use.
		wait: max amount of seconds before to give up.

	Returns:
		Returns the protocol and hardware address.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(target) == str:
		target = MACAddress(target)
	r = list(ReverseResolver(sock, interface, target, wait=wait).stream())
	return r[0] if len(r) > 0 else None


if __name__ == "__main__":

	import sys


	if len(sys.argv) < 2:
		print("[ERROR] Too few parameters.")
	else:
		x = reverse(
			socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE_RARP)),
			sys.argv[1],
			sys.argv[2],
			wait=1
		)
		if x is not None:
				print("{}".format(x[0]))
		else:
			print("[ERROR] No reply received.")

