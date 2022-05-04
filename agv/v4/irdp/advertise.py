"""
Advertises routers from a static list. This implementation is not conform
to RFC 1256.

Usage:
	python3 -m agave.irdp.advertise <preference> <router> [...[<preference> <router>]]

Example:
	python3 -m agave.irdp.advertise 100 192.168.1.2
	python3 -m agave.irdp.advertise 100 192.168.1.2 40 192.168.1.5

"""
import socket, array
from typing import Union, Iterator, Iterable, Tuple
from agave.models.icmp.irdp import IRDP, ROUTER_ADVERTISMENT_MULTICAST_ADDRESS, ROUTER_SOLICITATION_MULTICAST_ADDRESS
from agave.models.icmp.icmpv4 import ICMPv4, TYPE_ROUTER_SOLICITATION_MESSAGE
from agave.utils.interfaces import NetworkInterface
from agave.utils.jobs import SocketAddress, Job, SendMsgArgs
from .utils import join_group, create_irdp_socket
from ipaddress import IPv4Address, IPv4Network


class RouterAdvertiser(Job):

	__slots__ = ("interface", "message")

	def __init__(self, sock: "socket", message: IRDP, **kwargs):
		super().__init__(sock, **kwargs)
		self.message = bytes(message)

	def process(self, data: bytes, address: SocketAddress):
		_, icmp = ICMPv4.parse(data)
		if icmp.type == TYPE_ROUTER_SOLICITATION_MESSAGE:
			# TODO (?) validate
			# Extra call to Job.loop
			self.sock.sendmsg([self.message], [], 0, address)

	def loop(self) -> bool:
		ancdata_multicast = [(socket.IPPROTO_IP, socket.IP_TTL, array.array("i", [1]))]
		self.sock.sendmsg([self.message], ancdata_multicast, 0, (ROUTER_ADVERTISMENT_MULTICAST_ADDRESS, 0))
		return True

	def stream(self):
		"""Overrides stream to call the loop before to start."""
		self.loop()
		return super().stream()


if __name__ == "__main__":

	import sys


	if len(sys.argv) < 3:
		print("Too few arguments")
	elif (len(sys.argv) -1 ) % 2 != 0:
		print("Malformed arguments")
	else:
		# creates socket
		rawsocket = create_irdp_socket()
		join_group(rawsocket, ROUTER_SOLICITATION_MULTICAST_ADDRESS)
		# parses arguments
		preferences = []
		addresses = []
		for i in range(1, len(sys.argv), 2):
			preferences.append(int(sys.argv[i]))
			addresses.append(IPv4Address(sys.argv[i+1]).packed)
		# builds job & run
		job = RouterAdvertiser(rawsocket, IRDP.advertise(addresses, preferences), interval=300)
		print("Running...")
		job.run()
