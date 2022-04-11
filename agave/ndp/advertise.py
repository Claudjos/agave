"""
Advertises routers from a static list. This implementation is not conform
to RFC 4861.

Usage:
	python3 -m agave.ndp.advertise interface [[prefix] ...]

Example:
	python3 -m agave.ndp.advertise wlan0
	python3 -m agave.ndp.advertise wlan0 fe80::/120 2001:4860:4860::8888/128

"""
import socket, array
from typing import Union, Iterator, Iterable, Tuple
from .utils import join_group
from agave.core.helpers import SocketAddress, Job, SendMsgArgs
from agave.core.ndp import ( 
	NDP, SourceLinkLayerAddress, RouterAdvertisement, PrefixInformation
)
from agave.core.icmpv6 import ICMPv6, TYPE_ROUTER_SOLICITATION
from agave.core.ip import (
	IPv6, PROTO_ICMPv6,
	IPV6_ALL_NODES_MULTICAST_INTERFACE_LOCAL,
	IPV6_ALL_NODES_MULTICAST_LINK_LOCAL,
	IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL,
	IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL,
	IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL
)
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv6Address, IPv6Network


class RouterAdvertiser(Job):

	__slots__ = ("interface", "message")

	def __init__(self, sock: "socket", message: NDP, **kwargs):
		super().__init__(sock, **kwargs)
		self.message = bytes(message)

	def process(self, data: bytes, address: SocketAddress):
		icmp, = ICMPv6.parse(data)
		if icmp.type == TYPE_ROUTER_SOLICITATION:
			# TODO (?) validate
			self.sock.sendmsg([self.message], [], 0, address)

	def loop(self) -> bool:
		ancdata = [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, array.array("i", [255]))]
		self.sock.sendmsg([self.message], ancdata, 0, (IPV6_ALL_NODES_MULTICAST_INTERFACE_LOCAL, 0))
		self.sock.sendmsg([self.message], ancdata, 0, (IPV6_ALL_NODES_MULTICAST_LINK_LOCAL, 0))
		return True

	def stream(self):
		"""Overrides stream to call the loop before to start."""
		self.loop()
		return super().stream()


if __name__ == "__main__":

	import sys, struct


	if len(sys.argv) < 2:
		print("Too few arguments")
	else:
		# creates socket joins multicast groups
		rawsocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
		join_group(rawsocket, IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL)
		join_group(rawsocket, IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL)
		join_group(rawsocket, IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL)
		# parses arguments
		interface = NetworkInterface.get_by_name(sys.argv[1])
		options = [SourceLinkLayerAddress.build(interface.mac)] + \
			[PrefixInformation.build(IPv6Network(net), 0xffffffff, 0xffffffff, a=True)
			for net in sys.argv[2:]]
		ndp = RouterAdvertisement(
			lifetime=9000,
			reachable_time=0,
			retrans_timer=0,
			options=options
		)
		message = bytes(ndp.to_frame())
		# builds job & run
		job = RouterAdvertiser(rawsocket, message, interval=300)
		print("Running...")
		job.run()

