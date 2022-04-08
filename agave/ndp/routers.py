"""
"""
import select, time, socket
from typing import Union, Iterator, Tuple
from agave.arp.utils import Host
from agave.core.ethernet import MACAddress, ETHER_TYPE_IPV6
from agave.arp.resolve import MACAddressNotFoundError
from agave.core.helpers import SocketAddress, Job
from agave.core.ndp import (
	SourceLinkLayerAddress, RouterSolicitation,
	TargetLinkLayerAddress, RouterAdvertisement,
	NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS, NDP
)
from agave.core.ethernet import Ethernet, ETHER_TYPE_IPV6
from agave.core.ip import (
	IPv6, PROTO_ICMPv6, IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL,
	IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL, IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL
)
from agave.core.icmpv6 import ICMPv6, TYPE_ROUTER_ADVERTISEMENT
from agave.core.buffer import Buffer
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv6Address, IPv6Network


class RouterSoliciter(Job):

	__slots__ = ("_cache", "_count", "interface", "repeat", "_request_to_send")

	def __init__(self, sock: "socket", interface: NetworkInterface, repeat: int, **args):
		super().__init__(sock, **args)
		self.interface: NetworkInterface = interface
		self.repeat: int = repeat
		self._request_to_send: Iterator[Tuple[bytes, SocketAddress]] = self.generate_packets()

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		result = None
		source = IPv6Address(address[0])
		icmp, = ICMPv6.parse(data)
		if icmp.type == TYPE_ROUTER_ADVERTISEMENT:
			ndp = RouterAdvertisement.parse(icmp)
			# Do something here
		return result

	def loop(self) -> bool:
		for message in self._request_to_send:
			self.sock.sendto(*message)
			return True
		return False

	def generate_packets(self) -> Iterator[Tuple[bytes, SocketAddress]]:
		options = [SourceLinkLayerAddress.build(self.interface.mac)]
		for _ in range(0, self.repeat):
			for ip in [
				IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL,
				IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL,
				IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL
			]:
				yield (bytes(RouterSolicitation(options).to_frame()), (ip, 0))
		return


class LowLevelRouterSoliciter(RouterSoliciter):

	def process(self, data: bytes, address: SocketAddress) -> Union[Host, None]:
		"""Removes the link and network layer from message."""
		if address[1] == ETHER_TYPE_IPV6:
			buf = Buffer.from_bytes(data)
			eth = Ethernet.read_from_buffer(buf)
			ip = IPv6.read_from_buffer(buf)
			if ip.next_header == PROTO_ICMPv6:
				return super().process(buf.read_remaining(), (str(ip.source), 0))

	def generate_packets(self) -> Iterator[Tuple[bytes, SocketAddress]]:
		"""Adds link and network layer to messages."""
		for data, addr in super().generate_packets():
			# Parses back ICMPv6 message
			icmp = ICMPv6.from_bytes(data)
			# Creates IPv6 header
			dest_ip = IPv6Address(addr[0])
			ip = IPv6(0, 0, len(data), PROTO_ICMPv6, 255,
				self.interface.ipv6, dest_ip)
			# Calculates checksum for ICMPv6
			icmp.set_pseudo_header(ip.get_pseudo_header())
			icmp.set_checksum()
			# Creates EthernetII header
			dest_mac = NDP.map_multicast_over_ethernet(dest_ip).packed
			dest_mac = b'\xff\xff\xff\xff\xff\xff'				# see module doc note.
			eth = Ethernet(dest_mac, self.interface.mac.packed, ETHER_TYPE_IPV6)
			# Yields
			yield (
				bytes(eth) + bytes(ip) + bytes(icmp),
				(self.interface.name, ETHER_TYPE_IPV6)
			)
		return


def routers(
	interface: Union[str, NetworkInterface],
	sock: "socket.socket" = None,
	repeat: int = 3,
	wait: float = 1,
	interval: int = 0.003,
	raise_on_miss: bool = False
) -> Iterator[Host]:
	"""Returns all the routers.
		
	Args:
		interface: interface to use.
		sock: socket to use.
		repeat: number of request to send before to give up.
		wait: max amount of seconds before to give up.
		interval: delta time between requests.
		raise_on_miss: raise if no router are returned.

	Returns:
		An Iterator with the tuple MAC, IPv6 addresses.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if interface is None:
		interface = NetworkInterface.get_by_host(subnet.network_address)
	if sock is None:
		try:
			sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
			sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, 255)					# see module doc note.
		except:
			sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHER_TYPE_IPV6))
	if sock.family == socket.AF_INET6:
		return RouterSoliciter(sock, interface, repeat, wait=wait, interval=interval).stream()
	if sock.family == socket.AF_PACKET:
		return LowLevelRouterSoliciter(sock, interface, repeat, wait=wait, interval=interval).stream()
	else:
		raise ValueError("Socket family must be either AF_INET6 or AF_PACKET.")


if __name__ == "__main__":

	import sys, socket


	if len(sys.argv) < 1:
		print("Too few parameters")
	else:
		for router in routers(sys.argv[1], sock=None, interval=0.5, repeat=1):
			print(router)

