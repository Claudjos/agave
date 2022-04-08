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
	NDP_OPTION_TYPE_TARGET_LINK_LAYER_ADDRESS
)
from agave.core.ip import (
	IPV6_ALL_ROUTERS_MULTICAST_SITE_LOCAL,
	IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL, IPV6_ALL_ROUTERS_MULTICAST_LINK_LOCAL
)
from agave.core.icmpv6 import ICMPv6, TYPE_ROUTER_ADVERTISEMENT
from agave.nic.interfaces import NetworkInterface
from .utils import NDPLinkLayerJob, handle_link_layer
from ipaddress import IPv6Address, IPv6Network


class RouterSoliciter(NDPLinkLayerJob):

	__slots__ = ("_cache", "_count", "interface", "repeat", "_request_to_send")

	def __init__(self, sock: "socket", interface: NetworkInterface, repeat: int, **kwargs):
		super().__init__(sock, interface, **kwargs)
		#self.interface: NetworkInterface = interface
		self.repeat: int = repeat
		self._request_to_send: Iterator[Tuple[bytes, SocketAddress]] = self.generate_packets()
		self._cache = set()

	def process(self, data: bytes, address: SocketAddress) -> Union[Tuple[IPv6Address, RouterAdvertisement], None]:
		icmp, = ICMPv6.parse(data)
		if icmp.type == TYPE_ROUTER_ADVERTISEMENT:
			if address[0] not in self._cache:
				self._cache.add(address[0])
				return (IPv6Address(address[0]), RouterAdvertisement.parse(icmp))

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


LowLevelRouterSoliciter = handle_link_layer(RouterSoliciter)


def routers(
	interface: Union[str, NetworkInterface],
	sock: "socket.socket" = None,
	repeat: int = 3,
	wait: float = 1,
	interval: int = 0.003
) -> Iterator[Host]:
	"""Returns all the routers.
		
	Args:
		interface: interface to use.
		sock: socket to use.
		repeat: number of request to send before to give up.
		wait: max amount of seconds before to give up.
		interval: delta time between requests.

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
	elif sock.family == socket.AF_PACKET:
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

