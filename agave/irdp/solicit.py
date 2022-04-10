"""Primitives to retrieve routing information.

"""
import socket, array
from typing import Union, Iterator, Iterable, Tuple
from agave.core.helpers import SocketAddress, Job, SendMsgArgs
from agave.core.irdp import IRDP, ROUTER_SOLICITATION_MULTICAST_ADDRESS
from agave.core.icmpv4 import ICMPv4, TYPE_ROUTER_ADVERTISMENT_MESSAGE
from agave.nic.interfaces import NetworkInterface
from .utils import IRDPLinkLayerJob, handle_link_layer, create_irdp_socket
from ipaddress import IPv4Address, IPv4Network


class RouterSoliciter(IRDPLinkLayerJob):

	__slots__ = ("_cache", "interface", "repeat", "_request_to_send")

	def __init__(self, sock: "socket", interface: NetworkInterface, repeat: int, **kwargs):
		super().__init__(sock, interface, **kwargs)
		#self.interface: NetworkInterface = interface
		self.repeat: int = repeat
		self._request_to_send: Iterator[Tuple[bytes, SocketAddress]] = self.generate_packets()
		self._cache = set()

	def process(self, data: bytes, address: SocketAddress) -> Union[Tuple[IPv4Address, ICMPv4], None]:
		_, icmp = ICMPv4.parse(data)
		if icmp.type == TYPE_ROUTER_ADVERTISMENT_MESSAGE:
			if address[0] not in self._cache:
				self._cache.add(address[0])
				return (IPv4Address(address[0]), icmp)

	def loop(self) -> bool:
		for message in self._request_to_send:
			self.sock.sendmsg(*message)
			return True
		return False

	def generate_packets(self) -> Iterator[SendMsgArgs]:
		message = bytes(IRDP.solicitation())
		ancdata_multicast = [(socket.IPPROTO_IP, socket.IP_TTL, array.array("i", [1]))]
		ancdata_broadcast = [(socket.IPPROTO_IP, socket.IP_TTL, array.array("i", [255]))]
		for _ in range(0, self.repeat):
			yield [message], ancdata_multicast, 0, (ROUTER_SOLICITATION_MULTICAST_ADDRESS, 0)
			yield [message], ancdata_broadcast, 0, ("255.255.255.255", 0)
		return


LowLevelRouterSoliciter = handle_link_layer(RouterSoliciter)


def routers(
	interface: Union[str, NetworkInterface],
	sock: "socket.socket" = None,
	repeat: int = 3,
	wait: float = 1,
	interval: int = 0.003
) -> Iterable[Tuple[IPv4Address, ICMPv4]]:
	"""Returns all the routers.
		
	Args:
		interface: interface to use.
		sock: socket to use.
		repeat: number of request to send before to give up.
		wait: max amount of seconds before to give up.
		interval: delta time between requests.

	Returns:
		An Iterable of IPv4 address and ICMPv4 message.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if sock is None:
		sock = create_irdp_socket()
	if sock.family == socket.AF_INET:
		return RouterSoliciter(sock, interface, repeat, wait=wait, interval=interval).stream()
	elif sock.family == socket.AF_PACKET:
		return LowLevelRouterSoliciter(sock, interface, repeat, wait=wait, interval=interval).stream()
	else:
		raise ValueError("Socket family must be either AF_INET or AF_PACKET.")


if __name__ == "__main__":

	import sys, socket


	if len(sys.argv) < 1:
		print("Too few parameters")
	else:
		for router in routers(sys.argv[1], sock=None, interval=0.5, repeat=1):
			print(router[0])

