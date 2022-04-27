import socket
from agave.utils.interfaces import NetworkInterface
from typing import Union


def create_socket(interface: Union[str, NetworkInterface]) -> "socket.socket":
	"""Creates a socket."""
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind((interface if isinstance(interface, str) else interface.name, 0))
	return sock

