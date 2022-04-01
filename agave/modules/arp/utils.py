import socket
from typing import Tuple
from agave.frames import ethernet, arp
from agave.frames.core import Buffer


SOCKET_MAX_READ = 65535
SOCKET_PROTO = socket.htons(ethernet.ETHER_TYPE_ARP)


def _create_socket():
	"""Creates a socket.

    Returns:
        A raw socket with protocol ARP.

    """
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, SOCKET_PROTO)


def _parse(data: bytes) -> Tuple[ethernet.Ethernet, arp.ARP]:
	buf = Buffer.from_bytes(data)
	return (
		ethernet.Ethernet.read_from_buffer(buf),
		arp.ARP.read_from_buffer(buf)
	)
