import socket
from typing import Tuple
from agave.frames import ethernet, arp
from agave.frames.core import Buffer


def _create_socket():
	"""Creates a socket.

    Returns:
        A raw socket with protocol ARP.

    """
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethernet.ETHER_TYPE_ARP))


def _parse(data: bytes) -> Tuple[ethernet.Ethernet, arp.ARP]:
	buf = Buffer.from_bytes(data)
	return (
		ethernet.Ethernet.read_from_buffer(buf),
		arp.ARP.read_from_buffer(buf)
	)
