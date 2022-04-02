import socket, select
from typing import Tuple
from agave.core import ethernet, arp
from agave.core.buffer import Buffer
from ipaddress import IPv4Address


HOST = Tuple[ethernet.MACAddress, IPv4Address]
SOCKET_MAX_READ = 65535
SOCKET_PROTO = socket.htons(ethernet.ETHER_TYPE_ARP)


def _create_socket():
	"""Creates a socket.

    Returns:
        A raw socket with protocol ARP.

    """
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, SOCKET_PROTO)


def _parse(data: bytes) -> Tuple[ethernet.Ethernet, arp.ARP]:
	"""Parses Ethernet and ARP frames.
		
	Args:
		data: an ARP message, including the Ethernet header.

	Returns:
		Ethernet and ARP frames.

	"""
	buf = Buffer.from_bytes(data)
	return (
		ethernet.Ethernet.read_from_buffer(buf),
		arp.ARP.read_from_buffer(buf)
	)


class ARPReaderLoop:
	"""This is a framework for a process processing ARP messages."""
	
	__slots__ = ["sock", "timeout", "flag"]

	def __init__(
		self,
		sock: "socket.socket" = None,
		selector_timeout: float = 1
	):
		if sock is None:
			sock = _create_socket()
		self._sock : "socket.socket" = sock
		self._timeout : float = selector_timeout

	def stop(self):
		"""Stops the running loop within Listener.timeout seconds."""
		self._flag = False

	def run(self):
		"""Main loop."""
		self._flag = True
		while self._flag:
			rl, wl, xl = select.select([self._sock], [], [], self._timeout)
			if rl != []:
				data, address = self._sock.recvfrom(SOCKET_MAX_READ)
				if address[1] != ethernet.ETHER_TYPE_ARP:
					continue
				eth_frame, arp_frame = _parse(data)
				self.process(address, eth_frame, arp_frame)
			self.after()

	def process(self, address: Tuple, eth: ethernet.Ethernet, frame: arp.ARP):
		"""This method is called for each ARP message received."""
		pass

	def after(self):
		"""This method is called after the read operation is completed."""
		pass
