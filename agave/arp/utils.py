import socket, select
from typing import Tuple, Union,Callable
from agave.core.buffer import Buffer
from agave.core.arp import ARP, OPERATION_REQUEST
from agave.core.ethernet import Ethernet, ETHER_TYPE_ARP, MACAddress
from ipaddress import IPv4Address, IPv4Network


HOST = Host = Tuple[MACAddress, IPv4Address]
SOCKET_MAX_READ = 65535
SOCKET_PROTO = socket.htons(ETHER_TYPE_ARP)


def _create_socket():
	"""Creates a socket.

    Returns:
        A raw socket with protocol ARP.

    """
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, SOCKET_PROTO)


def _parse(data: bytes) -> Tuple[Ethernet, ARP]:
	"""Parses Ethernet and ARP frames.
		
	Args:
		data: an ARP message, including the Ethernet header.

	Returns:
		Ethernet and ARP frames.

	"""
	buf = Buffer.from_bytes(data)
	return (
		Ethernet.read_from_buffer(buf),
		ARP.read_from_buffer(buf)
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
				if address[1] != ETHER_TYPE_ARP:
					continue
				eth_frame, arp_frame = _parse(data)
				self.process(address, eth_frame, arp_frame)
			self.after()

	def process(self, address: Tuple, eth: Ethernet, frame: ARP):
		"""This method is called for each ARP message received."""
		pass

	def after(self):
		"""This method is called after the read operation is completed."""
		pass


def create_filter(
	operation: int,
	sender: Union[IPv4Address, IPv4Network] = None,
	target: Union[IPv4Address, IPv4Network] = None
) -> Callable[[ARP], bool]:
	"""Creates a filter for ARP messages.

	Args:
		operation: operation to filter (request/reply).
		sender: sender protocol address or a subnet.
		target: target protocol address or a subnet.
	
	Returns:
		A function that return True if all the condition
		are matched.

	"""
	if type(sender) == IPv4Address:
		sender = IPv4Network(sender, 32)
	if type(target) == IPv4Address:
		target = IPv4Network(target, 32)
	if sender is None:
		sender = IPv4Network("0.0.0.0/0")
	if target is None:
		target = IPv4Network("0.0.0.0/0")

	def fn(frame: ARP) -> bool:
		return ( 
			frame.operation == operation and
			IPv4Address(frame.target_protocol_address) in target and
			IPv4Address(frame.sender_protocol_address) in sender
		)

	return fn
