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
