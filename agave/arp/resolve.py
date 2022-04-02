"""This module provides primitives to resolve an IPv4 address into a MAC
address.
"""
import select, time
from typing import Union
from .utils import _create_socket, _parse, SOCKET_PROTO, SOCKET_MAX_READ
from agave.frames.ethernet import MACAddress
from agave.frames import ethernet, arp
from agave.modules.nic.interfaces import NetworkInterface
from ipaddress import IPv4Address


def resolve(
	interface: Union[str, NetworkInterface],
	address: Union[str, IPv4Address],
	sock: "socket.socket" = None,
	max_wait: float = 0.5,
	retry: int = 3
):
	"""Resolve the MAC address for a given IP.
	
	Args:
		interface: the interface to use.
		address: the IP address to resolve.
		sock: a socket to use.
		max_wait: max amount of seconds before to give up.
		retry: number of request to send before to give up.

	Returns:
		The MAC address for the given IP address or None.

	"""
	mac = None
	while retry > 0 and mac is None:
		retry -= 1
		mac = _resolve(interface, address, sock, max_wait)
	return mac


def _resolve(
	interface: Union[str, NetworkInterface],
	address: Union[str, IPv4Address],
	sock: "socket.socket" = None,
	max_wait: float = 0.1
) -> Union[MACAddress, None]:
	"""Send a ARP Request and wait for the reply.
	
	Args:
		interface: the interface to use.
		address: the IP address to resolve.
		sock: a socket to use.
		max_wait: max amount of seconds before to give up.

	Returns:
		The MAC address for the given IP address or None.

	"""
	# Initialize vars
	deadline = time.time() + max_wait
	timeout = max_wait / 10
	# Initialize arguments
	if sock is None:
		sock = _create_socket()
	if type(address) == str:
		address = IPv4Address(address)
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	# Creates and send ARP request
	request = arp.ARP.who_has(
		interface.mac.address,
		interface.ip, 
		b'\xff\xff\xff\xff\xff\xff',
		address
	)
	sock.sendto(request, (interface.name, SOCKET_PROTO))
	# Waits for reply until the deadline
	while True:
		rl, wl, xl = select.select([sock], [], [], timeout)
		if rl != []:
			eth_frame, arp_frame = _parse(sock.recv(SOCKET_MAX_READ))
			if ( 
				arp_frame.operation == arp.OPERATION_REPLY and
				arp_frame.sender_protocol_address == address.packed
			):
				return MACAddress(arp_frame.sender_hardware_address)
		if time.time() >= deadline:
			return None


if __name__ == "__main__":
	"""
	Given an IPv4, retrieves the MAC address.

	Usage:
		python3 -m agave.arp.resolve <IPv4>

	Example:
		python3 -m agave.arp.resolve 192.168.1.1

	"""
	import sys


	if len(sys.argv) < 1:
		print("Too few parameters")
	else:
		mac = resolve(NetworkInterface.get_by_host(sys.argv[1]), sys.argv[1])
		print("Host not found" if mac is None else str(mac))
