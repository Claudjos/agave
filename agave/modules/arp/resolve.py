import socket, select, time
from typing import Union, Iterator, Tuple
from agave.frames.ethernet import MACAddress
from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import IPv4Address, IPv4Network, ip_network
from agave.modules.nic.interfaces import NetworkInterface, NetworkInterfaceNotFound


def _create_socket():
	"""Creates a socket.

    Returns:
        A raw socket with protocol ARP.

    """
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethernet.ETHER_TYPE_ARP))


def discover(
	interface: Union[str, NetworkInterface],
	subnet: Union[str, IPv4Network] = None,
	sock: "socket.socket" = None,
	max_wait: float = 0.1,
	retry: int = 3
) -> Iterator[Tuple[MACAddress, IPv4Address]]:
	sock = _create_socket()
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str:
		subnet = ip_network(subnet)
	if subnet is None:
		subnet = interface.network
	for address in subnet.hosts():
		mac = resolve(interface, address, sock, max_wait, retry)
		if mac is not None:
			yield (mac, address)
	return


def resolve(
	interface: Union[str, NetworkInterface],
	address: Union[str, IPv4Address],
	sock: "socket.socket" = None,
	max_wait: float = 0.1,
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
	sock.sendto(request, (interface.name, socket.htons(ethernet.ETHER_TYPE_ARP)))
	# Waits for reply until the deadline
	while True:
		rl, wl, xl = select.select([sock], [], [], timeout)
		if rl != []:
			buf = Buffer.from_bytes(sock.recv(65535))
			eth_frame = ethernet.Ethernet.read_from_buffer(buf)
			arp_frame = arp.ARP.read_from_buffer(buf)
			if ( 
				arp_frame.operation == arp.OPERATION_REPLY and
				arp_frame.sender_protocol_address == address.packed
			):
				return MACAddress(arp_frame.sender_hardware_address)
		if time.time() >= deadline:
			return None
