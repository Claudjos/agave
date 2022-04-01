"""Modules including utilities to discover hosts in a subnet
through ARP.
"""
import select, time
from typing import Iterator, Tuple, Union
from .solicit import all_packet
from .utils import _create_socket, _parse, SOCKET_MAX_READ, SOCKET_PROTO
from .resolve import resolve
from agave.frames import ethernet, arp
from agave.frames.ethernet import MACAddress
from agave.modules.nic.interfaces import NetworkInterface
from ipaddress import IPv4Address, IPv4Network, ip_network, ip_address


def r_discover(
	interface: Union[str, NetworkInterface],
	subnet: Union[str, IPv4Network] = None,
	sock: "socket.socket" = None,
	max_wait: float = 0.1,
	retry: int = 3
) -> Iterator[Tuple[MACAddress, IPv4Address]]:
	"""Finds host in a subnet by repeatedly call the primitive
	resolve.

	Args:
		interface: the interface to use.
		subnet: the subnet to explore.
		sock: a socket to use.
		max_wait: max amount of seconds before to give up.
		retry: number of request to send before to give up.
	
	Yields:
		Hardware and protocol address of the host found.

	"""
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str:
		subnet = ip_network(subnet)
	if subnet is None:
		subnet = interface.network
	if sock is None:
		sock = _create_socket()
	for address in subnet.hosts():
		mac = resolve(interface, address, sock, max_wait, retry)
		if mac is not None:
			yield (mac, address)
	return


def discover(
	interface: Union[str, NetworkInterface],
	subnet: Union[str, IPv4Network] = None,
	sock: "socket.socket" = None,
	send_interval: float = 0.005,
	final_wait: float = 1,
	repeat_solicit: int = 2
) -> Iterator[Tuple[MACAddress, IPv4Address]]:
	"""Discover host in a subnet using ARP messages.

	Args:
		interface: the interface to use.
		subnet: the subnet to explore.
		sock: a socket to use.
		send_interval: delta time in seconds between requests.
		final_wait: time to wait after all the request have been sent.
		repeat_solicit: number of request to send per host.
	
	Yields:
		Hardware and protocol address of the host found.

	"""
	# Initialize arguments
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str:
		subnet = ip_network(subnet)
	if subnet is None:
		subnet = interface.network
	if sock is None:
		sock = _create_socket()
	# Initialize vars
	cache = set()
	request_iterator = request_all_network(
		subnet,
		interface.mac.address,
		interface.ip,
		repeat=repeat_solicit
	)
	flag_loop = True
	flag_sending = True
	select_timeout = send_interval
	next_send = time.time() + send_interval
	# Loop
	while flag_loop:
		rl, wl, xl = select.select([sock], [], [], select_timeout)
		# Parses ARP replies and yields
		if rl != []:
			_, frame = _parse(sock.recv(SOCKET_MAX_READ))
			if frame.operation == arp.OPERATION_REPLY:
				sender = (
					frame.sender_hardware_address,
					frame.sender_protocol_address
				)
				if sender not in cache:
					cache.add(sender)
					yield MACAddress(sender[0]), IPv4Address(sender[1])
		# Sends ARP requests
		if time.time() > next_send:
			if flag_sending:
				try:
					request = next(request_iterator)
				except StopIteration:
					flag_sending = False
					next_send = time.time() + final_wait
					select_timeout = final_wait
				else:
					sock.sendto(request, (interface.name, SOCKET_PROTO))
					next_send = time.time() + send_interval
			else:
				flag_loop = False
	return


def request_all_network(subnet: IPv4Network, sender_mac: bytes, sender_ipv4: bytes,
	broadcast: bytes = b'\xff\xff\xff\xff\xff\xff', repeat: int = 1
) -> Iterator[bytes]:
	"""Creates ARP request for each host in subnet.

	Args:
		subnet: subnet to explore.
		sender_mac: sender MAC address.
		sender_ipv4: sender IPv4 address.
		broadcast: broadcast MAC address.
		repeat: number of requests to generate for each host.

	Yields:
		A frame including Ethernet and ARP layer.

	"""
	for _ in range(0, repeat):
		for address in subnet.hosts():
			yield arp.ARP.who_has(sender_mac, sender_ipv4, broadcast, address)
	return
