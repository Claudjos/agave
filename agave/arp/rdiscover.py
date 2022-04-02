from typing import Iterator, Tuple, Union
from .utils import _create_socket
from .resolve import resolve
from agave.core.ethernet import MACAddress
from agave.nic.interfaces import NetworkInterface
from ipaddress import IPv4Address, IPv4Network, ip_network


def discover(
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


if __name__ == "__main__":
	"""
	Discovers host in a subnet.

	Usage:
		python3 -m agave.arp.rdiscover <interface> [subnet]

	Example:
		python3 -m agave.arp.rdiscover eth0
		python3 -m agave.arp.rdiscover eth0 192.168.1.0/24

	"""
	import sys


	print("Looking for hosts...")
	subnet = sys.argv[2] if len(sys.argv) > 2 else None
	for mac, ip in discover(sys.argv[1], subnet=subnet):
		print("{}\t{}".format(ip, str(mac)))
