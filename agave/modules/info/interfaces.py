import socket, fcntl, struct
from typing import List
from ipaddress import ip_address, ip_network
from .base import NetworkInterface, MACAddress


"""
From <bits/ioctls.h>
"""
SIOCGIFADDR = 0x8915 		# get PA address
SIOCGIFBRDADDR = 0x8919 	# get broadcast PA address
SIOCGIFNETMASK = 0x891b 	# get network PA mask
SIOCGIFHWADDR = 0x8927 		# get HW address


class NetworkInterfaceNotFound(Exception):
	pass


def get_socket() -> socket.socket:
	return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def get_interface_by_name(nic_name: str) -> NetworkInterface:
	with get_socket() as s:
		return get_interface_by_name_fileno(nic_name, s.fileno())


def get_interface_by_name_fileno(nic_name: str, fileno: int) -> NetworkInterface:
	"""
	TODO
		- add support for IPv6 network
	"""
	try:
		iface = struct.pack('256s', bytes(nic_name, 'utf-8')[:15])
		mac = MACAddress(fcntl.ioctl(fileno, SIOCGIFHWADDR, iface)[18:24])
	except OSError:
		raise NetworkInterfaceNotFound()
	try:
		ip = ip_address(fcntl.ioctl(fileno, SIOCGIFADDR, iface)[20:24])
		broadcast = ip_address(fcntl.ioctl(fileno, SIOCGIFBRDADDR, iface)[20:24])
		netmask = ip_address(fcntl.ioctl(fileno, SIOCGIFNETMASK, iface)[20:24])
		network_address = ip_address(int.from_bytes(netmask.packed, byteorder="big") & int.from_bytes(ip.packed, byteorder="big"))
		network = ip_network("{}/{}".format(
			network_address,
			netmask
		))
	except:
		ip = broadcast = network = None
	return NetworkInterface(
		nic_name,
		mac,
		ip,
		network,
		broadcast
	)


def get_interfaces() -> List[NetworkInterface]:
	interfaces = []
	with get_socket() as s:
		fileno = s.fileno()
		for _, nic_name in socket.if_nameindex():
			interfaces.append(get_interface_by_name_fileno(nic_name, fileno))
	return interfaces
