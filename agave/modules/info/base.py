from typing import Union
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network


IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


class MACAddress:

	__slots__ = ["address"]

	def __init__(self, address: Union[bytes, str]):
		if type(address) == str:
			self.address = self.str_to_mac(address)
		else:
			self.address = address

	@classmethod
	def str_to_mac(cls, address: str):
		return bytes(map(lambda x: int(x, 16), address.split(":")))

	@classmethod
	def mac_to_str(cls, address: str):
		return ':'.join('%02x'%i for i in address)

	def __str__(self):
		return self.mac_to_str(self.address)


class NetworkInterface:

	__slots__ = ["name", "mac", "ip", "network", "broadcast"]

	def __init__(self, name: str, mac: MACAddress, ip: IPAddress, 
		network: IPNetwork, broadcast: IPAddress):
		self.name = name
		self.mac = mac
		self.ip = ip
		self.network = network
		self.broadcast = broadcast

	def __str__(self):
		return self.name
