"""Miscellaneous code to reuse in scripts."""
from agave.models.ethernet import MACAddress
from agave.utils.interfaces import NetworkInterfaceNotFound, NetworkInterface
from agv.blocks.wifi import ServiceSetNotFound, get_service_set_address


def read_mac_or_die(x: str) -> MACAddress:
	try:
		return MACAddress(x)
	except ValueError:
		print("Invalid MAC Address {}".format(x))
		exit(0)


def read_bssid_or_die(x: str, i: str) -> MACAddress:
	try:
		return MACAddress(x)
	except ValueError:
		try:
			return get_service_set_address(x, i)
		except ServiceSetNotFound:
			print("Couldn't find a SS {}".format(x))
			exit(0)
		except NetworkInterfaceNotFound as e:
			print(e)
			exit(0)


def read_interface_or_die(x: str) -> NetworkInterface:
	try:
		return NetworkInterface.get_by_name(x)
	except NetworkInterfaceNotFound as e:
			print(e)
			exit(0)

