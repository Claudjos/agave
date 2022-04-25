"""Simple functions to retrieve Service Set informations."""
import socket
from typing import Tuple, Union
from agave.core.ethernet import MACAddress
from agave.core.wifi.mac import ProbeResponse, Beacon
from agave.utils.interfaces import NetworkInterface
from agv.jobs.wifi.scan import Scanner


class ServiceSetNotFound(Exception):
	pass


def get_service_set_by_id(ssid: str, interface: Union[NetworkInterface, str], 
	sock: "socket.socket" = None) -> Tuple[MACAddress, Union[ProbeResponse, Beacon]]:
	"""Retrieves information about a Service Set (BSS or ESS).
	
	Args:
		ssid: the service set identifier.
		interface: interface to use.
		sock: socket to use.

	Returns:
		The SS Address and frame received (either a Beacon or a ProbeResponse).

	Raises:
		ServiceSetNotFound: if no data are found for the given SSID.

	"""
	if isinstance(interface, str):
		interface = NetworkInterface.get_by_name(interface)
	if sock is None:
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		sock.bind((interface.name, 0))
	job = Scanner(sock, interface, [ssid], Scanner.build_probe_request(
		interface.mac, [ssid]), repeat=3, interval=0.1, wait=1)
	for mac, ssid, frame in job.stream():
		return mac, frame
	raise ServiceSetNotFound()


def get_service_set_address(ssid: str, interface: Union[NetworkInterface, str], 
	sock: "socket.socket" = None) -> MACAddress:
	"""Retrieves Service Set MAC Address.
	
	Args:
		ssid: the service set identifier.
		interface: interface to use.
		sock: socket to use.

	Returns:
		The SS Address.

	Raises:
		ServiceSetNotFound: if no data are found for the given SSID.

	"""
	return get_service_set_by_id(ssid, interface, sock)[0]

