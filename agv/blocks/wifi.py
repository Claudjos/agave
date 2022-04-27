"""Simple functions to retrieve Service Set informations."""
import socket
from typing import Tuple, Union, Iterable
from agave.models.ethernet import MACAddress
from agave.models.wifi.mac import ProbeResponse, Beacon
from agave.utils.interfaces import NetworkInterface
from agv.jobs.wifi import Scanner, StationsMapper


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
		sock = create_socket(interface)
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


def create_socket(interface: Union[str, NetworkInterface]) -> "socket.socket":
	"""Creates a socket."""
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind((interface if isinstance(interface, str) else interface.name, 0))
	return sock


def list_bss_clients(bssid: MACAddress, sock: "socket.socket", wait: float = 10) -> Iterable[Tuple[MACAddress]]:
	"""List clients connected to a BSS.

	Args:
		bssid: BSSID.
		sock: socket to use.
		wait: interval to wait, None to never stop listening.

	Yields:
		The MAC address of each client.

	"""
	stream = StationsMapper(sock, [bssid], wait=wait).stream()
	for results in stream:
		for bssid, client in results:
			yield client
	return

