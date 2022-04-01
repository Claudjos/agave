from typing import Iterator, Tuple
from agave.frames import ethernet
from agave.frames.core import Buffer
from ipaddress import ip_address
import socket, select, time
from .solicit import all_packet
from .listen import Network
from ipaddress import IPv4Address, IPv4Network, ip_network
from agave.modules.nic.interfaces import NetworkInterface, NetworkInterfaceNotFound
from typing import Union


def discover(
	interface: Union[str, NetworkInterface],
	subnet: Union[str, IPv4Network] = None,
	send_interval: float = 0.005,
	final_wait: float = 1,
	repeat_solicit: int = 2
) -> Iterator[Tuple[str, str, str]]:
	
	if type(interface) == str:
		interface = NetworkInterface.get_by_name(interface)
	if type(subnet) == str:
		subnet = ip_network(subnet)
	if subnet is None:
		subnet = interface.network
	net = Network()
	sender_mac = interface.mac.address
	sender_ipv4 = interface.ip
	broadcast = b'\xff\xff\xff\xff\xff\xff'
	rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethernet.ETHER_TYPE_ARP))
	
	frame_iterator = all_packet(subnet, sender_mac, sender_ipv4, broadcast, repeat=repeat_solicit)
	flag_loop = True
	flag_sending = True
	select_timeout = send_interval
	next_send = time.time() + send_interval

	while flag_loop:

		rl, wl, xl = select.select([rawsocket], [], [], select_timeout)
		
		if rl != []:
			for item in net.parse(Buffer.from_bytes(rawsocket.recv(65535))):
				if item is not None:
					yield item

		if time.time() > next_send:
			if flag_sending:
				try:
					frame = next(frame_iterator)
				except StopIteration:
					flag_sending = False
					next_send = time.time() + final_wait
					select_timeout = final_wait
				else:
					rawsocket.sendto(frame, (interface.name, 1))
					next_send = time.time() + send_interval
			else:
				flag_loop = False

	return
