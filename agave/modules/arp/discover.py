from typing import Iterator, Tuple
from agave.frames import ethernet
from agave.frames.core import Buffer
from ipaddress import ip_address
import socket, select, time
from .solicit import all_packet
from .listen import Network


def main(argv):
	if len(argv) < 4:
		print("Too few parameters")
	else:
		print("Looking for hosts...")
		for op, ip, mac in discover(argv[0], argv[1], argv[2], argv[3]):
			print("[{}] {}\t{}".format(
				Network.OP[op],
				ip,
				mac
			))


def discover(
	iface: str,
	subnet: str,
	ipv4: str,
	mac: str,
	send_interval = 0.005,
	final_wait = 1,
	repeat_solicit = 3
) -> Iterator[Tuple[str, str, str]]:
	
	net = Network()
	interface = (iface, 1)
	sender_mac = ethernet.str_to_mac(mac)
	sender_ipv4 = ip_address(ipv4)
	broadcast = b'\xff\xff\xff\xff\xff\xff'
	rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	
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
					rawsocket.sendto(frame, interface)
					next_send = time.time() + send_interval
			else:
				flag_loop = False

	return
