from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
from typing import Iterator, Tuple
import socket
import select


_NETWORK = {}


def push_data(ip: str, mac: str):
	if ip not in _NETWORK:
		_NETWORK[ip] = mac
		print(f"[INSERT] {ip} @ {mac}", flush=True)
	else:
		if _NETWORK[ip] != mac:
			_NETWORK[ip] = mac
			print(f"[UPDATE] {ip} @ {mac}", flush=True)


def process(buf: Buffer) -> Iterator[Tuple[str, str]]:
	"""
	Collects data from ARP messages. Target address are collected just
	for replies.
	"""
	eth_frame = ethernet.Ethernet.read_from_buffer(buf)
	if eth_frame.next_header == ethernet.ETHER_TYPE_ARP:
		arp_frame = arp.ARP.read_from_buffer(buf)
		if arp_frame.operation == arp.OPERATION_REPLY:
			yield (
				str(ip_address(arp_frame.target_protocol_address)),
				ethernet.mac_to_str(arp_frame.target_hardware_address)
			)
		yield (
			str(ip_address(arp_frame.sender_protocol_address)),
			ethernet.mac_to_str(arp_frame.sender_hardware_address)
		)
	return


def read(rawsocket, timeout) -> Iterator[Tuple[str, str]]:
	rl, wl, xl = select.select([rawsocket], [], [], timeout)
	if rl != []:
		for item in process(Buffer.from_bytes(rawsocket.recv(65535))):
			yield item
	return


def main(argv):
	try:
		rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		timeout = 1
		print("Listening for ARP messages...")
		while True:
			for item in read(rawsocket, timeout):
				push_data(item[0], item[1])
	except KeyboardInterrupt as e:
		pass
