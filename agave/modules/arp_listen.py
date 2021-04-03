from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
import socket
import select
import logging


_NETWORK = {}


def push_data(ip: str, mac: str):
	if ip not in _NETWORK:
		_NETWORK[ip] = mac
		print(f"[INSERT] {ip} @ {mac}", flush=True)
	else:
		if _NETWORK[ip] != mac:
			_NETWORK[ip] = mac
			print(f"[UPDATE] {ip} @ {mac}", flush=True)


def process(buf: Buffer):
	"""
	Collects data from ARP messages. Target address are collected just
	for replies.
	"""
	eth_frame = ethernet.Ethernet.read_from_buffer(buf)
	if eth_frame.next_header == ethernet.ETHER_TYPE_ARP:
		arp_frame = arp.ARP.read_from_buffer(buf)
		if arp_frame.operation == arp.OPERATION_REPLY:
			push_data(
				str(ip_address(arp_frame.target_protocol_address)),
				ethernet.mac_to_str(arp_frame.target_hardware_address)
			)
		push_data(
			str(ip_address(arp_frame.sender_protocol_address)),
			ethernet.mac_to_str(arp_frame.sender_hardware_address)
		)


def loop(rawsocket, timeout):
	logging.info("Listening for ARP messages...")
	while True:
		rl, wl, xl = select.select([rawsocket], [], [], timeout)
		if rl != []:
			process(Buffer.from_bytes(rawsocket.recv(65535)))


def main(argv):
	try:
		rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		timeout = 1
		loop(rawsocket, timeout)
	except KeyboardInterrupt as e:
		pass
