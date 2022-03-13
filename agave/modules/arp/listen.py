from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
from typing import Iterator, Tuple
import socket
import select


class Network:

	OP_PASS = 0
	OP_INSERT = 1
	OP_UPDATE = 2

	OP = ["PASS", "INSERT", "UPDATE"]

	def __init__(self):
		self._network = {}

	def process(self, ip: str, mac: str) -> int:
		if ip not in self._network:
			self._network[ip] = mac
			return self.OP_INSERT
		else:
			if self._network[ip] != mac:
				return self.OP_UPDATE
			else:
				return self.OP_PASS

	def parse(self, buf: Buffer) -> Iterator[Tuple[str, str, str]]:
		"""
		Collects data from ARP messages. Target address are collected just
		for replies.
		"""
		eth_frame = ethernet.Ethernet.read_from_buffer(buf)
		if eth_frame.next_header == ethernet.ETHER_TYPE_ARP:
			arp_frame = arp.ARP.read_from_buffer(buf)
			if arp_frame.operation == arp.OPERATION_REPLY:
				ip = str(ip_address(arp_frame.target_protocol_address))
				eth = ethernet.mac_to_str(arp_frame.target_hardware_address)
				status = self.process(ip, eth)
				if status is not self.OP_PASS:
					yield status, ip, eth
			ip = str(ip_address(arp_frame.sender_protocol_address))
			eth = ethernet.mac_to_str(arp_frame.sender_hardware_address)
			status = self.process(ip, eth)
			if status is not self.OP_PASS:
				yield status, ip, eth
		return


def listen(timeout = 1) -> Iterator[Tuple[str, str, str]]:
	net = Network()
	rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	while True:
		rl, wl, xl = select.select([rawsocket], [], [], timeout)
		if rl != []:
			for item in net.parse(Buffer.from_bytes(rawsocket.recv(65535))):
				yield item
	return


def main(argv):
	try:
		print("Listening for ARP messages...")
		while True:
			for op, ip, mac in listen():
				print("[{}] {}\t{}".format(
					Network.OP[op],
					ip,
					mac
				))
	except KeyboardInterrupt as e:
		pass
