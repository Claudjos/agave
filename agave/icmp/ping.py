"""ICMPv4 Echo request/reply PING.

The module provides a script to discover host in a network by 
using Echo ICMPv4 messages. With the option -m, returns also
the host for which neither a reply or a destination unreachable 
message was received.

Usage:
	python3 -m agave.icmp.discover <subnet> [-m]

Example:
	python3 -m agave.icmp.discover 192.168.1.0/24
	python3 -m agave.icmp.discover 192.168.1.0/24 -m

"""
import socket
from agave.core.helpers import Job, SocketAddress
from agave.core.icmpv4 import ICMPv4, TYPE_ECHO_REPLY, TYPE_DESTINATION_UNREACHABLE
from agave.core.ip import IPv4
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import List, Tuple, Iterator


class Pinger(Job):

	def __init__(self, sock: "socket.socket", subnet: IPv4Network, repeat: int = 2, **kwargs):
		super().__init__(sock, **kwargs)
		self.subnet = subnet
		self.packets_to_send = self.generate_echo_requests(subnet, repeat)
		self._cache = set()
		self._count = self.subnet.num_addresses

	def loop(self) -> bool:
		for message in self.packets_to_send:
			self.sock.sendto(*message)
			return True
		return False

	def process(self, data: bytes, address: SocketAddress) -> Tuple[bool, IPv4Address, int]:
		ip_h, icmp_h = ICMPv4.parse(data)
		if address[0] not in self._cache and icmp_h.type == TYPE_ECHO_REPLY:
			self._count -= 1
			self._cache.add(address[0])
			return True, IPv4Address(address[0]), ip_h.ttl
		if icmp_h.type == TYPE_DESTINATION_UNREACHABLE:
			ip_frame = IPv4.from_bytes(icmp_h.data)
			destination = IPv4Address(ip_frame.destination)
			if destination not in self._cache and ip_frame.is_checksum_valid():
				self._count -= 1
				self._cache.add(str(destination))
		if self._count < 1:
			self.set_finished()

	def get_missing_hosts(self) -> set:
		return set(map(lambda x: str(x), self.subnet.hosts())) - self._cache

	@classmethod
	def generate_echo_requests(cls, subnet: IPv4Network, repeat: int) -> Iterator[Tuple[bytes, SocketAddress]]:
		for _ in range(0, repeat):
			for address in subnet.hosts():
				t = ICMPv4.echo(b"abcdefghijklmonpqrstuvwxyz")
				t.set_checksum()
				yield bytes(t), (str(address), 0)
		return


if __name__ == "__main__":

	import sys


	# Parsing arguments
	if len(sys.argv) < 2:
		print("Too few parameters")
		exit(0)
	if len(sys.argv) > 2 and sys.argv[2] == "-m":
		print("[INFO] Script will wait additional ten seconds for destination unreachable messages.")
		print_missing = True
		wait = 10
	else:
		print_missing = False
		wait = 0.5
	# Create Job
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	job = Pinger(
		sock,
		ip_network(sys.argv[1]),
		interval=0.05,
		wait=wait
	)
	# Ping
	for flag, ip, ttl in job.stream():
		if flag:
			print(f"{ip}\t{ttl}")
	# Missing
	if print_missing:
		miss = job.get_missing_hosts()
		if len(miss) > 0:
			print("[INFO] Hosts for which a destination unreachable message wasn't received:")
			print("\n".join(map(lambda x: f"\t - {x}", miss)))
		else:
			print("[INFO] Destination unreachable message was received for all missing host.")

