"""ICMPv6 Echo request/reply PING.

The module provides a script to discover host in a network by 
using Echo ICMPv6 messages. With the option -m, returns also
the host for which neither a reply or a destination unreachable 
message was received.

"""
import socket, array
from agave.core.helpers import Job, SocketAddress
from agave.core.icmpv6 import ICMPv6, TYPE_ECHO_REPLY, TYPE_DESTINATION_UNREACHABLE
from agave.core.ip import IPv6, PROTO_ICMPv6
from ipaddress import IPv6Address, IPv6Network, ip_network
from typing import List, Tuple, Iterator


class Pinger(Job):

	def __init__(self, sock: "socket.socket", subnet: IPv6Network, repeat: int = 2, **kwargs):
		super().__init__(sock, **kwargs)
		self.subnet = subnet
		self.packets_to_send = self.generate_echo_requests(subnet, repeat)
		self._cache = set()
		self._count = self.subnet.num_addresses
		self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1);

	def loop(self) -> bool:
		for message in self.packets_to_send:
			self.sock.sendto(*message)
			return True
		return False

	def recv_message(self):
		fds = array.array("i")
		m, ancillary_data, _, addr = self.sock.recvmsg(self.max_read, 
			socket.CMSG_LEN(socket.CMSG_LEN(10 * fds.itemsize)), socket.IPV6_HOPLIMIT)
		return m, ancillary_data[0][2][0], addr

	def process(self, data: bytes, hop_limit: int, address: SocketAddress) -> Tuple[bool, IPv6Address, int]:
		result = None
		p_h, icmp_h = None, ICMPv6.parse(data)[0]
		if address[0] not in self._cache and icmp_h.type == TYPE_ECHO_REPLY:
			self._count -= 1
			self._cache.add(address[0])
			result = True, IPv6Address(address[0]), hop_limit
		if icmp_h.type == TYPE_DESTINATION_UNREACHABLE:
			ip_frame = IPv6.from_bytes(icmp_h.payload)
			destination = IPv6Address(ip_frame.destination)
			if destination not in self._cache:# and ip_frame.is_checksum_valid():
				self._count -= 1
				self._cache.add(str(destination))
		if self._count < 1:
			self.set_finished()
		return result

	def get_missing_hosts(self) -> set:
		return set(map(lambda x: str(x), self.subnet.hosts())) - self._cache

	def generate_echo_requests(self, subnet: IPv6Network, repeat: int) -> Iterator[Tuple[bytes, SocketAddress]]:
		for _ in range(0, repeat):
			for address in subnet.hosts():
				if address not in self._cache:
					yield (
						bytes(ICMPv6.echo_request(b"abcdefghijklmonpqrstuvwxyz")),
						(str(address), 0)
					)
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
	sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
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

