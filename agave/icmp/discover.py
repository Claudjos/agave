"""ICMPv4 host discover utilities.

Todo:
	* clean up this mess.

The module provides a script to discover host in a network
by using Echo ICMPv4 messages.

Usage:
	python3 -m agave.icmp.discover <subnet>

Example:
	python3 -m agave.icmp.discover 192.168.1.0/24

"""
from agave.core.helpers import Job, SocketAddress
from agave.core import ethernet, ip, icmpv4 as icmp
from agave.core.buffer import Buffer
from ipaddress import ip_address, ip_network
import socket
from typing import List


class NetworkReport:

	STATUS_REACHED = 1
	STATUS_UNREACHABLE = 2
	STATUS_UNKNOWN = 3

	def __init__(self, subnet: str):
		self.subnet = ip_network(subnet)
		self.all_hosts = list(map(lambda x: x._ip, self.get_hosts()))
		self.hosts_status = [(self.STATUS_UNKNOWN, None)] * len(self.all_hosts)

	def get_hosts(self):
		for address in self.subnet.hosts():
			yield address
		return

	def get_index(self, ip: bytes):
		try:
			return self.all_hosts.index(ip_address(ip)._ip)
		except ValueError:
			return None

	def set_unreachable(self, ip: bytes):
		index = self.get_index(ip)
		if index != None:
			self.hosts_status[index] = (self.STATUS_UNREACHABLE, None)

	def set_reached(self, ip: bytes, ttl: int):
		index = self.get_index(ip)
		if index != None:
			self.hosts_status[index] = (self.STATUS_REACHED, ttl)

	def process_frame(self, ip_frame: ip.IPv4, icmp_frame: icmp.ICMPv4):
		if icmp_frame.type == icmp.TYPE_ECHO_REPLY:
			# print("ECHO REPLY", icmp_frame, icmp_frame.data, flush=True)
			self.set_reached(ip_frame.source, ip_frame.ttl)
		elif icmp_frame.type == icmp.TYPE_DESTINATION_UNREACHABLE:
			# print("DESTINATION UNREACHABLE", icmp_frame, flush=True)
			original_ip_frame = ip.IPv4.read_from_buffer(Buffer.from_bytes(icmp_frame.data))
			if original_ip_frame.is_checksum_valid():
				self.set_unreachable(original_ip_frame.destination)
		else:
			# print(icmp_frame, flush=True)
			pass

	def build_echo_requests(self, repeat: int = 2):
		for _ in range(0, repeat):
			for address in self.all_hosts:
				buf = Buffer.from_bytes()
				t = icmp.ICMPv4.echo(b"abcdefghijklmonpqrstuvwxyz")
				t.set_checksum()
				t.write_to_buffer(buf)
				yield bytes(buf), (str(ip_address(address)), 0)
		return

	def get_confirmed_host(self):
		out = []
		for i in range(0, len(self.hosts_status)):
			status, ttl = self.hosts_status[i]
			if status == self.STATUS_REACHED:
				out.append("{} {}".format(str(ip_address(self.all_hosts[i])), str(ttl)))
		return out

	def get_missing_host(self):
		out = []
		for i in range(0, len(self.hosts_status)):
			status, ttl = self.hosts_status[i]
			if status == self.STATUS_UNKNOWN:
				out.append("{}".format(str(ip_address(self.all_hosts[i]))))
		return out


class Pinger(Job):

	def __init__(self, sock: "socket.socket", report: NetworkReport, **kwargs):
		super().__init__(sock, wait=0.5, **kwargs)
		self.report = report
		self.packets_to_send = report.build_echo_requests()

	def loop(self) -> bool:
		for message in self.packets_to_send:
			self.sock.sendto(*message)
			return True
		return False

	def process(self, data: bytes, address: SocketAddress) -> None:
		buf = Buffer.from_bytes(data)
		ip_frame = ip.IPv4.read_from_buffer(buf)
		icmp_frame = icmp.ICMPv4.read_from_buffer(buf)
		self.report.process_frame(ip_frame, icmp_frame)


if __name__ == "__main__":

	import sys


	if len(sys.argv) < 2:
		print("Too few parameters")
	else:
		report = NetworkReport(sys.argv[1])
		scanner = Pinger(
			socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
			report,
			interval=0.1
		)
		print("Scanning..")
		scanner.run()
		print("Hosts found:")
		for i in report.get_confirmed_host():
			print(i)
		print("Hosts for which a destination unreachable message wasn't received:")
		for i in report.get_missing_host():
			print(i)

