from agave.core import ethernet, ip, icmp
from agave.core.buffer import Buffer
from ipaddress import ip_address, ip_network
import socket, select, time
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

	def process_frame(self, ip_frame: ip.IPv4, icmp_frame: icmp.ICMP):
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
				t = icmp.ICMP.echo(b"abcdefghijklmonpqrstuvwxyz")
				t.set_checksum()
				t.write_to_buffer(buf)
				yield str(ip_address(address)), bytes(buf)
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


class NetScanner:

	def __init__(self, recv_socket, send_socket, report: NetworkReport, timeout: float):
		self.timeout = timeout
		self.report = report
		self.recv_socket = recv_socket
		self.send_socket = send_socket
		self.last_send = 0
		self.packets_to_send = report.build_echo_requests()

	def time_to_send(self) -> bool:
		return (time.time() - self.last_send)  > self.timeout

	def send(self, destination: str, data: bytes):
		self.send_socket.sendto(data, (destination, 0))
		self.last_send = time.time()

	def run(self):
		"""
		TODO
			- handling incomplete send (Is it necessary?)
			- wait some time before exiting after sending phase is completed
		"""
		flag = True
		while flag:
			rl, wl, xl = select.select([self.recv_socket], [], [], self.timeout)
			if rl != []:
				ip_frame, icmp_frame = self.read_icmp(
					Buffer.from_bytes(self.recv_socket.recv(65535))
				)
				if icmp_frame is not None:
					self.report.process_frame(ip_frame, icmp_frame)
			if self.time_to_send():
				try:
					self.send(*next(self.packets_to_send))
				except StopIteration:
					flag = False

	def read_icmp(self, buf: Buffer):
		eth_frame = ethernet.Ethernet.read_from_buffer(buf)
		if eth_frame.next_header == ethernet.ETHER_TYPE_IPV4:
			ip_frame = ip.IPv4.read_from_buffer(buf)
			if ip_frame.protocol == ip.PROTO_ICMP:
				icmp_frame = icmp.ICMP.read_from_buffer(buf)
				return ip_frame, icmp_frame
		return None, None


if __name__ == "__main__":
	"""
	Discovers host in a network by using Echo ICMP messages.

	Usage:
		python3 -m agave.icmp.discover <subnet>

	Example:
		python3 -m agave.icmp.discover 192.168.1.0/24


	"""
	import sys


	if len(sys.argv) < 2:
		print("Too few parameters")
	else:
		report = NetworkReport(sys.argv[1])
		scanner = NetScanner(
			socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)),
			socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
			report,
			0.1
		)
		print("Scanning..")
		scanner.run()
		print("Hosts found:")
		for i in report.get_confirmed_host():
			print(i)
		print("Hosts for which a destination unreachable message wasn't received:")
		for i in report.get_missing_host():
			print(i)

