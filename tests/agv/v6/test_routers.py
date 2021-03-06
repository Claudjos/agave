import unittest
from tests.dummy import DummyInterface, DummySock
from agave.models.ethernet import ETHER_TYPE_IPV6, Ethernet
from agave.models.ip import (
	IPv6, PROTO_ICMPv6, IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL
)
from agave.models.icmp.icmpv6 import ICMPv6, TYPE_ROUTER_SOLICITATION
from agave.models.icmp.ndp import RouterSolicitation, RouterAdvertisement, MTU
from agv.v6.ndp.routers import RouterSoliciter
from ipaddress import IPv6Address 


class TestNDPRouters(unittest.TestCase):

	def test_loop(self):
		"""Should send solicitation messages."""
		dummysocket = DummySock()
		dummyinterface = DummyInterface()
		job = RouterSoliciter(dummysocket, dummyinterface, repeat=1)
		# Activate loop, with flag to prevent erroneous never ending loop.
		loop_count = 0
		while job.loop() and loop_count < 10:
			loop_count += 1
		self.assertEqual(loop_count, 3)
		# Parse the first messages
		icmp = ICMPv6.from_bytes(dummysocket.get_message(0)[0])
		ndp = RouterSolicitation.parse(icmp)
		# Check data
		self.assertEqual(icmp.type, TYPE_ROUTER_SOLICITATION)
		self.assertEqual(ndp.options[0].mac, dummyinterface.mac)

	def test_process_advertisement(self):
		"""Should return the advertisement, each address only once."""
		job = RouterSoliciter(None, None, repeat=1)
		ndp = RouterAdvertisement(options=[MTU.build(4092)])
		packet = bytes(ndp.to_frame())
		# Process Advertisement
		result = job.process(packet, ("ff80::1", 0))
		self.assertEqual(result[0], IPv6Address("ff80::1"))
		self.assertTrue(isinstance(result[1], RouterAdvertisement))
		self.assertEqual(result[1].options[0].mtu, 4092)
		# Retry
		result = job.process(packet, ("ff80::1", 0))
		self.assertEqual(result, None)

	def test_process_other(self):
		"""Should send solicitation messages."""
		job = RouterSoliciter(None, None, repeat=1)
		ndp = RouterSolicitation()
		result = job.process(bytes(ndp.to_frame()), ("ff80::1", 0))
		self.assertEqual(result, None)

