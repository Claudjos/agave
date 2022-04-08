import unittest
from tests.dummy import DummyInterface, DummySock
from agave.core.ethernet import ETHER_TYPE_IPV6, Ethernet
from agave.core.ip import (
	IPv6, PROTO_ICMPv6, IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL
)
from agave.core.icmpv6 import ICMPv6, TYPE_ROUTER_SOLICITATION
from agave.core.ndp import RouterSolicitation
from agave.ndp.routers import LowLevelRouterSoliciter
from ipaddress import IPv6Address 


class TestNDPRouters(unittest.TestCase):

	def test_loop(self):
		"""Should send solicitation messages."""
		dummysocket = DummySock()
		dummyinterface = DummyInterface()
		job = LowLevelRouterSoliciter(dummysocket, dummyinterface, repeat=1)
		# Activate loop, with flag to prevent erroneous never ending loop.
		loop_count = 0
		while job.loop() and loop_count < 10:
			loop_count += 1
		self.assertEqual(loop_count, 3)
		# Parse the first messages
		eth, ip, icmp = ICMPv6.parse(dummysocket.get_message(0)[0], network=True, link=True)
		ndp = RouterSolicitation.parse(icmp)
		# Check data
		self.assertEqual(eth.next_header, ETHER_TYPE_IPV6)
		self.assertEqual(ip.next_header, PROTO_ICMPv6)
		self.assertEqual(icmp.type, TYPE_ROUTER_SOLICITATION)
		self.assertEqual(ip.destination, IPv6Address(IPV6_ALL_ROUTERS_MULTICAST_INTERFACE_LOCAL))
		self.assertEqual(ndp.options[0].mac, dummyinterface.mac)

