import unittest
from tests.dummy import DummyInterface, DummySock
from agave.models.ethernet import MACAddress
from agave.models.icmpv6 import ICMPv6
from agave.models.ndp import NeighborSolicitation, NeighborAdvertisement, TargetLinkLayerAddress
from agave.ndp.resolve import NeighborSoliciter
from ipaddress import IPv6Address, IPv6Network


class TestNDPNeighborSoliciter(unittest.TestCase):

	def test_loop(self):
		"""Should send solicitation messages."""
		dummysocket = DummySock()
		dummyinterface = DummyInterface()
		job = NeighborSoliciter(dummysocket, dummyinterface, 
			IPv6Network("fe80::0/127"), repeat=1)
		# Activate loop, with flag to prevent erroneous never ending loop.
		loop_count = 0
		while job.loop() and loop_count < 10:
			loop_count += 1
		self.assertEqual(loop_count, 2)
		# Checks first messages
		data, addr = dummysocket.get_message(0)
		ndp = NeighborSolicitation.parse(ICMPv6.parse(data)[0])
		self.assertEqual(IPv6Address(addr[0]), 
			NeighborSolicitation.compute_solicited_node_multicast_address(IPv6Address("fe80::0")))
		self.assertEqual(ndp.options[0].mac, dummyinterface.mac)
		# Checks second messages
		data, addr = dummysocket.get_message(1)
		ndp = NeighborSolicitation.parse(ICMPv6.parse(data)[0])
		self.assertEqual(IPv6Address(addr[0]), 
			NeighborSolicitation.compute_solicited_node_multicast_address(IPv6Address("fe80::1")))
		self.assertEqual(ndp.options[0].mac, dummyinterface.mac)

	def test_process_advertisement(self):
		"""Should return the advertisement, each address only once."""
		mac = MACAddress("45:45:60:60:aa:aa")
		job = NeighborSoliciter(None, None, IPv6Network("fe80::0/127"), repeat=1)
		ndp = NeighborAdvertisement(target=IPv6Address("fe80::1"), 
			options=[TargetLinkLayerAddress.build(mac)])
		packet = bytes(ndp.to_frame())
		# Process Advertisement
		result = job.process(packet, ("fe80::1", 0))
		self.assertEqual(result[0], mac)
		self.assertEqual(result[1], IPv6Address("fe80::1"))
		# Retry
		result = job.process(packet, ("fe80::1", 0))
		self.assertEqual(result, None)
		# Outside subnet
		result = job.process(packet, ("fe80::2", 0))
		self.assertEqual(result, None)

	def test_process_other(self):
		"""Should send solicitation messages."""
		job = NeighborSoliciter(None, None, IPv6Network("fe80::0/127"), repeat=1)
		ndp = NeighborSolicitation(IPv6Address("ff80::1"))
		result = job.process(bytes(ndp.to_frame()), ("ff80::2", 0))
		self.assertEqual(result, None)

