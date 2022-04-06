import unittest
from agave.core.icmpv6 import ICMPv6
from agave.core.ndp import NeighborSolicitation, NeighborAdvertisment, TargetLinkLayerAddress
from agave.core.ethernet import MACAddress
from ipaddress import IPv6Address


class TestNDP(unittest.TestCase):

	ICMP_neighbour_solicitation = (
		b'\x87\x00\x26\x14\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00'
		b'\x7e\xf9\x0e\xff\xfe\x48\xe4\xc4'
	)

	ICMP_neighbour_advertisment = (
		b'\x88\x00\x02\x59\x60\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00'
		b'\x7e\xf9\x0e\xff\xfe\x48\xe4\xc4\x02\x01\x7c\xf9\x0e\x48\xe4\xc4'
	)

	def test_read_neighbour_solicitation(self):
		"""Decode NDP neighbor solicitation from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_neighbour_solicitation)
		ndp = NeighborSolicitation.parse(icmp)
		assert ndp.target == IPv6Address("fe80::7ef9:eff:fe48:e4c4")

	def test_write_neighbour_solicitation(self):
		"""Recreates the test solicitation message."""
		ndp = NeighborSolicitation(IPv6Address("fe80::7ef9:eff:fe48:e4c4"))
		icmp = ndp.to_frame()
		icmp.checksum = 0x2614
		assert bytes(icmp) == self.ICMP_neighbour_solicitation

	def test_read_neighbour_advertisment(self):
		"""Decode NDP neighbor advertisement (with link layer address option) from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_neighbour_advertisment)
		ndp = NeighborAdvertisment.parse(icmp)
		assert ndp.target == IPv6Address("fe80::7ef9:eff:fe48:e4c4")
		assert ndp.options[0].mac == MACAddress("7c:f9:0e:48:e4:c4")
		self.assertFalse(ndp.router_flag)
		self.assertTrue(ndp.solicited_flag)
		self.assertTrue(ndp.override_flag)

	def test_write_neighbour_advertisement(self):
		"""Recreates the test advertisement message."""
		ndp = NeighborAdvertisment(
			IPv6Address("fe80::7ef9:eff:fe48:e4c4"),
			[TargetLinkLayerAddress.build(MACAddress("7c:f9:0e:48:e4:c4"))]
		)
		ndp.override_flag = ndp.solicited_flag = True
		icmp = ndp.to_frame()
		icmp.checksum = 0x0259
		assert bytes(icmp) == self.ICMP_neighbour_advertisment

