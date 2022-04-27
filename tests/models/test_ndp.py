import unittest
from agave.models.icmpv6 import ICMPv6
from agave.models.ndp import (
	NeighborSolicitation, NeighborAdvertisement, RouterSolicitation,
	SourceLinkLayerAddress, TargetLinkLayerAddress, RouterAdvertisement,
	PrefixInformation, MTU
)
from agave.models.ethernet import MACAddress
from ipaddress import IPv6Address, IPv6Network


class TestNDP(unittest.TestCase):

	ICMP_neighbour_solicitation = (
		b'\x87\x00\x26\x14\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00'
		b'\x7e\xf9\x0e\xff\xfe\x48\xe4\xc4'
	)

	ICMP_neighbour_advertisement = (
		b'\x88\x00\x02\x59\x60\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00'
		b'\x7e\xf9\x0e\xff\xfe\x48\xe4\xc4\x02\x01\x7c\xf9\x0e\x48\xe4\xc4'
	)

	ICMP_router_solicitation = (
		b'\x85\x00\x9b\x21\x00\x00\x00\x00\x01\x01\x7c\xf9\x0e\x48\xe4\xc4'
	)

	ICMP_router_advertisment = (
		b'\x86\x00\x76\x63\x01\x80\x00\x3c\x00\x00\x00\x1e\x00\x00\x00\x2d'
		b'\x01\x01\x00\x11\x22\xaa\xbb\xcc\x05\x01\x00\x00\x00\x00\x0f\xfc'
		b'\x03\x04\x46\x40\x00\x00\x00\x3c\x00\x00\x00\x5a\x00\x00\x00\x00'
		b'\xff\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	)

	def test_read_neighbour_solicitation(self):
		"""Decode NDP neighbor solicitation from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_neighbour_solicitation)
		ndp = NeighborSolicitation.parse(icmp)
		self.assertEqual(ndp.target, IPv6Address("fe80::7ef9:eff:fe48:e4c4"))

	def test_write_neighbour_solicitation(self):
		"""Recreates the test solicitation message."""
		ndp = NeighborSolicitation(IPv6Address("fe80::7ef9:eff:fe48:e4c4"))
		icmp = ndp.to_frame()
		icmp.checksum = 0x2614
		self.assertEqual(bytes(icmp), self.ICMP_neighbour_solicitation)

	def test_read_neighbour_advertisment(self):
		"""Decode NDP neighbor advertisement (with link layer address option) from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_neighbour_advertisement)
		ndp = NeighborAdvertisement.parse(icmp)
		self.assertEqual(ndp.target, IPv6Address("fe80::7ef9:eff:fe48:e4c4"))
		self.assertEqual(ndp.options[0].mac, MACAddress("7c:f9:0e:48:e4:c4"))
		self.assertFalse(ndp.router_flag)
		self.assertTrue(ndp.solicited_flag)
		self.assertTrue(ndp.override_flag)

	def test_write_neighbour_advertisement(self):
		"""Recreates the test advertisement message."""
		ndp = NeighborAdvertisement(
			IPv6Address("fe80::7ef9:eff:fe48:e4c4"),
			[TargetLinkLayerAddress.build(MACAddress("7c:f9:0e:48:e4:c4"))]
		)
		ndp.override_flag = ndp.solicited_flag = True
		icmp = ndp.to_frame()
		icmp.checksum = 0x0259
		self.assertEqual(bytes(icmp), self.ICMP_neighbour_advertisement)

	def test_read_router_solicitation(self):
		"""Decode NDP router solicitation (with link layer address option) from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_router_solicitation)
		ndp = RouterSolicitation.parse(icmp)
		self.assertEqual(ndp.options[0].mac, MACAddress("7c:f9:0e:48:e4:c4"))

	def test_write_router_solicitation(self):
		"""Recreates the test solicitation message."""
		ndp = RouterSolicitation(
			[SourceLinkLayerAddress.build(MACAddress("7c:f9:0e:48:e4:c4"))]
		)
		icmp = ndp.to_frame()
		icmp.checksum = 0x9b21
		self.assertEqual(bytes(icmp), self.ICMP_router_solicitation)

	def test_read_router_advertisement(self):
		"""Decode NDP router advertisement (with options) from bytes."""
		icmp = ICMPv6.from_bytes(self.ICMP_router_advertisment)
		ndp = RouterAdvertisement.parse(icmp)
		# Advertisement
		self.assertEqual(ndp.cur_hop_limit, 1)
		self.assertEqual(ndp.lifetime, 60)
		self.assertEqual(ndp.reachable_time, 30)
		self.assertEqual(ndp.retrans_timer, 45)
		self.assertTrue(ndp.m_flag)
		self.assertFalse(ndp.o_flag)
		# Option source link layer address
		self.assertEqual(ndp.options[0].mac, MACAddress("00:11:22:aa:bb:cc"))
		# Options MTU
		self.assertEqual(ndp.options[1].mtu, 4092)
		# Option prefix information
		self.assertEqual(ndp.options[2].prefix_length, 70)
		self.assertFalse(ndp.options[2].l_flag)
		self.assertTrue(ndp.options[2].a_flag)
		self.assertEqual(ndp.options[2].valid_lifetime, 60)
		self.assertEqual(ndp.options[2].preferred_lifetime, 90)
		self.assertEqual(ndp.options[2].prefix, IPv6Address("ff80::").packed)

	def test_write_router_advertisement(self):
		"""Recreates the test advertisement message."""
		ndp = RouterAdvertisement(lifetime=60, reachable_time=30, retrans_timer=45, m=True,
			options=[
				SourceLinkLayerAddress.build(MACAddress("00:11:22:aa:bb:cc")),
				MTU.build(4092),
				PrefixInformation.build(IPv6Network("ff80::/70"), 60, 90, a=True)
			]
		)
		icmp = ndp.to_frame()
		icmp.checksum = 0x7663
		self.assertEqual(bytes(icmp), self.ICMP_router_advertisment)
