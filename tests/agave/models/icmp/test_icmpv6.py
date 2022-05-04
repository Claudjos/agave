import unittest
from agave.models.ip import IPv6, PROTO_ICMPv6
from agave.models.icmp.icmpv6 import ICMPv6, TYPE_ROUTER_SOLICITATION
from ipaddress import IPv6Address


class TestICMPv6(unittest.TestCase):

	mex_1_IPv6_header = (
		b'\x60\x00\x00\x00\x00\x10\x3a\xff\xfe\x80'
		b'\x00\x00\x00\x00\x00\x00\x7e\xf9\x0e\xff'
		b'\xfe\x48\xe4\xc4\xff\x02\x00\x00\x00\x00'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
	)

	mex_1_ICMPv6_header = (
		b'\x85\x00\x9b\x21\x00\x00\x00\x00'
		b'\x01\x01\x7c\xf9\x0e\x48\xe4\xc4'
	)

	def test_read(self):
		packet = ICMPv6.from_bytes(self.mex_1_ICMPv6_header)
		self.assertEqual(packet.type, TYPE_ROUTER_SOLICITATION)
		self.assertEqual(packet.code, 0)
		self.assertEqual(packet.checksum, 0x9b21)
		self.assertEqual(packet.body, b'\x00\x00\x00\x00\x01\x01\x7c\xf9\x0e\x48\xe4\xc4')

	def test_write(self):
		packet = ICMPv6.from_bytes(self.mex_1_ICMPv6_header)
		self.assertEqual(bytes(packet), self.mex_1_ICMPv6_header)

	def test_checksum(self):
		packet = ICMPv6.from_bytes(self.mex_1_ICMPv6_header)
		ip_header = IPv6.from_bytes(self.mex_1_IPv6_header)
		self.assertTrue(packet.is_checksum_valid(
			pseudo_header=ip_header.get_pseudo_header()))

