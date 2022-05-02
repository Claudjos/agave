import unittest
from agave.models import ip
from agave.models.buffer import Buffer
from ipaddress import IPv4Address, IPv6Address


class TestIP(unittest.TestCase):

	IPv4_packet = (
		b'\x45\x00\x00\x54\xe0\x10\x40\x00\x40\x01'
		b'\xd7\xdd\xc0\xa8\x00\x69\xc0\xa8\x01\x01'
	)

	IPv6_packet = (
		b'\x60\x02\xfe\x81\x00\x95\x11\xff\xfe\x80'
		b'\x00\x00\x00\x00\x00\x00\xca\x7e\x89\xbf'
		b'\x54\x9a\x1c\xdc\xff\x02\x00\x00\x00\x00'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb'
	)

	def test_ipv4_parse(self):
		packet = ip.IPv4.from_bytes(self.IPv4_packet)
		self.assertEqual(packet.ihl, 5)
		self.assertEqual(packet.dscp, 0)
		self.assertEqual(packet.dscp, 0)
		self.assertEqual(packet.total_length, 84)
		self.assertEqual(packet.identification, 0xe010)
		self.assertEqual(packet.flags, 2)
		self.assertEqual(packet.fragment_offset, 0)
		self.assertEqual(packet.ttl, 64)
		self.assertEqual(packet.protocol, ip.PROTO_ICMP)
		self.assertEqual(packet.checksum, 0xd7dd)
		self.assertEqual(packet.source, IPv4Address("192.168.0.105")),
		self.assertEqual(packet.destination, IPv4Address("192.168.1.1")),
		self.assertEqual(packet.options, b'')
		self.assertEqual(bytes(packet), self.IPv4_packet)

	def test_ipv4_checksum(self):
		packet = ip.IPv4.from_bytes(self.IPv4_packet)
		self.assertEqual(packet.is_checksum_valid(), True)

	def test_ipv6_parse(self):
		packet = ip.IPv6.from_bytes(self.IPv6_packet)
		self.assertEqual(packet.traffic_class, 0)
		self.assertEqual(packet.flow_label, 0x2fe81)
		self.assertEqual(packet.payload_length, 149)
		self.assertEqual(packet.next_header, ip.PROTO_UDP)
		self.assertEqual(packet.hop_limit, 255)
		self.assertEqual(packet.source, IPv6Address("fe80::ca7e:89bf:549a:1cdc"))
		self.assertEqual(packet.destination, IPv6Address("ff02::fb"))
		self.assertEqual(bytes(packet), self.IPv6_packet)

	def test_ip_parse(self):
		header = ip.read_from_buffer(Buffer.from_bytes(self.IPv4_packet))
		self.assertEqual(header.version, 4)
		header = ip.read_from_buffer(Buffer.from_bytes(self.IPv6_packet))
		self.assertEqual(header.version, 6)

