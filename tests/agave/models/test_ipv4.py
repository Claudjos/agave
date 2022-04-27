import unittest
from agave.models.ip import IPv4, PROTO_ICMP
from agave.models.buffer import Buffer
from ipaddress import IPv4Address


class TestIPv4(unittest.TestCase):

	IPv4_packet = (
		b'\x45\x00\x00\x54\xe0\x10\x40\x00\x40\x01'
		b'\xd7\xdd\xc0\xa8\x00\x69\xc0\xa8\x01\x01'
	)

	def test_read(self):
		packet = IPv4.read_from_buffer(Buffer.from_bytes(self.IPv4_packet))
		self.assertEqual(packet.ihl, 5)
		self.assertEqual(packet.dscp, 0)
		self.assertEqual(packet.dscp, 0)
		self.assertEqual(packet.total_length, 84)
		self.assertEqual(packet.identification, 0xe010)
		self.assertEqual(packet.flags, 2)
		self.assertEqual(packet.fragment_offset, 0)
		self.assertEqual(packet.ttl, 64)
		self.assertEqual(packet.protocol, PROTO_ICMP)
		self.assertEqual(packet.checksum, 0xd7dd)
		self.assertEqual(packet.source, IPv4Address("192.168.0.105").packed),
		self.assertEqual(packet.destination, IPv4Address("192.168.1.1").packed),
		self.assertEqual(packet.options, b'')

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = IPv4.read_from_buffer(Buffer.from_bytes(self.IPv4_packet))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.IPv4_packet)

	def test_checksum(self):
		packet = IPv4.read_from_buffer(Buffer.from_bytes(self.IPv4_packet))
		self.assertEqual(packet.is_checksum_valid(), True)

