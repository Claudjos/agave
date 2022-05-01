import unittest
from agave.models.udp import UDP
from agave.models.ip import IPv4, PROTO_UDP
from ipaddress import IPv4Address


class TestUDP(unittest.TestCase):

	upd_packet = (
		b'\xc4\x27\x00\x35\x00\x33\x93\xb0'
		b'\x1e\x94\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77'
		b'\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01'
		b'\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00'
	)

	def test_parse(self):
		packet = UDP.from_bytes(self.upd_packet)
		self.assertEqual(packet.source, 50215)
		self.assertEqual(packet.destination, 53)
		self.assertEqual(packet.length, 51)
		self.assertEqual(packet.checksum, 0x93b0)
		self.assertEqual(bytes(packet), self.upd_packet[:8])

	def test_checksum(self):
		packet = UDP.from_bytes(self.upd_packet)
		payload = self.upd_packet[8:]
		pseudo_header = IPv4.build_pseudo_header(
			IPv4Address("192.168.0.105"),
			IPv4Address("8.8.8.8"),
			PROTO_UDP,
			len(self.upd_packet)
		)
		self.assertTrue(packet.is_checksum_valid(pseudo_header, payload))

