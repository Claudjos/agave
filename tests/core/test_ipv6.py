import unittest
from agave.core.ip import IPv6, PROTO_UDP
from agave.core.buffer import Buffer
from ipaddress import IPv6Address


class TestIPv6(unittest.TestCase):

	IPv6_packet = (
		b'\x60\x02\xfe\x81\x00\x95\x11\xff\xfe\x80'
		b'\x00\x00\x00\x00\x00\x00\xca\x7e\x89\xbf'
		b'\x54\x9a\x1c\xdc\xff\x02\x00\x00\x00\x00'
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb'
	)

	def test_read(self):
		packet = IPv6.read_from_buffer(Buffer.from_bytes(self.IPv6_packet))
		self.assertEqual(packet.traffic_class, 0)
		self.assertEqual(packet.flow_label, 0x2fe81)
		self.assertEqual(packet.payload_length, 149)
		self.assertEqual(packet.next_header, PROTO_UDP)
		self.assertEqual(packet.hop_limit, 255)
		self.assertEqual(packet.source, IPv6Address("fe80::ca7e:89bf:549a:1cdc"))
		self.assertEqual(packet.destination, IPv6Address("ff02::fb"))

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = IPv6.read_from_buffer(Buffer.from_bytes(self.IPv6_packet))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.IPv6_packet)


if __name__ == '__main__':
	unittest.main()

