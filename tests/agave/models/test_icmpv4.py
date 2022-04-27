import unittest
from agave.models.icmpv4 import ICMPv4, TYPE_ECHO_MESSAGE
from agave.models.buffer import Buffer


class TestICMPv4(unittest.TestCase):

	ICMPv4_header = (
		b'\x08\x00\x02\x2a\x00\x01\x00\x01\xf7\x76\x49\x62\x00\x00\x00\x00'
		b'\xef\x27\x07\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17'
		b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27'
		b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'
	)

	def test_read(self):
		packet = ICMPv4.read_from_buffer(Buffer.from_bytes(self.ICMPv4_header))
		self.assertEqual(packet.type, TYPE_ECHO_MESSAGE)
		self.assertEqual(packet.code, 0)
		self.assertEqual(packet.checksum, 0x022a)
		self.assertEqual(packet.rest_of_the_header, 0x00010001)

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = ICMPv4.read_from_buffer(Buffer.from_bytes(self.ICMPv4_header))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.ICMPv4_header)

	def test_checksum(self):
		packet = ICMPv4.read_from_buffer(Buffer.from_bytes(self.ICMPv4_header))
		self.assertEqual(packet.is_checksum_valid(), True)

