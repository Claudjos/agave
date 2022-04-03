import unittest
from agave.core.ethernet import Ethernet, ETHER_TYPE_IPV4, str_to_mac, mac_to_str
from agave.core.buffer import Buffer


class TestEthernet(unittest.TestCase):

	ethernet_header = (
		b'\x00\x0c\xf6\xaa\x33\x04\x3c\xa0\x55\x2e\x11\x22\x08\x00'
	)

	def test_read(self):
		packet = Ethernet.read_from_buffer(Buffer.from_bytes(self.ethernet_header))
		self.assertEqual(packet.destination, b'\x00\x0c\xf6\xaa\x33\x04')
		self.assertEqual(packet.source, b'\x3c\xa0\x55\x2e\x11\x22')
		self.assertEqual(packet.next_header, ETHER_TYPE_IPV4)

	def test_write(self):
		buf = Buffer.from_bytes()
		packet = Ethernet.read_from_buffer(Buffer.from_bytes(self.ethernet_header))
		packet.write_to_buffer(buf)
		self.assertEqual(bytes(buf), self.ethernet_header)

	def test_conversion(self):
		self.assertEqual(
			b'\xff\xee\xdd\x00\x02\x04',
			str_to_mac("ff:ee:dd:00:02:04")
		)
		self.assertEqual(
			"ff:ee:dd:00:02:04",
			mac_to_str(str_to_mac("ff:ee:dd:00:02:04"))
		)

